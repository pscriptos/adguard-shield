// Package web stellt eine schreibgeschützte Statusseite für den Daemon bereit.
package web

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"adguard-shield/internal/config"
)

const (
	cacheTTL          = 2 * time.Second
	statusTimeout     = 15 * time.Second
	shutdownTimeout   = 5 * time.Second
	errorLogEvery     = time.Minute
	contentSecPolicy  = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
	staticCacheHeader = "private, max-age=3600"
	hstsHeader        = "max-age=31536000"
)

//go:embed assets
var assets embed.FS

var staticFiles = map[string]string{
	"app.css":  "text/css; charset=utf-8",
	"app.js":   "text/javascript; charset=utf-8",
	"icon.svg": "image/svg+xml",
}

var (
	ErrTLSIncomplete = errors.New("WEB_TLS_CERT und WEB_TLS_KEY müssen gemeinsam gesetzt sein")
	ErrNoProvider    = errors.New("kein Status-Provider")
	errStopping      = errors.New("Statusseite wird beendet")
)

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

type Options struct {
	Listen   string
	BasePath string
	User     string
	// Password leer = Statusseite ohne Anmeldung.
	Password string
	TLSCert  string
	TLSKey   string
	Version  string
	Hostname string
}

// OptionsFromConfig übernimmt die WEB_*-Schlüssel.
func OptionsFromConfig(c *config.Config) Options {
	return Options{
		Listen: c.WebListen, BasePath: c.WebBasePath,
		User: c.WebUser, Password: c.WebPassword,
		TLSCert: c.WebTLSCert, TLSKey: c.WebTLSKey,
	}
}

type Server struct {
	opts     Options
	base     string
	provider Provider
	log      Logger
	auth     *authenticator
	page     *template.Template
	now      func() time.Time

	shutdownTimeout time.Duration
	// life endet beim Herunterfahren und bricht laufende Provider-Aufrufe ab.
	life     context.Context
	stopLife context.CancelFunc
	callMu   sync.Mutex
	stopping bool
	calls    sync.WaitGroup

	cacheMu  sync.Mutex
	cached   []byte
	cacheErr error
	cachedAt time.Time
	errLogAt time.Time
}

func New(opts Options, p Provider, log Logger) (*Server, error) {
	if p == nil {
		return nil, ErrNoProvider
	}
	if log == nil {
		log = nopLogger{}
	}
	if (opts.TLSCert == "") != (opts.TLSKey == "") {
		return nil, ErrTLSIncomplete
	}
	if opts.Listen == "" {
		opts.Listen = config.DefaultWebListen
	}
	if _, _, err := net.SplitHostPort(opts.Listen); err != nil {
		return nil, fmt.Errorf("ungültige Adresse %q: %w", opts.Listen, err)
	}
	base, ok := config.NormalizeBasePath(opts.BasePath)
	if !ok {
		return nil, fmt.Errorf("ungültiger Basispfad %q", opts.BasePath)
	}
	page, err := template.ParseFS(assets, "assets/index.html")
	if err != nil {
		return nil, err
	}
	s := &Server{opts: opts, base: base, provider: p, log: log, page: page, now: time.Now, shutdownTimeout: shutdownTimeout}
	s.life, s.stopLife = context.WithCancel(context.Background())
	if opts.Password != "" {
		s.auth = newAuthenticator(opts.User, opts.Password, log)
	}
	return s, nil
}

func (s *Server) TLS() bool { return s.opts.TLSCert != "" }

func (s *Server) AuthEnabled() bool { return s.auth != nil }

// StartupWarnings beschreibt unsichere, aber zulässige Konfigurationen.
func (s *Server) StartupWarnings() []string {
	host, _, _ := net.SplitHostPort(s.opts.Listen)
	if isLoopbackHost(host) {
		return nil
	}
	if s.auth == nil {
		return []string{fmt.Sprintf("Web-Statusseite ohne Anmeldung auf %s erreichbar – WEB_PASSWORD setzen oder an 127.0.0.1 binden", s.opts.Listen)}
	}
	if !s.TLS() {
		return []string{fmt.Sprintf("Web-Statusseite auf %s ohne TLS: Basic-Auth-Zugangsdaten werden im Klartext übertragen – WEB_TLS_CERT/WEB_TLS_KEY setzen, an 127.0.0.1 binden (SSH-Tunnel) oder einen HTTPS-Reverse-Proxy nutzen", s.opts.Listen)}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Run lauscht auf Options.Listen, bis ctx endet, und fährt den Server dann
// geordnet herunter.
func (s *Server) Run(ctx context.Context) error {
	var tlsCfg *tls.Config
	if s.TLS() {
		certs, err := newCertReloader(s.opts.TLSCert, s.opts.TLSKey, s.log)
		if err != nil {
			return fmt.Errorf("TLS-Zertifikat: %w", err)
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.getCertificate}
	}
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln, tlsCfg)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	for _, w := range s.StartupWarnings() {
		s.log.Warnf("%s", w)
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         tlsCfg,
	}
	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
		ln = tls.NewListener(ln, tlsCfg)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	auth := "aus"
	if s.auth != nil {
		auth = "Basic Auth"
	}
	s.log.Infof("Web-Statusseite gestartet: %s://%s%s (Anmeldung: %s)", scheme, ln.Addr(), s.base, auth)
	select {
	case err := <-errc:
		s.finish()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	s.stopLife()
	sctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(sctx)
	if err != nil {
		_ = srv.Close()
	}
	<-errc
	s.finish()
	s.log.Infof("Web-Statusseite gestoppt")
	return err
}

// finish beendet die Server-Lebensdauer und wartet begrenzt auf laufende
// Provider-Aufrufe, damit der Daemon danach gefahrlos die Datenbank schließt.
func (s *Server) finish() {
	s.stopLife()
	s.callMu.Lock()
	s.stopping = true
	s.callMu.Unlock()
	done := make(chan struct{})
	go func() {
		s.calls.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(s.shutdownTimeout):
		s.log.Warnf("Web-Statusseite: Statusabfrage nach %s noch nicht beendet", s.shutdownTimeout)
	}
}

func (s *Server) beginCall() bool {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.stopping {
		return false
	}
	s.calls.Add(1)
	return true
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecPolicy)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if s.TLS() {
		h.Set("Strict-Transport-Security", hstsHeader)
	}
	if s.auth == nil && !s.hostAllowed(r.Host) {
		http.Error(w, "Unbekannter Host", http.StatusMisdirectedRequest)
		return
	}
	if s.auth != nil && !s.auth.check(w, r) {
		return
	}
	rel, ok := strings.CutPrefix(r.URL.Path, s.base)
	if !ok {
		if r.URL.Path+"/" != s.base {
			http.NotFound(w, r)
		} else if allowRead(w, r) {
			http.Redirect(w, r, s.base, http.StatusMovedPermanently)
		}
		return
	}
	switch {
	case rel == "":
		if allowRead(w, r) {
			s.servePage(w)
		}
	case rel == "api/status":
		if allowRead(w, r) {
			s.serveStatus(w, r)
		}
	case strings.HasPrefix(rel, "static/"):
		name := strings.TrimPrefix(rel, "static/")
		ctype, known := staticFiles[name]
		if !known {
			http.NotFound(w, r)
			return
		}
		if allowRead(w, r) {
			s.serveStatic(w, r, name, ctype)
		}
	default:
		http.NotFound(w, r)
	}
}

// hostAllowed schützt die Seite ohne Anmeldung vor DNS-Rebinding: Erlaubt
// sind nur IP-Literale, localhost und der Host aus WEB_LISTEN.
func (s *Server) hostAllowed(host string) bool {
	if host == "" {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	listen, _, _ := net.SplitHostPort(s.opts.Listen)
	return listen != "" && strings.EqualFold(host, listen)
}

func allowRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
	return false
}

type pageData struct {
	Base     string
	Version  string
	Hostname string
}

func (s *Server) servePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.page.Execute(w, pageData{Base: s.base, Version: s.opts.Version, Hostname: s.opts.Hostname}); err != nil {
		s.log.Warnf("Web-Statusseite: Seite nicht gerendert: %v", err)
	}
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, name, ctype string) {
	data, err := assets.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", staticCacheHeader)
	_, _ = w.Write(data)
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	body, err := s.snapshot()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Status derzeit nicht verfügbar"}`))
		return
	}
	_, _ = w.Write(body)
}

// snapshot liefert den JSON-Status, höchstens alle cacheTTL neu erzeugt, damit
// mehrere offene Tabs die Datenbank nicht zusätzlich belasten. Fehler werden
// ebenfalls für cacheTTL gemerkt.
func (s *Server) snapshot() ([]byte, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	now := s.now()
	if (s.cached != nil || s.cacheErr != nil) && now.Sub(s.cachedAt) < cacheTTL {
		return s.cached, s.cacheErr
	}
	if !s.beginCall() {
		return nil, errStopping
	}
	defer s.calls.Done()
	ctx, cancel := context.WithTimeout(s.life, statusTimeout)
	defer cancel()
	st, err := s.provider.Status(ctx)
	if err == nil && st == nil {
		err = errors.New("leerer Status")
	}
	var body []byte
	if err == nil {
		body, err = json.Marshal(st)
	}
	s.cached, s.cacheErr, s.cachedAt = body, err, now
	if err != nil {
		s.cached = nil
		if s.errLogAt.IsZero() || now.Sub(s.errLogAt) >= errorLogEvery {
			s.errLogAt = now
			s.log.Warnf("Web-Statusseite: Status nicht ermittelt: %v", err)
		}
		return nil, err
	}
	return body, nil
}
