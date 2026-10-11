package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adguard-shield/internal/config"
)

const maliciousDomain = `<script>alert(1)</script>.evil.example`

type countingProvider struct {
	calls atomic.Int32
	err   error
}

func (p *countingProvider) Status(context.Context) (*Status, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	now := time.Now()
	return &Status{
		GeneratedAt: now, Version: "v-test", Hostname: "host", StartedAt: now.Add(-time.Hour), UptimeSeconds: 3600,
		Tiles:   Tiles{ActiveBans: 3, PermanentBans: 1},
		Poll:    Poll{IntervalSeconds: 10, LastSuccess: &now, Entries: 42},
		Modules: []Module{{Name: "GeoIP", Active: true}},
		Live: Live{WindowSeconds: 60, Limit: 30,
			Top:    []Count{{Client: "192.0.2.1", Domain: maliciousDomain, Count: 12, Protocol: "DNS"}},
			Recent: []Query{{Time: now, Client: "192.0.2.1", Protocol: "DNS", Domain: maliciousDomain}}},
		Bans:    []Ban{{IP: "192.0.2.9", Source: "monitor", Reason: "rate-limit", Domain: maliciousDomain}},
		History: []HistoryEntry{{Action: "BAN", IP: "192.0.2.9"}},
		Logs:    []string{"[INFO] test"},
	}, nil
}

type memLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *memLogger) add(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(format, args...))
}
func (l *memLogger) Infof(f string, a ...any)  { l.add("INFO", f, a...) }
func (l *memLogger) Warnf(f string, a ...any)  { l.add("WARN", f, a...) }
func (l *memLogger) Errorf(f string, a ...any) { l.add("ERROR", f, a...) }
func (l *memLogger) count(prefix string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func newServer(t *testing.T, opts Options) (*Server, *countingProvider, *memLogger) {
	t.Helper()
	p := &countingProvider{}
	log := &memLogger{}
	s, err := New(opts, p, log)
	if err != nil {
		t.Fatal(err)
	}
	return s, p, log
}

type req struct {
	method, path, user, pass, remote, host string
}

func do(s *Server, r req) *httptest.ResponseRecorder {
	if r.method == "" {
		r.method = http.MethodGet
	}
	hr := httptest.NewRequest(r.method, r.path, nil)
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	hr.Host = "127.0.0.1:8443"
	if r.host != "" {
		hr.Host = r.host
	}
	if r.user != "" || r.pass != "" {
		hr.SetBasicAuth(r.user, r.pass)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, hr)
	return w
}

var authOpts = Options{Listen: "127.0.0.1:0", BasePath: "/", User: "admin", Password: "s3cret-pass"}

func TestBasicAuth(t *testing.T) {
	s, _, _ := newServer(t, authOpts)
	for _, path := range []string{"/", "/static/app.js", "/api/status", "/does-not-exist"} {
		w := do(s, req{path: path})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s ohne Anmeldung: %d", path, w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="AdGuard Shield"`) {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
		if w := do(s, req{path: path, user: "admin", pass: "wrong"}); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s falsches Passwort: %d", path, w.Code)
		}
		if w := do(s, req{path: path, user: "root", pass: "s3cret-pass"}); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s falscher Benutzer: %d", path, w.Code)
		}
	}
	for path, want := range map[string]int{"/": 200, "/static/app.js": 200, "/api/status": 200, "/does-not-exist": 404} {
		if w := do(s, req{path: path, user: "admin", pass: "s3cret-pass"}); w.Code != want {
			t.Fatalf("%s angemeldet: %d, erwartet %d", path, w.Code, want)
		}
	}
}

func TestNoPasswordDisablesAuth(t *testing.T) {
	s, _, _ := newServer(t, Options{Listen: "127.0.0.1:0", User: "admin"})
	if s.AuthEnabled() {
		t.Fatal("ohne Passwort darf keine Anmeldung aktiv sein")
	}
	for _, path := range []string{"/", "/static/app.css", "/api/status"} {
		w := do(s, req{path: path})
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if w.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: unerwartete Anmeldeaufforderung", path)
		}
	}
}

func TestAuthThrottling(t *testing.T) {
	s, _, log := newServer(t, authOpts)
	now := time.Unix(1_700_000_000, 0)
	s.auth.now = func() time.Time { return now }
	attacker := "198.51.100.7:4711"
	for i := 0; i < authMaxFailures; i++ {
		if w := do(s, req{path: "/", user: "admin", pass: fmt.Sprint("guess", i), remote: attacker}); w.Code != http.StatusUnauthorized {
			t.Fatalf("Versuch %d: %d", i, w.Code)
		}
	}
	w := do(s, req{path: "/", user: "admin", pass: "noch-ein-versuch", remote: attacker})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("nach %d Fehlversuchen: %d (Retry-After %q)", authMaxFailures, w.Code, w.Header().Get("Retry-After"))
	}
	if w := do(s, req{path: "/", remote: attacker}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("gesperrte IP ohne Anmeldung: %d", w.Code)
	}
	// Auch gültige Zugangsdaten werden während der Sperre abgewiesen, sonst
	// ließe sich das Passwort weiter raten.
	if w := do(s, req{path: "/", user: "admin", pass: "s3cret-pass", remote: attacker}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("gesperrte IP mit gültigen Zugangsdaten: %d", w.Code)
	}
	if w := do(s, req{path: "/", user: "admin", pass: "s3cret-pass", remote: "203.0.113.5:1"}); w.Code != http.StatusOK {
		t.Fatalf("andere IP: %d", w.Code)
	}
	if n := log.count("WARN"); n != 2 {
		t.Fatalf("erwartet 2 gedrosselte Warnungen, erhalten %d: %v", n, log.lines)
	}
	now = now.Add(authWindow + time.Second)
	if w := do(s, req{path: "/", user: "admin", pass: "s3cret-pass", remote: attacker}); w.Code != http.StatusOK {
		t.Fatalf("nach Ablauf des Fensters: %d", w.Code)
	}
}

func TestBasePathRouting(t *testing.T) {
	cases := []struct {
		base  string
		path  string
		want  int
		ctype string
	}{
		{"/", "/", 200, "text/html"},
		{"/", "/api/status", 200, "application/json"},
		{"/", "/static/app.js", 200, "text/javascript"},
		{"/", "/static/app.css", 200, "text/css"},
		{"/", "/static/icon.svg", 200, "image/svg+xml"},
		{"/", "/static/", 404, ""},
		{"/", "/static/../server.go", 404, ""},
		{"/", "/static/index.html", 404, ""},
		{"/", "/api/status/", 404, ""},
		{"/", "/favicon.ico", 404, ""},
		{"/adguard-shield/", "/adguard-shield/", 200, "text/html"},
		{"/adguard-shield/", "/adguard-shield/api/status", 200, "application/json"},
		{"/adguard-shield/", "/adguard-shield/static/app.js", 200, "text/javascript"},
		{"/adguard-shield/", "/adguard-shield", 301, ""},
		{"/adguard-shield/", "/", 404, ""},
		{"/adguard-shield/", "/api/status", 404, ""},
		{"/adguard-shield/", "/adguard-shieldx/", 404, ""},
		{"/adguard-shield/", "/adguard-shield/nope", 404, ""},
	}
	for _, c := range cases {
		opts := authOpts
		opts.BasePath = c.base
		s, _, _ := newServer(t, opts)
		w := do(s, req{path: c.path, user: "admin", pass: "s3cret-pass"})
		if w.Code != c.want {
			t.Errorf("base %s, %s: %d, erwartet %d", c.base, c.path, w.Code, c.want)
			continue
		}
		if c.ctype != "" && !strings.HasPrefix(w.Header().Get("Content-Type"), c.ctype) {
			t.Errorf("base %s, %s: Content-Type %q", c.base, c.path, w.Header().Get("Content-Type"))
		}
		if c.want == 301 && w.Header().Get("Location") != c.base {
			t.Errorf("Redirect nach %q", w.Header().Get("Location"))
		}
	}
	s, _, _ := newServer(t, Options{BasePath: "adguard-shield"})
	if w := do(s, req{path: "/adguard-shield/"}); w.Code != 200 {
		t.Fatalf("Basispfad ohne Slashes nicht normalisiert: %d", w.Code)
	}
	body := do(s, req{path: "/adguard-shield/"}).Body.String()
	if !strings.Contains(body, `data-base="/adguard-shield/"`) || !strings.Contains(body, `href="/adguard-shield/static/app.css`) {
		t.Fatal("Seite verweist nicht auf den Basispfad")
	}
}

func TestMethods(t *testing.T) {
	s, _, _ := newServer(t, authOpts)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		for _, path := range []string{"/", "/api/status", "/static/app.js"} {
			w := do(s, req{method: m, path: path, user: "admin", pass: "s3cret-pass"})
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("%s %s: %d Allow=%q", m, path, w.Code, w.Header().Get("Allow"))
			}
		}
		if w := do(s, req{method: m, path: "/unknown", user: "admin", pass: "s3cret-pass"}); w.Code != http.StatusNotFound {
			t.Fatalf("%s /unknown: %d", m, w.Code)
		}
	}
	if w := do(s, req{method: http.MethodHead, path: "/api/status", user: "admin", pass: "s3cret-pass"}); w.Code != http.StatusOK {
		t.Fatalf("HEAD: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _, _ := newServer(t, authOpts)
	for _, r := range []req{
		{path: "/", user: "admin", pass: "s3cret-pass"},
		{path: "/api/status", user: "admin", pass: "s3cret-pass"},
		{path: "/static/app.js", user: "admin", pass: "s3cret-pass"},
		{path: "/missing", user: "admin", pass: "s3cret-pass"},
		{path: "/"},
	} {
		h := do(s, r).Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: CSP %q", r.path, csp)
		}
		for k, v := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
			if h.Get(k) != v {
				t.Fatalf("%s: %s = %q", r.path, k, h.Get(k))
			}
		}
	}
	if cc := do(s, req{path: "/api/status", user: "admin", pass: "s3cret-pass"}).Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("API Cache-Control = %q", cc)
	}
}

func TestPageHasNoInlineCode(t *testing.T) {
	s, _, _ := newServer(t, Options{})
	body := do(s, req{path: "/"}).Body.String()
	for _, bad := range []string{"<style", " style=", "onclick", "onload", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Fatalf("Seite enthält %q (verstößt gegen CSP)", bad)
		}
	}
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/app.js`) {
		t.Fatal("Seite darf nur das eingebettete Skript laden")
	}
}

func TestStatusJSON(t *testing.T) {
	s, _, _ := newServer(t, Options{})
	w := do(s, req{path: "/api/status"})
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("Content-Type %q", w.Header().Get("Content-Type"))
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"generated_at", "version", "hostname", "uptime_seconds", "dry_run", "tiles", "poll", "modules", "live", "bans", "history", "logs"} {
		if _, ok := m[k]; !ok {
			t.Errorf("Feld %s fehlt", k)
		}
	}
	tiles := m["tiles"].(map[string]any)
	for _, k := range []string{"active_bans", "permanent_bans", "bans_today", "bans_7_days", "offenses", "whitelist_entries"} {
		if _, ok := tiles[k]; !ok {
			t.Errorf("tiles.%s fehlt", k)
		}
	}
	live := m["live"].(map[string]any)
	for _, k := range []string{"window_seconds", "limit", "top", "subdomains", "recent"} {
		if _, ok := live[k]; !ok {
			t.Errorf("live.%s fehlt", k)
		}
	}
}

func TestMaliciousDataIsEscaped(t *testing.T) {
	s, _, _ := newServer(t, Options{Hostname: `<script>alert("host")</script>`, Version: `"><img src=x>`})
	api := do(s, req{path: "/api/status"}).Body.String()
	if strings.Contains(api, "<script>") || strings.Contains(api, "</script>") {
		t.Fatalf("JSON enthält unmaskiertes HTML: %s", api)
	}
	var st Status
	if err := json.Unmarshal([]byte(api), &st); err != nil {
		t.Fatal(err)
	}
	if st.Live.Top[0].Domain != maliciousDomain || st.Bans[0].Domain != maliciousDomain {
		t.Fatal("Domain beim Roundtrip verändert")
	}
	page := do(s, req{path: "/"}).Body.String()
	if strings.Contains(page, `<script>alert`) || strings.Contains(page, `"><img`) {
		t.Fatalf("Seite enthält unmaskierte Serverwerte:\n%s", page)
	}
	if !strings.Contains(page, "&lt;script&gt;alert(&#34;host&#34;)&lt;/script&gt;") {
		t.Fatal("Hostname nicht HTML-maskiert")
	}
	js := do(s, req{path: "/static/app.js"}).Body.String()
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "insertAdjacentHTML") || strings.Contains(js, "document.write") {
		t.Fatal("app.js darf Daten nicht als HTML einfügen")
	}
}

func TestStatusIsCached(t *testing.T) {
	s, p, _ := newServer(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		do(s, req{path: "/api/status"})
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("Provider %d-mal aufgerufen, erwartet 1", n)
	}
	now = now.Add(cacheTTL)
	do(s, req{path: "/api/status"})
	if n := p.calls.Load(); n != 2 {
		t.Fatalf("nach Ablauf des Caches %d Aufrufe, erwartet 2", n)
	}
}

func TestStatusProviderError(t *testing.T) {
	p := &countingProvider{err: errors.New("db locked")}
	log := &memLogger{}
	s, err := New(Options{}, p, log)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.now = func() time.Time { return time.Unix(1_700_000_000+int64(i)*3, 0) }
		w := do(s, req{path: "/api/status"})
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "db locked") {
			t.Fatalf("Fehlerantwort: %d %s", w.Code, w.Body.String())
		}
	}
	if p.calls.Load() != 3 || log.count("WARN") != 1 {
		t.Fatalf("Fehler muss nach Ablauf des Caches neu ermittelt und gedrosselt geloggt werden: calls=%d warns=%d", p.calls.Load(), log.count("WARN"))
	}
	now := time.Unix(1_700_000_100, 0)
	s.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if w := do(s, req{path: "/api/status"}); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("gecachter Fehler: %d", w.Code)
		}
	}
	if p.calls.Load() != 4 {
		t.Fatalf("Fehler muss für cacheTTL gecacht werden: calls=%d", p.calls.Load())
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	if _, err := New(Options{BasePath: "/../etc"}, &countingProvider{}, nil); err == nil {
		t.Fatal("ungültiger Basispfad akzeptiert")
	}
	if _, err := New(Options{Listen: "8080"}, &countingProvider{}, nil); err == nil {
		t.Fatal("ungültige Adresse akzeptiert")
	}
	s, _, _ := newServer(t, Options{})
	if s.opts.Listen != ":8080" {
		t.Fatalf("Standardadresse %q", s.opts.Listen)
	}
}

func TestOptionsFromConfig(t *testing.T) {
	o := OptionsFromConfig(&config.Config{WebPort: 9090, WebBasePath: "/x/", WebUser: "u", WebPassword: "p"})
	if o.Listen != ":9090" || o.BasePath != "/x/" || o.User != "u" || o.Password != "p" {
		t.Fatalf("%+v", o)
	}
}

func TestStartupWarnings(t *testing.T) {
	cases := []struct {
		opts Options
		want string
	}{
		{Options{Listen: "127.0.0.1:8443"}, ""},
		{Options{Listen: "[::1]:8443", Password: "x"}, ""},
		{Options{Listen: "localhost:8443"}, ""},
		{Options{Listen: "0.0.0.0:8443"}, "ohne Anmeldung auf 0.0.0.0:8443"},
		{Options{Listen: ":8443"}, "ohne Anmeldung"},
		{Options{Listen: ":8080", Password: "x"}, ""},
	}
	for _, c := range cases {
		s, _, _ := newServer(t, c.opts)
		got := strings.Join(s.StartupWarnings(), "\n")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: Warnungen %q, erwartet %q", c.opts, got, c.want)
		}
	}
}

func TestServeAndGracefulShutdown(t *testing.T) {
	s, _, log := newServer(t, authOpts)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	r, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/api/status", nil)
	r.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown-Fehler: %v", err)
		}
	case <-time.After(shutdownTimeout + 2*time.Second):
		t.Fatal("Server nicht beendet")
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("Server lauscht nach Shutdown noch")
	}
	if log.count("INFO Web-Statusseite gestoppt") != 1 {
		t.Fatalf("Stopp nicht geloggt: %v", log.lines)
	}
}
