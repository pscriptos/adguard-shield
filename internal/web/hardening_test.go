package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthIPv6KeyedPerSlash64(t *testing.T) {
	s, _, _ := newServer(t, authOpts)
	for i := 1; i <= authMaxFailures; i++ {
		remote := fmt.Sprintf("[2001:db8:1:2::%x]:4711", i)
		if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: remote}); w.Code != http.StatusUnauthorized {
			t.Fatalf("Versuch %d: %d", i, w.Code)
		}
	}
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "[2001:db8:1:2:ffff:1:2:3]:1"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("andere Adresse im selben /64: %d", w.Code)
	}
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "[2001:db8:1:3::1]:1"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("anderes /64: %d", w.Code)
	}
	for remote, want := range map[string]string{
		"192.0.2.1:1":            "192.0.2.1",
		"[::ffff:192.0.2.1]:1":   "192.0.2.1",
		"[2001:db8::1]:1":        "2001:db8::/64",
		"[fe80::1%eth0]:1":       "fe80::/64",
		"kein-host-port":         "kein-host-port",
		"[2001:DB8:0:0:1::5]:80": "2001:db8::/64",
	} {
		if got := clientKey(&http.Request{RemoteAddr: remote}); got != want {
			t.Errorf("clientKey(%q) = %q, erwartet %q", remote, got, want)
		}
	}
}

func block(t *testing.T, s *Server, remote string) {
	t.Helper()
	for i := 0; i < authMaxFailures; i++ {
		do(s, req{path: "/", user: "admin", pass: "falsch", remote: remote})
	}
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: remote}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("%s nicht gesperrt: %d", remote, w.Code)
	}
}

func TestAuthFullTableKeepsBlockedClients(t *testing.T) {
	s, _, _ := newServer(t, authOpts)
	now := time.Unix(1_700_000_000, 0)
	s.auth.now = func() time.Time { return now }
	s.auth.maxTracked = 3

	block(t, s, "198.51.100.1:1")
	do(s, req{path: "/", user: "admin", pass: "falsch", remote: "198.51.100.2:1"})
	do(s, req{path: "/", user: "admin", pass: "falsch", remote: "198.51.100.3:1"})
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "198.51.100.4:1"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("neuer Client bei voller Tabelle mit nicht gesperrten Einträgen: %d", w.Code)
	}
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "198.51.100.1:1"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("gesperrter Client wurde beim Aufräumen entfernt: %d", w.Code)
	}
	if _, ok := s.auth.fails["198.51.100.2"]; ok {
		t.Fatal("nicht gesperrte Einträge müssen bei voller Tabelle entfernt werden")
	}

	block(t, s, "198.51.100.4:1")
	block(t, s, "198.51.100.5:1")
	if n := len(s.auth.fails); n != 3 {
		t.Fatalf("Tabelle: %d Einträge", n)
	}
	w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "203.0.113.9:1"})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("unbekannter Client bei Tabelle voller gesperrter Clients: %d", w.Code)
	}
	if w := do(s, req{path: "/", remote: "203.0.113.9:1"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("ohne Zugangsdaten: %d", w.Code)
	}
	if w := do(s, req{path: "/", user: "admin", pass: "s3cret-pass", remote: "203.0.113.9:1"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("gültige Zugangsdaten während Sperre: %d", w.Code)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.4", "198.51.100.5"} {
		if _, ok := s.auth.fails[ip]; !ok {
			t.Fatalf("gesperrter Client %s fehlt", ip)
		}
	}
	now = now.Add(authWindow + time.Second)
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: "203.0.113.9:1"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("nach Ablauf des Fensters: %d", w.Code)
	}
}

func TestAuthGlobalLimit(t *testing.T) {
	s, _, log := newServer(t, authOpts)
	now := time.Unix(1_700_000_000, 0)
	s.auth.now = func() time.Time { return now }
	perClient := authMaxFailures / 2
	for i := 0; i < authGlobalMaxFailures; i++ {
		remote := fmt.Sprintf("10.0.%d.1:1", i/perClient)
		if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: remote}); w.Code != http.StatusUnauthorized {
			t.Fatalf("Versuch %d (%s): %d", i, remote, w.Code)
		}
	}
	fresh := "192.0.2.200:1"
	w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: fresh})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("globales Limit greift nicht: %d", w.Code)
	}
	if w := do(s, req{path: "/", remote: fresh}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("globales Limit ohne Zugangsdaten: %d", w.Code)
	}
	if w := do(s, req{path: "/", user: "admin", pass: "s3cret-pass", remote: fresh}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("gültige Zugangsdaten während globalem Limit: %d", w.Code)
	}
	if n := log.count("WARN Web-Statusseite: 100 fehlgeschlagene Anmeldungen insgesamt"); n != 1 {
		t.Fatalf("globale Sperre %d-mal geloggt: %v", n, log.lines)
	}
	now = now.Add(authWindow)
	if w := do(s, req{path: "/", user: "admin", pass: "falsch", remote: fresh}); w.Code != http.StatusUnauthorized {
		t.Fatalf("nach Ablauf des Fensters: %d", w.Code)
	}
}

func TestHostCheckWithoutAuth(t *testing.T) {
	s, _, _ := newServer(t, Options{Listen: "dashboard.lan:8443"})
	for host, want := range map[string]int{
		"127.0.0.1:8443":          200,
		"127.0.0.1":               200,
		"[::1]:8443":              200,
		"[::1]":                   200,
		"192.0.2.10:8443":         200,
		"localhost:8443":          200,
		"LOCALHOST":               200,
		"localhost.":              200,
		"dashboard.lan:8443":      200,
		"Dashboard.LAN":           200,
		"evil.example":            421,
		"evil.example:8443":       421,
		"127.0.0.1.evil.example":  421,
		"localhost.evil.example":  421,
		"dashboard.lan.evil:8443": 421,
	} {
		for _, path := range []string{"/", "/api/status"} {
			if w := do(s, req{path: path, host: host}); w.Code != want {
				t.Errorf("Host %q %s: %d, erwartet %d", host, path, w.Code, want)
			}
		}
	}
	a, _, _ := newServer(t, authOpts)
	if w := do(a, req{path: "/api/status", host: "dashboard.example.com", user: "admin", pass: "s3cret-pass"}); w.Code != http.StatusOK {
		t.Fatalf("mit Anmeldung darf der Host nicht geprüft werden: %d", w.Code)
	}
}

func TestHSTSOnlyWithTLS(t *testing.T) {
	opts := authOpts
	s, _, _ := newServer(t, opts)
	if h := do(s, req{path: "/", user: "admin", pass: "s3cret-pass"}).Header().Get("Strict-Transport-Security"); h != "" {
		t.Fatalf("HSTS ohne TLS: %q", h)
	}
	opts.TLSCert, opts.TLSKey = "/x/cert.pem", "/x/key.pem"
	s, _, _ = newServer(t, opts)
	for _, r := range []req{{path: "/", user: "admin", pass: "s3cret-pass"}, {path: "/api/status"}} {
		if h := do(s, r).Header().Get("Strict-Transport-Security"); h != "max-age=31536000" {
			t.Fatalf("%s: HSTS = %q", r.path, h)
		}
	}
}

type slowProvider struct {
	entered   chan struct{}
	once      sync.Once
	release   chan struct{}
	ignoreCtx bool
	sawCancel atomic.Bool
	finished  atomic.Bool
}

func (p *slowProvider) Status(ctx context.Context) (*Status, error) {
	p.once.Do(func() { close(p.entered) })
	if p.ignoreCtx {
		<-p.release
	} else {
		<-ctx.Done()
		p.sawCancel.Store(true)
		time.Sleep(200 * time.Millisecond)
	}
	p.finished.Store(true)
	return nil, ctx.Err()
}

func serveSlow(t *testing.T, p *slowProvider, timeout time.Duration) (*Server, *memLogger, context.CancelFunc, chan error) {
	t.Helper()
	log := &memLogger{}
	s, err := New(Options{Listen: "127.0.0.1:0"}, p, log)
	if err != nil {
		t.Fatal(err)
	}
	s.shutdownTimeout = timeout
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln, nil) }()
	go func() {
		c := &http.Client{Timeout: 10 * time.Second}
		if resp, err := c.Get("http://" + ln.Addr().String() + "/api/status"); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Provider nicht aufgerufen")
	}
	return s, log, cancel, done
}

func TestShutdownCancelsAndWaitsForProvider(t *testing.T) {
	p := &slowProvider{entered: make(chan struct{})}
	_, _, cancel, done := serveSlow(t, p, 2*time.Second)
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Server nicht beendet")
	}
	if !p.sawCancel.Load() {
		t.Fatal("Provider-Kontext wurde beim Herunterfahren nicht abgebrochen")
	}
	if !p.finished.Load() {
		t.Fatal("Serve kehrte zurück, bevor der Provider-Aufruf beendet war")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Herunterfahren dauerte %s", d)
	}
}

func TestShutdownWaitIsBounded(t *testing.T) {
	p := &slowProvider{entered: make(chan struct{}), release: make(chan struct{}), ignoreCtx: true}
	defer close(p.release)
	s, log, cancel, done := serveSlow(t, p, 300*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Warten auf den Provider ist nicht begrenzt")
	}
	if p.finished.Load() {
		t.Fatal("Provider sollte noch laufen")
	}
	if log.count("WARN Web-Statusseite: Statusabfrage nach") != 1 {
		t.Fatalf("fehlende Warnung: %v", log.lines)
	}
	if s.beginCall() {
		t.Fatal("nach dem Herunterfahren darf kein Provider-Aufruf mehr starten")
	}
}

func writeTestCert(t *testing.T, certFile, keyFile, cn string, mtime time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{certFile, keyFile} {
		if err := os.Chtimes(f, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func certCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeTestCert(t, certFile, keyFile, "eins", mtime)
	log := &memLogger{}
	r, err := newCertReloader(certFile, keyFile, log)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }
	r.checkedAt = now
	get := func() string {
		c, err := r.getCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return certCN(t, c)
	}
	if cn := get(); cn != "eins" {
		t.Fatalf("CN %q", cn)
	}
	writeTestCert(t, certFile, keyFile, "zwei", mtime.Add(time.Minute))
	now = now.Add(certCheckEvery / 2)
	if cn := get(); cn != "eins" {
		t.Fatalf("Dateien dürfen höchstens alle %s geprüft werden: %q", certCheckEvery, cn)
	}
	now = now.Add(certCheckEvery)
	if cn := get(); cn != "zwei" {
		t.Fatalf("erneuertes Zertifikat nicht geladen: %q", cn)
	}
	if log.count("INFO Web-Statusseite: TLS-Zertifikat neu geladen") != 1 {
		t.Fatalf("Neuladen nicht geloggt: %v", log.lines)
	}
	if err := os.WriteFile(certFile, []byte("kaputt"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(certFile, mtime.Add(2*time.Minute), mtime.Add(2*time.Minute))
	now = now.Add(certCheckEvery)
	if cn := get(); cn != "zwei" {
		t.Fatalf("defektes Zertifikat muss das bisherige behalten: %q", cn)
	}
	if !strings.Contains(strings.Join(log.lines, "\n"), "nicht neu geladen") {
		t.Fatalf("fehlende Warnung: %v", log.lines)
	}
	_ = os.Remove(keyFile)
	now = now.Add(certCheckEvery)
	if cn := get(); cn != "zwei" {
		t.Fatalf("fehlende Datei muss das bisherige behalten: %q", cn)
	}
}
