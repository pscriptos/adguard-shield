package daemon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"adguard-shield/internal/config"
	"adguard-shield/internal/syslog"
)

// plainListServer liefert eine Liste unverschlüsselt per http:// und zählt
// die Abrufe.
func plainListServer(t *testing.T, body string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListHTTPRejectedByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := plainListServer(t, "203.0.113.9\n", &hits)
	cacheDir := t.TempDir()
	// Ein vorhandener Cache darf für abgelehnte URLs nicht genutzt werden.
	if err := os.WriteFile(filepath.Join(cacheDir, "blocklist_0.txt"), []byte("203.0.113.10\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ExternalBlocklistURLs: []string{srv.URL + "/list.txt"}, ExternalBlocklistCacheDir: cacheDir}
	d, _ := newTestDaemon(t, cfg)
	var logBuf bytes.Buffer
	d.Logger = syslog.New(&logBuf, "DEBUG")

	if err := d.SyncBlocklist(context.Background()); err == nil {
		t.Fatal("http:// ohne ALLOW_INSECURE_LIST_URLS muss fehlschlagen")
	}
	if hits.Load() != 0 {
		t.Fatalf("http-Quelle wurde abgerufen: %d", hits.Load())
	}
	for _, ip := range []string{"203.0.113.9", "203.0.113.10"} {
		if ok, _ := d.Store.BanExists(ip); ok {
			t.Fatalf("%s darf nicht gesperrt werden", ip)
		}
	}
	if !strings.Contains(logBuf.String(), "ALLOW_INSECURE_LIST_URLS=true") || !strings.Contains(logBuf.String(), "https://") {
		t.Fatalf("Warnung muss die Abhilfe nennen:\n%s", logBuf.String())
	}
}

func TestListHTTPAllowedWithFlag(t *testing.T) {
	var hits atomic.Int32
	srv := plainListServer(t, "203.0.113.9\n", &hits)
	cfg := &config.Config{ExternalBlocklistURLs: []string{srv.URL + "/list.txt"}, ExternalBlocklistCacheDir: t.TempDir(), AllowInsecureListURLs: true}
	d, _ := newTestDaemon(t, cfg)
	var logBuf bytes.Buffer
	d.Logger = syslog.New(&logBuf, "DEBUG")

	for i := 0; i < 2; i++ {
		if err := d.SyncBlocklist(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := d.Store.BanExists("203.0.113.9"); !ok {
		t.Fatal("Eintrag der http-Liste muss mit ALLOW_INSECURE_LIST_URLS=true gesperrt werden")
	}
	if n := strings.Count(logBuf.String(), "unverschlüsselt per http://"); n != 1 {
		t.Fatalf("erwartet genau eine Warnung zur unverschlüsselten Quelle, gefunden %d:\n%s", n, logBuf.String())
	}
}

func TestListRejectsUnsupportedSchemes(t *testing.T) {
	cfg := &config.Config{ExternalBlocklistCacheDir: t.TempDir(), AllowInsecureListURLs: true}
	d, _ := newTestDaemon(t, cfg)
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com/list.txt", "https:///list.txt", "http://", "example.com/list.txt"} {
		if _, _, err := d.fetchCachedLines(context.Background(), u, cfg.ExternalBlocklistCacheDir, "blocklist", 0); err == nil {
			t.Errorf("%q muss abgelehnt werden", u)
		}
	}
}

func TestListRedirectDowngradeRejected(t *testing.T) {
	var hits atomic.Int32
	plain := plainListServer(t, "203.0.113.9\n", &hits)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/list.txt", http.StatusFound)
	}))
	t.Cleanup(redir.Close)

	cfg := &config.Config{ExternalBlocklistURLs: []string{redir.URL + "/list.txt"}, ExternalBlocklistCacheDir: t.TempDir()}
	d, _ := newTestDaemon(t, cfg)
	useListServer(d, redir)
	if err := d.SyncBlocklist(context.Background()); err == nil {
		t.Fatal("Weiterleitung https→http muss fehlschlagen")
	}
	if hits.Load() != 0 {
		t.Fatalf("http-Ziel der Weiterleitung wurde abgerufen: %d", hits.Load())
	}
	if ok, _ := d.Store.BanExists("203.0.113.9"); ok {
		t.Fatal("Eintrag hinter einer https→http-Weiterleitung darf nicht gesperrt werden")
	}
	if d.Client.CheckRedirect != nil {
		t.Fatal("der gemeinsame d.Client darf nicht verändert werden")
	}

	cfg.AllowInsecureListURLs = true
	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatalf("mit ALLOW_INSECURE_LIST_URLS=true muss die Weiterleitung erlaubt sein: %v", err)
	}
	if ok, _ := d.Store.BanExists("203.0.113.9"); !ok {
		t.Fatal("Eintrag nach erlaubter Weiterleitung fehlt")
	}
}

// oversizeServer liefert maxListBytes+1 Bytes gültiger Listeneinträge.
func oversizeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"oversize"`)
		line := []byte("203.0.113.77\n")
		chunk := bytes.Repeat(line, 64<<10/len(line))
		remaining := maxListBytes + 1
		for remaining > 0 {
			n := min(remaining, len(chunk))
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListOversizeFallsBackToCache(t *testing.T) {
	srv := oversizeServer(t)
	cacheDir := t.TempDir()
	cacheFile := filepath.Join(cacheDir, "blocklist_0.txt")
	if err := os.WriteFile(cacheFile, []byte("198.51.100.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ExternalBlocklistURLs: []string{srv.URL + "/list.txt"}, ExternalBlocklistCacheDir: cacheDir}
	d, _ := newTestDaemon(t, cfg)
	useListServer(d, srv)
	var logBuf bytes.Buffer
	d.Logger = syslog.New(&logBuf, "DEBUG")

	err := d.SyncBlocklist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "1 von 1 Quellen fehlgeschlagen") {
		t.Fatalf("zu große Liste muss als fehlgeschlagen gemeldet werden: %v", err)
	}
	if b, _ := os.ReadFile(cacheFile); string(b) != "198.51.100.1\n" {
		t.Fatalf("Cache wurde überschrieben (%d Bytes)", len(b))
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "blocklist_0.etag")); !os.IsNotExist(err) {
		t.Fatal("ETag einer verworfenen Liste darf nicht gespeichert werden")
	}
	if ok, _ := d.Store.BanExists("198.51.100.1"); !ok {
		t.Fatal("Einträge aus dem Cache müssen weiter genutzt werden")
	}
	if ok, _ := d.Store.BanExists("203.0.113.77"); ok {
		t.Fatal("Einträge der zu großen Liste dürfen nicht übernommen werden")
	}
	if !strings.Contains(logBuf.String(), "größer als 50 MB, nutze Cache") {
		t.Fatalf("Warnung fehlt:\n%s", logBuf.String())
	}
}

func TestListOversizeWithoutCacheFails(t *testing.T) {
	srv := oversizeServer(t)
	cacheDir := t.TempDir()
	cfg := &config.Config{ExternalBlocklistCacheDir: cacheDir}
	d, _ := newTestDaemon(t, cfg)
	useListServer(d, srv)

	lines, fromCache, err := d.fetchCachedLines(context.Background(), srv.URL+"/list.txt", cacheDir, "blocklist", 0)
	if err == nil || !strings.Contains(err.Error(), "größer als 50 MB") || lines != nil || fromCache {
		t.Fatalf("erwartet Fehler ohne Cache: lines=%d fromCache=%v err=%v", len(lines), fromCache, err)
	}
	for _, name := range []string{"blocklist_0.txt", "blocklist_0.tmp", "blocklist_0.etag"} {
		if _, err := os.Stat(filepath.Join(cacheDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s darf nicht geschrieben werden", name)
		}
	}
}
