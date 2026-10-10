package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeGeoIPStore struct {
	ip      string
	country string
	mtime   int64
	loaded  map[string]string
}

func (s *fakeGeoIPStore) LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range s.loaded {
		out[k] = v
	}
	return out, nil
}

func (s *fakeGeoIPStore) UpsertGeoIP(ip, country string, dbMtime int64) error {
	s.ip = ip
	s.country = country
	s.mtime = dbMtime
	return nil
}

// buildMMDB erzeugt eine minimale IPv4-MaxMind-DB, die jede Adresse auf cc abbildet.
func buildMMDB(cc string) []byte {
	var b bytes.Buffer
	// Ein Knoten, beide Records zeigen auf Daten-Offset 0 (node_count + 16).
	b.Write([]byte{0, 0, 17, 0, 0, 17})
	b.Write(make([]byte, 16))
	writeStr := func(s string) {
		b.WriteByte(0x40 | byte(len(s)))
		b.WriteString(s)
	}
	b.WriteByte(0xE1)
	writeStr("country")
	b.WriteByte(0xE1)
	writeStr("iso_code")
	writeStr(cc)
	b.WriteString("\xAB\xCD\xEFMaxMind.com")
	b.WriteByte(0xE5)
	writeStr("node_count")
	b.Write([]byte{0xC1, 1})
	writeStr("record_size")
	b.Write([]byte{0xA1, 24})
	writeStr("ip_version")
	b.Write([]byte{0xA1, 4})
	writeStr("binary_format_major_version")
	b.Write([]byte{0xA1, 2})
	writeStr("database_type")
	writeStr("Test-Country")
	return b.Bytes()
}

func buildArchive(t *testing.T, mmdb []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	name := "GeoLite2-Country_20260101/GeoLite2-Country.mmdb"
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(mmdb)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(mmdb); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFixture(t *testing.T, dir, cc string) string {
	t.Helper()
	path := filepath.Join(dir, "test.mmdb")
	if err := os.WriteFile(path, buildMMDB(cc), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShouldBlockModes(t *testing.T) {
	countries := []string{"CN", "RU"}
	if !ShouldBlock("cn", "blocklist", countries) {
		t.Fatal("blocklist should block listed country")
	}
	if ShouldBlock("DE", "blocklist", countries) {
		t.Fatal("blocklist should allow unlisted country")
	}
	if ShouldBlock("CN", "allowlist", countries) {
		t.Fatal("allowlist should allow listed country")
	}
	if !ShouldBlock("DE", "allowlist", countries) {
		t.Fatal("allowlist should block unlisted country")
	}
}

func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "192.168.1.10", "10.1.2.3", "100.64.0.1", "::1", "fd00::1"} {
		if !IsPrivateIP(ip) {
			t.Fatalf("%s should be private", ip)
		}
	}
	if IsPrivateIP("8.8.8.8") {
		t.Fatal("8.8.8.8 should be public")
	}
}

func TestStoreCachePersistsLegacyLookupResult(t *testing.T) {
	store := &fakeGeoIPStore{}
	r := New("", "", "", 86400, store)
	r.mtime = 123

	r.storeCache("203.0.113.7", "cn", r.gen)

	if got := r.cache["203.0.113.7"].country; got != "CN" {
		t.Fatalf("cache = %q, want CN", got)
	}
	if store.ip != "203.0.113.7" || store.country != "CN" || store.mtime != 123 {
		t.Fatalf("store got ip=%q country=%q mtime=%d", store.ip, store.country, store.mtime)
	}
}

func TestStoreCacheDropsResultFromOldGeneration(t *testing.T) {
	store := &fakeGeoIPStore{}
	r := New("", "", "", 86400, store)
	gen := r.gen
	r.gen++
	r.storeCache("203.0.113.7", "CN", gen)
	if len(r.cache) != 0 || store.ip != "" {
		t.Fatalf("stale generation result was stored: cache=%v store=%q", r.cache, store.ip)
	}
}

func TestParseCountryOutput(t *testing.T) {
	if got := parseCountryOutput("GeoIP Country Edition: CN, China"); got != "CN" {
		t.Fatalf("got %q", got)
	}
	if got := parseCountryOutput("IP Address not found"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "DE")
	now := time.Unix(1_800_000_000, 0)
	r := New(path, "", "", 60, nil)
	r.now = func() time.Time { return now }
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	r.mu.Lock()
	r.cache["198.51.100.1"] = cacheEntry{country: "CN", at: now.Unix()}
	r.mu.Unlock()
	if cc, _ := r.Lookup("198.51.100.1"); cc != "CN" {
		t.Fatalf("fresh cache entry not used, got %q", cc)
	}
	now = now.Add(61 * time.Second)
	cc, err := r.Lookup("198.51.100.1")
	if err != nil || cc != "DE" {
		t.Fatalf("expired entry should be re-resolved from DB, got %q, %v", cc, err)
	}
	if e := r.cache["198.51.100.1"]; e.country != "DE" || e.at != now.Unix() {
		t.Fatalf("cache entry not refreshed: %+v", e)
	}
}

func TestOpenLoadsStoreCacheAsFresh(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "DE")
	store := &fakeGeoIPStore{loaded: map[string]string{"198.51.100.9": "US"}}
	r := New(path, "", "", 3600, store)
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if cc, _ := r.Lookup("198.51.100.9"); cc != "US" {
		t.Fatalf("loaded cache entry not used, got %q", cc)
	}
}

func TestCacheCapPrunesExpiredThenResets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := New("", "", "", 60, nil)
	r.maxCache = 3
	r.now = func() time.Time { return now }
	r.cache["a"] = cacheEntry{country: "DE", at: now.Unix() - 120}
	r.cache["b"] = cacheEntry{country: "DE", at: now.Unix()}
	r.cache["c"] = cacheEntry{country: "DE", at: now.Unix()}

	r.storeCache("d", "FR", r.gen)
	if len(r.cache) != 3 {
		t.Fatalf("expected expired entry pruned, cache=%v", r.cache)
	}
	if _, ok := r.cache["a"]; ok {
		t.Fatal("expired entry should be removed")
	}

	r.storeCache("e", "FR", r.gen)
	if len(r.cache) != 1 || r.cache["e"].country != "FR" {
		t.Fatalf("expected reset map with only new entry, cache=%v", r.cache)
	}

	r.storeCache("e", "NL", r.gen)
	if len(r.cache) != 1 || r.cache["e"].country != "NL" {
		t.Fatalf("update of existing key must not reset, cache=%v", r.cache)
	}
}

func TestRefreshNoopWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "DE")
	r := New(path, "", "", 3600, nil)
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := r.Lookup("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	swapped, err := r.Refresh(context.Background())
	if err != nil || swapped {
		t.Fatalf("Refresh = %v, %v; want false, nil", swapped, err)
	}
	if len(r.cache) != 1 {
		t.Fatal("cache must be kept when DB is unchanged")
	}
}

func TestRefreshSwapsReaderOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "DE")
	r := New(path, "", "", 3600, nil)
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if cc, _ := r.Lookup("198.51.100.1"); cc != "DE" {
		t.Fatalf("got %q, want DE", cc)
	}

	newPath := filepath.Join(dir, "new.mmdb")
	if err := os.WriteFile(newPath, buildMMDB("FR"), 0644); err != nil {
		t.Fatal(err)
	}
	want := "FR"
	if err := os.Rename(newPath, path); err != nil {
		// Windows kann eine gemappte Datei nicht ersetzen; dann nur mtime aendern.
		want = "DE"
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	oldGen := r.gen
	swapped, err := r.Refresh(context.Background())
	if err != nil || !swapped {
		t.Fatalf("Refresh = %v, %v; want true, nil", swapped, err)
	}
	if len(r.cache) != 0 || r.gen == oldGen || r.mtime != future.Unix() {
		t.Fatalf("cache not cleared or state not updated: cache=%v gen=%d mtime=%d", r.cache, r.gen, r.mtime)
	}
	if cc, _ := r.Lookup("198.51.100.1"); cc != want {
		t.Fatalf("after refresh got %q, want %q", cc, want)
	}
}

func TestOpenAutoDownloadInstallsValidDB(t *testing.T) {
	archive := buildArchive(t, buildMMDB("DE"))
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotKey = req.URL.Query().Get("license_key")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := New("", "key+with/special", dir, 3600, nil)
	r.downloadURL = srv.URL
	r.client = srv.Client()
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if gotKey != "key+with/special" {
		t.Fatalf("license key not passed correctly: %q", gotKey)
	}
	if cc, err := r.Lookup("203.0.113.5"); err != nil || cc != "DE" {
		t.Fatalf("Lookup = %q, %v", cc, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func TestAutoDownloadKeepsOldDBWhenInvalid(t *testing.T) {
	archive := buildArchive(t, []byte("not a database"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, autoDBName)
	if err := os.WriteFile(dst, buildMMDB("DE"), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dst, old, old); err != nil {
		t.Fatal(err)
	}
	r := New("", "secret", dir, 3600, nil)
	r.downloadURL = srv.URL
	r.client = srv.Client()
	err := r.Open(context.Background())
	t.Cleanup(func() { _ = r.Close() })
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid DB error, got %v", err)
	}
	if cc, lerr := r.Lookup("203.0.113.5"); lerr != nil || cc != "DE" {
		t.Fatalf("old DB should stay in use, got %q, %v", cc, lerr)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func TestRefreshRedownloadsStaleAutoDB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows kann gemappte Dateien nicht ersetzen")
	}
	country := "DE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(buildArchive(t, buildMMDB(country)))
	}))
	defer srv.Close()

	dir := t.TempDir()
	now := time.Now()
	r := New("", "secret", dir, 3600, nil)
	r.downloadURL = srv.URL
	r.client = srv.Client()
	r.now = func() time.Time { return now }
	if err := r.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if swapped, err := r.Refresh(context.Background()); err != nil || swapped {
		t.Fatalf("fresh DB must not be refreshed: %v, %v", swapped, err)
	}
	country = "FR"
	now = now.Add(25 * time.Hour)
	swapped, err := r.Refresh(context.Background())
	if err != nil || !swapped {
		t.Fatalf("Refresh = %v, %v; want true, nil", swapped, err)
	}
	if cc, _ := r.Lookup("203.0.113.5"); cc != "FR" {
		t.Fatalf("got %q, want FR", cc)
	}
}

type leakyTransport struct{}

func (leakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("dial failed for %s (key %s)", req.URL.String(), req.URL.Query().Get("license_key"))
}

func TestDownloadErrorsDoNotLeakLicenseKey(t *testing.T) {
	const key = "SuperSecretKey_123"
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "nope "+req.URL.String(), http.StatusUnauthorized)
	}))
	defer failing.Close()

	cases := map[string]*Resolver{}
	r1 := New("", key, t.TempDir(), 3600, nil)
	r1.downloadURL = closedURL
	r1.client = &http.Client{Timeout: 5 * time.Second}
	cases["connection refused"] = r1
	r2 := New("", key, t.TempDir(), 3600, nil)
	r2.downloadURL = "https://example.invalid/download"
	r2.client = &http.Client{Transport: leakyTransport{}}
	cases["transport error"] = r2
	r3 := New("", key, t.TempDir(), 3600, nil)
	r3.downloadURL = failing.URL
	r3.client = failing.Client()
	cases["http status"] = r3

	for name, r := range cases {
		err := r.Open(context.Background())
		if err == nil {
			t.Fatalf("%s: expected error", name)
		}
		if strings.Contains(err.Error(), key) {
			t.Fatalf("%s: license key leaked: %v", name, err)
		}
		_, err = r.Refresh(context.Background())
		if err == nil || strings.Contains(err.Error(), key) {
			t.Fatalf("%s: Refresh error leaked key or missing: %v", name, err)
		}
	}
}

func TestSanitizeErrRedactsKey(t *testing.T) {
	r := New("", "a b&c", "", 0, nil)
	err := r.sanitizeErr(errors.New("failed: license_key=a+b%26c and a b&c"))
	if strings.Contains(err.Error(), "a b&c") || strings.Contains(err.Error(), "a+b%26c") {
		t.Fatalf("key not redacted: %v", err)
	}
}
