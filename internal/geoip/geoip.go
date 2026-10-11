package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const (
	defaultDownloadURL = "https://download.maxmind.com/app/geoip_download"
	autoDBName         = "GeoLite2-Country.mmdb"
	autoDBMaxAge       = 24 * time.Hour
	maxDownloadBytes   = 100 << 20
	maxDBBytes         = 256 << 20
	defaultMaxCache    = 50000
	commandTimeout     = 5 * time.Second
)

var countryCodeRe = regexp.MustCompile(`\b[A-Z]{2}\b`)

type Store interface {
	LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error)
	UpsertGeoIP(ip, country string, dbMtime int64) error
}

type cacheEntry struct {
	country string
	at      int64
}

type Resolver struct {
	DBPath     string
	LicenseKey string
	Dir        string
	TTL        int64
	Store      Store

	// Test-Hooks; Nullwerte bedeuten Standardverhalten.
	downloadURL string
	client      *http.Client
	maxCache    int
	now         func() time.Time

	refreshMu     sync.Mutex
	mu            sync.RWMutex
	reader        *maxminddb.Reader
	effectivePath string
	cache         map[string]cacheEntry
	gen           uint64
	mtime         int64
	modTime       time.Time
}

func New(dbPath, licenseKey, dir string, ttl int64, store Store) *Resolver {
	return &Resolver{DBPath: dbPath, LicenseKey: licenseKey, Dir: dir, TTL: ttl, Store: store, cache: map[string]cacheEntry{}}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

func (r *Resolver) nowTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Open laedt die Datenbank. Schlaegt der automatische Download fehl, wird eine
// vorhandene aeltere Datenbank weiter genutzt und der Fehler trotzdem zurueckgegeben.
func (r *Resolver) Open(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	path := r.DBPath
	var dlErr error
	if path == "" && r.LicenseKey != "" {
		path, dlErr = r.ensureAutoDB(ctx)
		if path == "" {
			return dlErr
		}
	}
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	var loaded map[string]string
	if r.Store != nil {
		if c, err := r.Store.LoadGeoIPCache(r.TTL, st.ModTime().Unix()); err == nil {
			loaded = c
		}
	}
	r.swapReader(reader, path, st.ModTime())
	now := r.nowTime().Unix()
	r.mu.Lock()
	for ip, cc := range loaded {
		r.cache[ip] = cacheEntry{country: cc, at: now}
	}
	r.mu.Unlock()
	return dlErr
}

// Refresh laedt im Auto-Download-Modus eine neue Datenbank, sobald die lokale
// Datei aelter als 24h ist, und tauscht den Reader aus, wenn sich die mtime der
// Datenbankdatei geaendert hat. Der Rueckgabewert meldet einen Austausch.
func (r *Resolver) Refresh(ctx context.Context) (bool, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	path := r.DBPath
	var dlErr error
	if path == "" && r.LicenseKey != "" {
		path, dlErr = r.ensureAutoDB(ctx)
		if path == "" {
			return false, dlErr
		}
	}
	if path == "" {
		return false, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	r.mu.RLock()
	unchanged := r.reader != nil && r.effectivePath == path && r.modTime.Equal(st.ModTime())
	r.mu.RUnlock()
	if unchanged {
		return false, dlErr
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return false, err
	}
	r.swapReader(reader, path, st.ModTime())
	return true, dlErr
}

func (r *Resolver) swapReader(reader *maxminddb.Reader, path string, modTime time.Time) {
	r.mu.Lock()
	old := r.reader
	r.reader = reader
	r.effectivePath = path
	r.mtime = modTime.Unix()
	r.modTime = modTime
	r.cache = map[string]cacheEntry{}
	r.gen++
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func (r *Resolver) Close() error {
	r.mu.Lock()
	reader := r.reader
	r.reader = nil
	r.mu.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}

func (r *Resolver) fresh(e cacheEntry, now int64) bool {
	return r.TTL <= 0 || now-e.at < r.TTL
}

func (r *Resolver) Lookup(ip string) (string, error) {
	now := r.nowTime().Unix()
	r.mu.RLock()
	if e, ok := r.cache[ip]; ok && r.fresh(e, now) {
		r.mu.RUnlock()
		return e.country, nil
	}
	gen := r.gen
	if r.reader == nil {
		path := r.effectivePath
		r.mu.RUnlock()
		return r.lookupLegacy(ip, path, gen)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		r.mu.RUnlock()
		return "", fmt.Errorf("invalid IP %q", ip)
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}
	err := r.reader.Lookup(parsed, &rec)
	r.mu.RUnlock()
	if err != nil {
		return "", err
	}
	cc := strings.ToUpper(rec.Country.ISOCode)
	if cc == "" {
		cc = strings.ToUpper(rec.RegisteredCountry.ISOCode)
	}
	r.storeCache(ip, cc, gen)
	return cc, nil
}

func (r *Resolver) lookupLegacy(ip, dbPath string, gen uint64) (string, error) {
	if strings.Contains(ip, ":") {
		if cc, err := runGeoIPCommand("geoiplookup6", ip); err == nil && cc != "" {
			r.storeCache(ip, cc, gen)
			return cc, nil
		}
	} else {
		if cc, err := runGeoIPCommand("geoiplookup", ip); err == nil && cc != "" {
			r.storeCache(ip, cc, gen)
			return cc, nil
		}
	}
	if dbPath != "" {
		if cc, err := runGeoIPCommand("mmdblookup", "--file", dbPath, "--ip", ip, "country", "iso_code"); err == nil && cc != "" {
			r.storeCache(ip, cc, gen)
			return cc, nil
		}
	}
	return "", fmt.Errorf("no GeoIP result for %s", ip)
}

// storeCache verwirft Ergebnisse, die vor einem Datenbankwechsel (gen) ermittelt wurden.
func (r *Resolver) storeCache(ip, country string, gen uint64) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "" {
		return
	}
	now := r.nowTime().Unix()
	r.mu.Lock()
	if gen != r.gen {
		r.mu.Unlock()
		return
	}
	if r.cache == nil {
		r.cache = map[string]cacheEntry{}
	}
	if _, exists := r.cache[ip]; !exists && len(r.cache) >= r.cacheLimit() {
		r.pruneLocked(now)
	}
	r.cache[ip] = cacheEntry{country: country, at: now}
	mtime := r.mtime
	r.mu.Unlock()
	if r.Store != nil {
		_ = r.Store.UpsertGeoIP(ip, country, mtime)
	}
}

func (r *Resolver) cacheLimit() int {
	if r.maxCache > 0 {
		return r.maxCache
	}
	return defaultMaxCache
}

func (r *Resolver) pruneLocked(now int64) {
	for ip, e := range r.cache {
		if !r.fresh(e, now) {
			delete(r.cache, ip)
		}
	}
	if len(r.cache) >= r.cacheLimit() {
		r.cache = map[string]cacheEntry{}
	}
}

func runGeoIPCommand(name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	return parseCountryOutput(string(out)), nil
}

func parseCountryOutput(out string) string {
	for _, m := range countryCodeRe.FindAllString(out, -1) {
		if m != "IP" {
			return strings.ToUpper(m)
		}
	}
	return ""
}

func ShouldBlock(country, mode string, countries []string) bool {
	if country == "" || len(countries) == 0 {
		return false
	}
	found := false
	country = strings.ToUpper(country)
	for _, c := range countries {
		if strings.ToUpper(strings.TrimSpace(c)) == country {
			found = true
			break
		}
	}
	if strings.ToLower(mode) == "allowlist" {
		return !found
	}
	return found
}

func IsPrivateIP(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return isPrivateAddr(p.Addr())
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return isPrivateAddr(a)
}

func isPrivateAddr(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() ||
		(a.Is4() && strings.HasPrefix(a.String(), "100.") && isCGNAT(a))
}

func isCGNAT(a netip.Addr) bool {
	p := a.As4()
	return p[0] == 100 && p[1] >= 64 && p[1] <= 127
}

// ensureAutoDB liefert den Pfad der automatisch verwalteten Datenbank. Schlaegt
// ein faelliger Download fehl, wird eine vorhandene alte Datei zusammen mit dem
// Fehler zurueckgegeben. Fehler enthalten nie den License-Key.
func (r *Resolver) ensureAutoDB(ctx context.Context) (string, error) {
	if err := os.MkdirAll(r.Dir, 0755); err != nil {
		return "", r.sanitizeErr(err)
	}
	dst := filepath.Join(r.Dir, autoDBName)
	st, statErr := os.Stat(dst)
	if statErr == nil && r.nowTime().Sub(st.ModTime()) < autoDBMaxAge {
		return dst, nil
	}
	if err := r.downloadDB(ctx, dst); err != nil {
		if statErr == nil {
			return dst, r.sanitizeErr(err)
		}
		return "", r.sanitizeErr(err)
	}
	return dst, nil
}

func (r *Resolver) downloadDB(ctx context.Context, dst string) error {
	base := r.downloadURL
	if base == "" {
		base = defaultDownloadURL
	}
	q := url.Values{}
	q.Set("edition_id", "GeoLite2-Country")
	q.Set("license_key", r.LicenseKey)
	q.Set("suffix", "tar.gz")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	client := r.client
	if client == nil {
		client = newHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MaxMind download failed: HTTP %d", resp.StatusCode)
	}
	gzr, err := gzip.NewReader(io.LimitReader(resp.Body, maxDownloadBytes))
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.FileInfo().IsDir() || filepath.Base(h.Name) != autoDBName {
			continue
		}
		return installDB(tr, dst)
	}
	return fmt.Errorf("%s not found in archive", autoDBName)
}

// installDB schreibt die Datenbank in eine temporaere Datei, prueft sie mit
// maxminddb und ersetzt erst dann die bestehende Datei.
func installDB(src io.Reader, dst string) (err error) {
	f, err := os.CreateTemp(filepath.Dir(dst), autoDBName+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	n, copyErr := io.Copy(f, io.LimitReader(src, maxDBBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxDBBytes {
		return fmt.Errorf("%s exceeds %d bytes", autoDBName, maxDBBytes)
	}
	check, err := maxminddb.Open(tmp)
	if err != nil {
		return fmt.Errorf("downloaded %s is invalid: %w", autoDBName, err)
	}
	if err := check.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (r *Resolver) sanitizeErr(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	if r.LicenseKey == "" {
		return err
	}
	msg := err.Error()
	redacted := redact(msg, r.LicenseKey)
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

func redact(msg, key string) string {
	for _, k := range []string{key, url.QueryEscape(key), url.PathEscape(key)} {
		if k != "" {
			msg = strings.ReplaceAll(msg, k, "[REDACTED]")
		}
	}
	return msg
}
