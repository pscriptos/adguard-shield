package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type Store interface {
	LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error)
	UpsertGeoIP(ip, country string, dbMtime int64) error
}

type Resolver struct {
	DBPath        string
	effectivePath string
	LicenseKey    string
	Dir           string
	TTL           int64
	Store         Store
	reader        *maxminddb.Reader
	cache         map[string]string
	mtime         int64
}

func New(dbPath, licenseKey, dir string, ttl int64, store Store) *Resolver {
	return &Resolver{DBPath: dbPath, LicenseKey: licenseKey, Dir: dir, TTL: ttl, Store: store, cache: map[string]string{}}
}

func (r *Resolver) Open(ctx context.Context) error {
	path := r.DBPath
	if path == "" && r.LicenseKey != "" {
		var err error
		path, err = r.ensureAutoDB(ctx)
		if err != nil {
			return err
		}
	}
	if path == "" {
		return nil
	}
	r.effectivePath = path
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	r.reader = reader
	r.mtime = st.ModTime().Unix()
	if r.Store != nil {
		if c, err := r.Store.LoadGeoIPCache(r.TTL, r.mtime); err == nil {
			r.cache = c
		}
	}
	return nil
}

func (r *Resolver) Close() error {
	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}

func (r *Resolver) Lookup(ip string) (string, error) {
	if v, ok := r.cache[ip]; ok {
		return v, nil
	}
	if r.reader == nil {
		return r.lookupLegacy(ip)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
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
	if err := r.reader.Lookup(parsed, &rec); err != nil {
		return "", err
	}
	cc := strings.ToUpper(rec.Country.ISOCode)
	if cc == "" {
		cc = strings.ToUpper(rec.RegisteredCountry.ISOCode)
	}
	if cc != "" {
		r.cache[ip] = cc
		if r.Store != nil {
			_ = r.Store.UpsertGeoIP(ip, cc, r.mtime)
		}
	}
	return cc, nil
}

func (r *Resolver) lookupLegacy(ip string) (string, error) {
	if strings.Contains(ip, ":") {
		if cc, err := runGeoIPCommand("geoiplookup6", ip); err == nil && cc != "" {
			return cc, nil
		}
	} else {
		if cc, err := runGeoIPCommand("geoiplookup", ip); err == nil && cc != "" {
			return cc, nil
		}
	}
	if r.effectivePath != "" {
		if cc, err := runGeoIPCommand("mmdblookup", "--file", r.effectivePath, "--ip", ip, "country", "iso_code"); err == nil && cc != "" {
			return cc, nil
		}
	}
	return "", fmt.Errorf("no GeoIP result for %s", ip)
}

func runGeoIPCommand(name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", err
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`\b[A-Z]{2}\b`)
	matches := re.FindAllString(string(out), -1)
	for _, m := range matches {
		if m != "IP" {
			return strings.ToUpper(m), nil
		}
	}
	return "", nil
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

func (r *Resolver) ensureAutoDB(ctx context.Context) (string, error) {
	if err := os.MkdirAll(r.Dir, 0755); err != nil {
		return "", err
	}
	dst := filepath.Join(r.Dir, "GeoLite2-Country.mmdb")
	if st, err := os.Stat(dst); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
		return dst, nil
	}
	url := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=" + r.LicenseKey + "&suffix=tar.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MaxMind download failed: HTTP %d", resp.StatusCode)
	}
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	tmp := dst + ".tmp"
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if h.FileInfo().IsDir() || filepath.Base(h.Name) != "GeoLite2-Country.mmdb" {
			continue
		}
		f, err := os.Create(tmp)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(f, tr)
		closeErr := f.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return dst, os.Rename(tmp, dst)
	}
	return "", fmt.Errorf("GeoLite2-Country.mmdb not found in archive")
}
