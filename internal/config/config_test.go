package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadParsesShellStyleConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adguard-shield.conf")
	err := os.WriteFile(path, []byte(`
ADGUARD_URL="https://dns.example"
ADGUARD_USER="admin"
ADGUARD_PASS='pa#ss'
CHECK_INTERVAL=7
BLOCKED_PORTS="53 443 853"
FIREWALL_BACKEND="ipset"
FIREWALL_MODE="docker-bridge"
GEOIP_ENABLED=true
GEOIP_MODE="allowlist"
GEOIP_COUNTRIES="DE, us"
GEOIP_CACHE_TTL=123
`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.AdGuardPass != "pa#ss" {
		t.Fatalf("quoted # was not preserved: %q", c.AdGuardPass)
	}
	if c.CheckInterval != 7 || c.FirewallBackend != "ipset" || c.FirewallMode != "docker-bridge" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if got := c.GeoIPCountries; len(got) != 2 || got[0] != "DE" || got[1] != "US" {
		t.Fatalf("unexpected countries: %#v", got)
	}
	if c.GeoIPCacheTTL != 123 {
		t.Fatalf("unexpected GeoIP cache ttl: %d", c.GeoIPCacheTTL)
	}
}
