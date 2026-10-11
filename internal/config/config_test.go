package config

import (
	"os"
	"path/filepath"
	"strings"
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

func loadString(t *testing.T, content string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adguard-shield.conf")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasWarning(c *Config, substr string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestLoadDefaultsWithoutWarnings(t *testing.T) {
	c := loadString(t, "ADGUARD_URL=\"https://dns.example\"\n")
	if len(c.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings)
	}
	if c.AdGuardTLSInsecure {
		t.Fatal("ADGUARD_TLS_INSECURE must default to false")
	}
	if c.HistoryRetentionDays != 0 {
		t.Fatalf("BAN_HISTORY_RETENTION_DAYS default: %d", c.HistoryRetentionDays)
	}
	if c.LogMaxSizeMB != 50 {
		t.Fatalf("LOG_MAX_SIZE_MB default: %d", c.LogMaxSizeMB)
	}
	if c.CheckInterval != 10 || c.FirewallMode != "host" || c.NotifyType != "ntfy" || c.ReportInterval != "weekly" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadNewKeys(t *testing.T) {
	c := loadString(t, "ADGUARD_TLS_INSECURE=true\nBAN_HISTORY_RETENTION_DAYS=30\nLOG_MAX_SIZE_MB=0\n")
	if !c.AdGuardTLSInsecure || c.HistoryRetentionDays != 30 || c.LogMaxSizeMB != 0 {
		t.Fatalf("unexpected values: tls=%v retention=%d logmax=%d", c.AdGuardTLSInsecure, c.HistoryRetentionDays, c.LogMaxSizeMB)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings)
	}
	c = loadString(t, "BAN_HISTORY_RETENTION_DAYS=-1\nLOG_MAX_SIZE_MB=-5\n")
	if c.HistoryRetentionDays != 0 || c.LogMaxSizeMB != 50 {
		t.Fatalf("negative values not reset: retention=%d logmax=%d", c.HistoryRetentionDays, c.LogMaxSizeMB)
	}
	if !hasWarning(c, "BAN_HISTORY_RETENTION_DAYS") || !hasWarning(c, "LOG_MAX_SIZE_MB") {
		t.Fatalf("missing warnings: %v", c.Warnings)
	}
}

func TestLoadWarnsOnUnknownAndDeprecatedKeys(t *testing.T) {
	c := loadString(t, "CHEK_INTERVAL=5\nBAN_HISTORY_FILE=\"/var/log/adguard-shield-bans.log\"\n")
	if !hasWarning(c, "Unbekannter Konfigurationsschlüssel CHEK_INTERVAL") {
		t.Fatalf("missing unknown-key warning: %v", c.Warnings)
	}
	if !hasWarning(c, "BAN_HISTORY_FILE wird ignoriert") || hasWarning(c, "Unbekannter Konfigurationsschlüssel BAN_HISTORY_FILE") {
		t.Fatalf("unexpected deprecated-key warnings: %v", c.Warnings)
	}
	if c.CheckInterval != 10 {
		t.Fatalf("CheckInterval: %d", c.CheckInterval)
	}
}

func TestLoadWarnsOnUnparseableValues(t *testing.T) {
	c := loadString(t, "RATE_LIMIT_WINDOW=abc\nGEOIP_ENABLED=vielleicht\n")
	if c.RateLimitWindow != 60 || c.GeoIPEnabled {
		t.Fatalf("defaults not used: window=%d geoip=%v", c.RateLimitWindow, c.GeoIPEnabled)
	}
	if !hasWarning(c, "RATE_LIMIT_WINDOW") || !hasWarning(c, "GEOIP_ENABLED") {
		t.Fatalf("missing warnings: %v", c.Warnings)
	}
}

func TestLoadSanitizesNonPositiveValues(t *testing.T) {
	c := loadString(t, `CHECK_INTERVAL=0
BAN_DURATION=-10
PROGRESSIVE_BAN_MULTIPLIER=0
GEOIP_CACHE_TTL=-5
PROGRESSIVE_BAN_MAX_LEVEL=-1
GEOIP_CHECK_INTERVAL=-3
EXTERNAL_BLOCKLIST_BAN_DURATION=0
`)
	if c.CheckInterval != 10 || c.BanDuration != 3600 || c.ProgressiveBanMultiplier != 2 || c.GeoIPCacheTTL != 86400 {
		t.Fatalf("positive values not sanitized: %+v", c)
	}
	if c.ProgressiveBanMaxLevel != 5 || c.GeoIPCheckInterval != 0 || c.ExternalBlocklistDuration != 0 {
		t.Fatalf("non-negative values not sanitized: %+v", c)
	}
	for _, k := range []string{"CHECK_INTERVAL", "BAN_DURATION", "PROGRESSIVE_BAN_MULTIPLIER", "GEOIP_CACHE_TTL", "PROGRESSIVE_BAN_MAX_LEVEL", "GEOIP_CHECK_INTERVAL"} {
		if !hasWarning(c, k) {
			t.Fatalf("missing warning for %s: %v", k, c.Warnings)
		}
	}
	if hasWarning(c, "EXTERNAL_BLOCKLIST_BAN_DURATION") {
		t.Fatalf("0 is valid for EXTERNAL_BLOCKLIST_BAN_DURATION: %v", c.Warnings)
	}
}

func TestLoadValidatesEnums(t *testing.T) {
	c := loadString(t, `GEOIP_MODE="denylist"
FIREWALL_MODE="iptables"
LOG_LEVEL="verbose"
NOTIFY_TYPE="telegram"
REPORT_FORMAT="pdf"
REPORT_INTERVAL="hourly"
`)
	if c.GeoIPMode != "blocklist" || c.FirewallMode != "host" || c.LogLevel != "INFO" || c.NotifyType != "ntfy" || c.ReportFormat != "html" || c.ReportInterval != "weekly" {
		t.Fatalf("invalid enums not reset: %+v", c)
	}
	if len(c.Warnings) != 6 {
		t.Fatalf("expected 6 warnings, got %v", c.Warnings)
	}
	c = loadString(t, `GEOIP_MODE="Allowlist"
FIREWALL_MODE="Docker-Published"
LOG_LEVEL="warning"
NOTIFY_TYPE="Gotify"
REPORT_FORMAT="TXT"
REPORT_INTERVAL="Monthly"
`)
	if c.GeoIPMode != "allowlist" || c.FirewallMode != "docker-published" || c.LogLevel != "WARNING" || c.NotifyType != "gotify" || c.ReportFormat != "txt" || c.ReportInterval != "monthly" {
		t.Fatalf("valid enums not accepted: %+v", c)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings)
	}
}

func TestKnownKeysContainsNewKeys(t *testing.T) {
	keys := map[string]bool{}
	for _, k := range KnownKeys() {
		keys[k] = true
	}
	for _, k := range []string{"ADGUARD_TLS_INSECURE", "NOTIFY_TLS_INSECURE", "ALLOW_INSECURE_LIST_URLS", "BAN_HISTORY_RETENTION_DAYS", "LOG_MAX_SIZE_MB", "CHECK_INTERVAL", "GEOIP_CACHE_TTL"} {
		if !keys[k] {
			t.Fatalf("KnownKeys misses %s", k)
		}
	}
	if keys["BAN_HISTORY_FILE"] {
		t.Fatal("deprecated key must not be known")
	}
}

func TestLoadZeroMeansPermanentOrNeverExpire(t *testing.T) {
	c := loadString(t, "BAN_DURATION=0\nGEOIP_CACHE_TTL=0\n")
	if c.BanDuration != 0 || c.GeoIPCacheTTL != 0 {
		t.Fatalf("0 must be kept: ban=%d ttl=%d", c.BanDuration, c.GeoIPCacheTTL)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings)
	}
}

func TestLoadBlockedPorts(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		warning bool
	}{
		{"", "53 443 853", false},
		{`BLOCKED_PORTS="53,853"`, "53 853", false},
		{`BLOCKED_PORTS="53, 443 ,853"`, "53 443 853", false},
		{`BLOCKED_PORTS="53 1000:2000"`, "53 1000:2000", false},
		{`BLOCKED_PORTS="053"`, "53", false},
		{`BLOCKED_PORTS="53 abc 70000 0 2000:1000 1:"`, "53", true},
		{`BLOCKED_PORTS="abc,99999"`, "53 443 853", true},
		{`BLOCKED_PORTS=""`, "53", false},
	}
	for _, tc := range cases {
		c := loadString(t, tc.in+"\n")
		if got := strings.Join(c.BlockedPorts, " "); got != tc.want {
			t.Errorf("%s: ports = %q, want %q", tc.in, got, tc.want)
		}
		if got := hasWarning(c, "BLOCKED_PORTS"); got != tc.warning {
			t.Errorf("%s: warning = %v, want %v (%v)", tc.in, got, tc.warning, c.Warnings)
		}
	}
}

func TestLoadNotifyTLSInsecure(t *testing.T) {
	if c := loadString(t, "\n"); c.NotifyTLSInsecure {
		t.Fatal("NOTIFY_TLS_INSECURE must default to false")
	}
	if c := loadString(t, "NOTIFY_TLS_INSECURE=true\n"); !c.NotifyTLSInsecure || len(c.Warnings) != 0 {
		t.Fatalf("NOTIFY_TLS_INSECURE=true not applied: %v %v", c.NotifyTLSInsecure, c.Warnings)
	}
}

func TestLoadWebDefaults(t *testing.T) {
	c := loadString(t, "ADGUARD_URL=\"https://dns.example\"\n")
	if c.WebEnabled || c.WebListen != "127.0.0.1:8443" || c.WebBasePath != "/" || c.WebUser != "admin" || c.WebPassword != "" || c.WebTLSCert != "" || c.WebTLSKey != "" {
		t.Fatalf("unexpected web defaults: %+v", c)
	}
	keys := map[string]bool{}
	for _, k := range KnownKeys() {
		keys[k] = true
	}
	for _, k := range []string{"WEB_ENABLED", "WEB_LISTEN", "WEB_BASE_PATH", "WEB_USER", "WEB_PASSWORD", "WEB_TLS_CERT", "WEB_TLS_KEY"} {
		if !keys[k] {
			t.Fatalf("KnownKeys misses %s", k)
		}
	}
}

func TestLoadWebValues(t *testing.T) {
	c := loadString(t, `WEB_ENABLED=true
WEB_LISTEN="[::1]:9000"
WEB_BASE_PATH="adguard-shield"
WEB_USER="viewer"
WEB_PASSWORD='p#ss word'
WEB_TLS_CERT="/etc/ssl/c.pem"
WEB_TLS_KEY="/etc/ssl/k.pem"
`)
	if !c.WebEnabled || c.WebListen != "[::1]:9000" || c.WebBasePath != "/adguard-shield/" || c.WebUser != "viewer" || c.WebPassword != "p#ss word" || c.WebTLSCert != "/etc/ssl/c.pem" || c.WebTLSKey != "/etc/ssl/k.pem" {
		t.Fatalf("unexpected web values: %+v", c)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings)
	}
}

func TestLoadWebListenValidation(t *testing.T) {
	for _, v := range []string{"8443", "127.0.0.1", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:http", "::1:8443"} {
		c := loadString(t, "WEB_LISTEN=\""+v+"\"\n")
		if c.WebListen != DefaultWebListen || !hasWarning(c, "WEB_LISTEN") {
			t.Errorf("%q: listen=%q warnings=%v", v, c.WebListen, c.Warnings)
		}
	}
	for _, v := range []string{":8443", "0.0.0.0:443", "localhost:8080"} {
		c := loadString(t, "WEB_LISTEN=\""+v+"\"\n")
		if c.WebListen != v || len(c.Warnings) != 0 {
			t.Errorf("%q: listen=%q warnings=%v", v, c.WebListen, c.Warnings)
		}
	}
}

func TestNormalizeBasePath(t *testing.T) {
	ok := map[string]string{
		"":                 "/",
		"/":                "/",
		"adguard-shield":   "/adguard-shield/",
		"/adguard-shield":  "/adguard-shield/",
		"/adguard-shield/": "/adguard-shield/",
		"//a//b//":         "/a/b/",
		"/a.b/c_d~e/":      "/a.b/c_d~e/",
	}
	for in, want := range ok {
		if got, valid := NormalizeBasePath(in); !valid || got != want {
			t.Errorf("%q -> %q (%v), erwartet %q", in, got, valid, want)
		}
	}
	for _, in := range []string{"/../etc", "/a/./b", "/a b", "/a?x", "/a#b", "/ä", `/<script>`, "/a%2f"} {
		if _, valid := NormalizeBasePath(in); valid {
			t.Errorf("%q sollte ungültig sein", in)
		}
	}
	c := loadString(t, "WEB_BASE_PATH=\"/../x\"\n")
	if c.WebBasePath != "/" || !hasWarning(c, "WEB_BASE_PATH") {
		t.Fatalf("base=%q warnings=%v", c.WebBasePath, c.Warnings)
	}
}

func TestLoadWebTLSPairWarning(t *testing.T) {
	for _, content := range []string{"WEB_TLS_CERT=\"/c.pem\"\n", "WEB_TLS_KEY=\"/k.pem\"\n"} {
		if c := loadString(t, content); !hasWarning(c, "WEB_TLS_CERT und WEB_TLS_KEY") {
			t.Errorf("%q: warnings=%v", content, c.Warnings)
		}
	}
	if c := loadString(t, "WEB_USER=\"a:b\"\n"); !hasWarning(c, "WEB_USER") {
		t.Errorf("Doppelpunkt im Benutzernamen nicht gewarnt: %v", c.Warnings)
	}
}

func TestCheckListURL(t *testing.T) {
	cases := []struct {
		url          string
		allow        bool
		wantInsecure bool
		wantErr      bool
	}{
		{"https://example.com/list.txt", false, false, false},
		{"HTTPS://example.com/list.txt", false, false, false},
		{"http://example.com/list.txt", false, false, true},
		{"http://example.com/list.txt", true, true, false},
		{"file:///etc/passwd", true, false, true},
		{"ftp://example.com/list.txt", true, false, true},
		{"https:///list.txt", true, false, true},
		{"http://", true, false, true},
		{"example.com/list.txt", true, false, true},
		{"", true, false, true},
	}
	for _, tc := range cases {
		insecure, err := CheckListURL(tc.url, tc.allow)
		if (err != nil) != tc.wantErr || insecure != tc.wantInsecure {
			t.Errorf("CheckListURL(%q, %v) = %v, %v", tc.url, tc.allow, insecure, err)
		}
	}
	if _, err := CheckListURL("http://example.com/x?token=geheim", false); err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_LIST_URLS=true") || strings.Contains(err.Error(), "geheim") {
		t.Fatalf("Fehler muss die Abhilfe nennen und darf die URL nicht enthalten: %v", err)
	}
}

func TestLoadWarnsAboutListURLs(t *testing.T) {
	c := loadString(t, `EXTERNAL_BLOCKLIST_URLS="https://ok.example/a.txt,http://plain.example/b.txt?token=geheim"
EXTERNAL_WHITELIST_URLS="file:///etc/hosts"
`)
	if c.AllowInsecureListURLs {
		t.Fatal("ALLOW_INSECURE_LIST_URLS must default to false")
	}
	if !hasWarning(c, "EXTERNAL_BLOCKLIST_URLS: Quelle #2 (http://plain.example) wird nicht geladen") || !hasWarning(c, "EXTERNAL_WHITELIST_URLS: Quelle #1 wird nicht geladen") {
		t.Fatalf("missing warnings: %v", c.Warnings)
	}
	if hasWarning(c, "Quelle #1 (https://ok.example)") || hasWarning(c, "geheim") {
		t.Fatalf("unexpected warning: %v", c.Warnings)
	}

	c = loadString(t, "ALLOW_INSECURE_LIST_URLS=true\nEXTERNAL_BLOCKLIST_URLS=\"http://plain.example/b.txt\"\n")
	if !c.AllowInsecureListURLs || !hasWarning(c, "unverschlüsselt per http://") {
		t.Fatalf("insecure URL must be allowed with a warning: %v", c.Warnings)
	}
}
