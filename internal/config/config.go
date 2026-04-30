package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Path string

	AdGuardURL  string
	AdGuardUser string
	AdGuardPass string

	RateLimitMaxRequests int
	RateLimitWindow      int
	CheckInterval        int
	APIQueryLimit        int

	SubdomainFloodEnabled   bool
	SubdomainFloodMaxUnique int
	SubdomainFloodWindow    int

	DNSFloodWatchlistEnabled bool
	DNSFloodWatchlist        []string

	BanDuration     int64
	Chain           string
	BlockedPorts    []string
	FirewallBackend string
	FirewallMode    string
	DryRun          bool

	Whitelist []string

	LogFile  string
	LogLevel string
	StateDir string
	PIDFile  string

	NotifyEnabled bool
	NotifyType    string
	NotifyWebhook string
	NTFYServerURL string
	NTFYTopic     string
	NTFYToken     string
	NTFYPriority  string

	ReportEnabled         bool
	ReportInterval        string
	ReportTime            string
	ReportEmailTo         string
	ReportEmailFrom       string
	ReportFormat          string
	ReportMailCmd         string
	ReportBusiestDayRange int

	ExternalWhitelistEnabled  bool
	ExternalWhitelistURLs     []string
	ExternalWhitelistInterval int
	ExternalWhitelistCacheDir string

	ExternalBlocklistEnabled   bool
	ExternalBlocklistURLs      []string
	ExternalBlocklistInterval  int
	ExternalBlocklistCacheDir  string
	ExternalBlocklistDuration  int64
	ExternalBlocklistAutoUnban bool
	ExternalBlocklistNotify    bool

	ProgressiveBanEnabled    bool
	ProgressiveBanMultiplier int
	ProgressiveBanMaxLevel   int
	ProgressiveBanResetAfter int64

	AbuseIPDBEnabled    bool
	AbuseIPDBAPIKey     string
	AbuseIPDBCategories string

	GeoIPEnabled       bool
	GeoIPMode          string
	GeoIPCountries     []string
	GeoIPNotify        bool
	GeoIPSkipPrivate   bool
	GeoIPLicenseKey    string
	GeoIPMMDBPath      string
	GeoIPCacheTTL      int64
	GeoIPCheckInterval int
}

func Load(path string) (*Config, error) {
	values, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Path: path}
	c.AdGuardURL = stringVal(values, "ADGUARD_URL", "")
	c.AdGuardUser = stringVal(values, "ADGUARD_USER", "")
	c.AdGuardPass = stringVal(values, "ADGUARD_PASS", "")
	c.RateLimitMaxRequests = intVal(values, "RATE_LIMIT_MAX_REQUESTS", 30)
	c.RateLimitWindow = intVal(values, "RATE_LIMIT_WINDOW", 60)
	c.CheckInterval = intVal(values, "CHECK_INTERVAL", 10)
	c.APIQueryLimit = intVal(values, "API_QUERY_LIMIT", 500)
	c.SubdomainFloodEnabled = boolVal(values, "SUBDOMAIN_FLOOD_ENABLED", true)
	c.SubdomainFloodMaxUnique = intVal(values, "SUBDOMAIN_FLOOD_MAX_UNIQUE", 50)
	c.SubdomainFloodWindow = intVal(values, "SUBDOMAIN_FLOOD_WINDOW", 60)
	c.DNSFloodWatchlistEnabled = boolVal(values, "DNS_FLOOD_WATCHLIST_ENABLED", false)
	c.DNSFloodWatchlist = csv(values["DNS_FLOOD_WATCHLIST"])
	c.BanDuration = int64(intVal(values, "BAN_DURATION", 3600))
	c.Chain = stringVal(values, "IPTABLES_CHAIN", "ADGUARD_SHIELD")
	c.BlockedPorts = fields(stringVal(values, "BLOCKED_PORTS", "53 443 853"))
	c.FirewallBackend = stringVal(values, "FIREWALL_BACKEND", "ipset")
	c.FirewallMode = strings.ToLower(strings.TrimSpace(stringVal(values, "FIREWALL_MODE", "host")))
	c.DryRun = boolVal(values, "DRY_RUN", false)
	if strings.EqualFold(os.Getenv("DRY_RUN"), "true") || os.Getenv("DRY_RUN") == "1" {
		c.DryRun = true
	}
	c.Whitelist = csv(values["WHITELIST"])
	c.LogFile = stringVal(values, "LOG_FILE", "/var/log/adguard-shield.log")
	c.LogLevel = stringVal(values, "LOG_LEVEL", "INFO")
	c.StateDir = stringVal(values, "STATE_DIR", "/var/lib/adguard-shield")
	c.PIDFile = stringVal(values, "PID_FILE", "/var/run/adguard-shield.pid")
	c.NotifyEnabled = boolVal(values, "NOTIFY_ENABLED", false)
	c.NotifyType = stringVal(values, "NOTIFY_TYPE", "ntfy")
	c.NotifyWebhook = stringVal(values, "NOTIFY_WEBHOOK_URL", "")
	c.NTFYServerURL = stringVal(values, "NTFY_SERVER_URL", "https://ntfy.sh")
	c.NTFYTopic = stringVal(values, "NTFY_TOPIC", "")
	c.NTFYToken = stringVal(values, "NTFY_TOKEN", "")
	c.NTFYPriority = stringVal(values, "NTFY_PRIORITY", "4")
	c.ReportEnabled = boolVal(values, "REPORT_ENABLED", false)
	c.ReportInterval = stringVal(values, "REPORT_INTERVAL", "weekly")
	c.ReportTime = stringVal(values, "REPORT_TIME", "08:00")
	c.ReportEmailTo = stringVal(values, "REPORT_EMAIL_TO", "admin@example.com")
	c.ReportEmailFrom = stringVal(values, "REPORT_EMAIL_FROM", "adguard-shield@example.com")
	c.ReportFormat = strings.ToLower(stringVal(values, "REPORT_FORMAT", "html"))
	c.ReportMailCmd = stringVal(values, "REPORT_MAIL_CMD", "msmtp")
	c.ReportBusiestDayRange = intVal(values, "REPORT_BUSIEST_DAY_RANGE", 30)
	c.ExternalWhitelistEnabled = boolVal(values, "EXTERNAL_WHITELIST_ENABLED", false)
	c.ExternalWhitelistURLs = csv(values["EXTERNAL_WHITELIST_URLS"])
	c.ExternalWhitelistInterval = intVal(values, "EXTERNAL_WHITELIST_INTERVAL", 300)
	c.ExternalWhitelistCacheDir = stringVal(values, "EXTERNAL_WHITELIST_CACHE_DIR", filepath.Join(c.StateDir, "external-whitelist"))
	c.ExternalBlocklistEnabled = boolVal(values, "EXTERNAL_BLOCKLIST_ENABLED", false)
	c.ExternalBlocklistURLs = csv(values["EXTERNAL_BLOCKLIST_URLS"])
	c.ExternalBlocklistInterval = intVal(values, "EXTERNAL_BLOCKLIST_INTERVAL", 300)
	c.ExternalBlocklistCacheDir = stringVal(values, "EXTERNAL_BLOCKLIST_CACHE_DIR", filepath.Join(c.StateDir, "external-blocklist"))
	c.ExternalBlocklistDuration = int64(intVal(values, "EXTERNAL_BLOCKLIST_BAN_DURATION", 0))
	c.ExternalBlocklistAutoUnban = boolVal(values, "EXTERNAL_BLOCKLIST_AUTO_UNBAN", true)
	c.ExternalBlocklistNotify = boolVal(values, "EXTERNAL_BLOCKLIST_NOTIFY", false)
	c.ProgressiveBanEnabled = boolVal(values, "PROGRESSIVE_BAN_ENABLED", true)
	c.ProgressiveBanMultiplier = intVal(values, "PROGRESSIVE_BAN_MULTIPLIER", 2)
	c.ProgressiveBanMaxLevel = intVal(values, "PROGRESSIVE_BAN_MAX_LEVEL", 5)
	c.ProgressiveBanResetAfter = int64(intVal(values, "PROGRESSIVE_BAN_RESET_AFTER", 86400))
	c.AbuseIPDBEnabled = boolVal(values, "ABUSEIPDB_ENABLED", false)
	c.AbuseIPDBAPIKey = stringVal(values, "ABUSEIPDB_API_KEY", "")
	c.AbuseIPDBCategories = stringVal(values, "ABUSEIPDB_CATEGORIES", "4")
	c.GeoIPEnabled = boolVal(values, "GEOIP_ENABLED", false)
	c.GeoIPMode = strings.ToLower(stringVal(values, "GEOIP_MODE", "blocklist"))
	c.GeoIPCountries = upperCSV(values["GEOIP_COUNTRIES"])
	c.GeoIPNotify = boolVal(values, "GEOIP_NOTIFY", true)
	c.GeoIPSkipPrivate = boolVal(values, "GEOIP_SKIP_PRIVATE", true)
	c.GeoIPLicenseKey = stringVal(values, "GEOIP_LICENSE_KEY", "")
	c.GeoIPMMDBPath = stringVal(values, "GEOIP_MMDB_PATH", "")
	c.GeoIPCacheTTL = int64(intVal(values, "GEOIP_CACHE_TTL", 86400))
	c.GeoIPCheckInterval = intVal(values, "GEOIP_CHECK_INTERVAL", 0)
	return c, nil
}

func DefaultPath() string {
	if v := os.Getenv("ADGUARD_SHIELD_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("/opt/adguard-shield/adguard-shield.conf"); err == nil {
		return "/opt/adguard-shield/adguard-shield.conf"
	}
	return filepath.Join(".", "adguard-shield.conf")
}

func (c *Config) DBPath() string                   { return filepath.Join(c.StateDir, "adguard-shield.db") }
func (c *Config) GeoIPDir(scriptDir string) string { return filepath.Join(scriptDir, "geoip") }

func parseFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := stripInlineComment(strings.TrimSpace(line[idx+1:]))
		out[key] = unquote(val)
	}
	return out, sc.Err()
}

func stripInlineComment(s string) string {
	inSingle, inDouble := false, false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
					return strings.TrimSpace(s[:i])
				}
			}
		}
	}
	return strings.TrimSpace(s)
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func stringVal(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}
func intVal(m map[string]string, k string, def int) int {
	v, ok := m[k]
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}
func boolVal(m map[string]string, k string, def bool) bool {
	v, ok := m[k]
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}
func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
func upperCSV(s string) []string {
	parts := csv(s)
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i])
	}
	return parts
}
func fields(s string) []string {
	out := strings.Fields(s)
	if len(out) == 0 {
		return []string{"53"}
	}
	return out
}
