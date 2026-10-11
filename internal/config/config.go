package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Config struct {
	Path string
	// Warnings sammelt Konfigurationsprobleme, die beim Laden durch Standardwerte ersetzt wurden.
	Warnings []string

	AdGuardURL         string
	AdGuardUser        string
	AdGuardPass        string
	AdGuardTLSInsecure bool

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

	LogFile      string
	LogLevel     string
	LogMaxSizeMB int
	StateDir     string
	PIDFile      string

	HistoryRetentionDays int

	NotifyEnabled bool
	NotifyType    string
	NotifyWebhook string
	NTFYServerURL string
	NTFYTopic     string
	NTFYToken     string
	NTFYPriority  string
	// NotifyTLSInsecure deaktiviert die Zertifikatsprüfung nur für Benachrichtigungen.
	NotifyTLSInsecure bool

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
	// AllowInsecureListURLs erlaubt http:// für externe Block-/Whitelists.
	AllowInsecureListURLs bool

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

	WebEnabled  bool
	WebPort     int
	WebBasePath string
	WebUser     string
	WebPassword string
}

func Load(path string) (*Config, error) {
	values, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	c, r := load(values)
	c.Path = path
	c.Warnings = append(r.warnings, r.unknownKeyWarnings()...)
	return c, nil
}

// KnownKeys liefert alle Konfigurationsschlüssel, die Load auswertet.
func KnownKeys() []string {
	_, r := load(map[string]string{})
	keys := make([]string, 0, len(r.used))
	for k := range r.used {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func load(values map[string]string) (*Config, *reader) {
	r := &reader{values: values, used: map[string]bool{}}
	c := &Config{}
	c.AdGuardURL = r.str("ADGUARD_URL", "")
	c.AdGuardUser = r.str("ADGUARD_USER", "")
	c.AdGuardPass = r.str("ADGUARD_PASS", "")
	c.AdGuardTLSInsecure = r.bool("ADGUARD_TLS_INSECURE", false)
	c.RateLimitMaxRequests = r.intMin("RATE_LIMIT_MAX_REQUESTS", 30, 1)
	c.RateLimitWindow = r.intMin("RATE_LIMIT_WINDOW", 60, 1)
	c.CheckInterval = r.intMin("CHECK_INTERVAL", 10, 1)
	c.APIQueryLimit = r.intMin("API_QUERY_LIMIT", 500, 1)
	c.SubdomainFloodEnabled = r.bool("SUBDOMAIN_FLOOD_ENABLED", true)
	c.SubdomainFloodMaxUnique = r.intMin("SUBDOMAIN_FLOOD_MAX_UNIQUE", 50, 1)
	c.SubdomainFloodWindow = r.intMin("SUBDOMAIN_FLOOD_WINDOW", 60, 1)
	c.DNSFloodWatchlistEnabled = r.bool("DNS_FLOOD_WATCHLIST_ENABLED", false)
	c.DNSFloodWatchlist = csv(r.str("DNS_FLOOD_WATCHLIST", ""))
	c.BanDuration = int64(r.intMin("BAN_DURATION", 3600, 0))
	c.Chain = r.str("IPTABLES_CHAIN", "ADGUARD_SHIELD")
	c.BlockedPorts = r.ports("BLOCKED_PORTS", "53 443 853")
	c.FirewallBackend = r.str("FIREWALL_BACKEND", "ipset")
	c.FirewallMode = r.enum("FIREWALL_MODE", "host", strings.ToLower, firewallModes...)
	c.DryRun = r.bool("DRY_RUN", false)
	if strings.EqualFold(os.Getenv("DRY_RUN"), "true") || os.Getenv("DRY_RUN") == "1" {
		c.DryRun = true
	}
	c.Whitelist = csv(r.str("WHITELIST", ""))
	c.LogFile = r.str("LOG_FILE", "/var/log/adguard-shield.log")
	c.LogLevel = r.enum("LOG_LEVEL", "INFO", strings.ToUpper, "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "ERR")
	c.LogMaxSizeMB = r.intMin("LOG_MAX_SIZE_MB", 50, 0)
	c.StateDir = r.str("STATE_DIR", "/var/lib/adguard-shield")
	c.PIDFile = r.str("PID_FILE", "/var/run/adguard-shield.pid")
	c.HistoryRetentionDays = r.intMin("BAN_HISTORY_RETENTION_DAYS", 0, 0)
	c.NotifyEnabled = r.bool("NOTIFY_ENABLED", false)
	c.NotifyType = r.enum("NOTIFY_TYPE", "ntfy", strings.ToLower, "ntfy", "discord", "slack", "generic", "gotify")
	c.NotifyWebhook = r.str("NOTIFY_WEBHOOK_URL", "")
	c.NTFYServerURL = r.str("NTFY_SERVER_URL", "https://ntfy.sh")
	c.NTFYTopic = r.str("NTFY_TOPIC", "")
	c.NTFYToken = r.str("NTFY_TOKEN", "")
	c.NTFYPriority = r.str("NTFY_PRIORITY", "4")
	c.NotifyTLSInsecure = r.bool("NOTIFY_TLS_INSECURE", false)
	c.ReportEnabled = r.bool("REPORT_ENABLED", false)
	c.ReportInterval = r.enum("REPORT_INTERVAL", "weekly", strings.ToLower, "daily", "weekly", "biweekly", "monthly")
	c.ReportTime = r.str("REPORT_TIME", "08:00")
	c.ReportEmailTo = r.str("REPORT_EMAIL_TO", "admin@example.com")
	c.ReportEmailFrom = r.str("REPORT_EMAIL_FROM", "adguard-shield@example.com")
	c.ReportFormat = r.enum("REPORT_FORMAT", "html", strings.ToLower, "html", "txt")
	c.ReportMailCmd = r.str("REPORT_MAIL_CMD", "msmtp")
	c.ReportBusiestDayRange = r.intMin("REPORT_BUSIEST_DAY_RANGE", 30, 0)
	c.ExternalWhitelistEnabled = r.bool("EXTERNAL_WHITELIST_ENABLED", false)
	c.ExternalWhitelistURLs = csv(r.str("EXTERNAL_WHITELIST_URLS", ""))
	c.ExternalWhitelistInterval = r.intMin("EXTERNAL_WHITELIST_INTERVAL", 300, 1)
	c.ExternalWhitelistCacheDir = r.str("EXTERNAL_WHITELIST_CACHE_DIR", filepath.Join(c.StateDir, "external-whitelist"))
	c.ExternalBlocklistEnabled = r.bool("EXTERNAL_BLOCKLIST_ENABLED", false)
	c.ExternalBlocklistURLs = csv(r.str("EXTERNAL_BLOCKLIST_URLS", ""))
	c.ExternalBlocklistInterval = r.intMin("EXTERNAL_BLOCKLIST_INTERVAL", 300, 1)
	c.ExternalBlocklistCacheDir = r.str("EXTERNAL_BLOCKLIST_CACHE_DIR", filepath.Join(c.StateDir, "external-blocklist"))
	c.ExternalBlocklistDuration = int64(r.intMin("EXTERNAL_BLOCKLIST_BAN_DURATION", 0, 0))
	c.ExternalBlocklistAutoUnban = r.bool("EXTERNAL_BLOCKLIST_AUTO_UNBAN", true)
	c.ExternalBlocklistNotify = r.bool("EXTERNAL_BLOCKLIST_NOTIFY", false)
	c.AllowInsecureListURLs = r.bool("ALLOW_INSECURE_LIST_URLS", false)
	r.checkListURLs("EXTERNAL_WHITELIST_URLS", c.ExternalWhitelistURLs, c.AllowInsecureListURLs)
	r.checkListURLs("EXTERNAL_BLOCKLIST_URLS", c.ExternalBlocklistURLs, c.AllowInsecureListURLs)
	c.ProgressiveBanEnabled = r.bool("PROGRESSIVE_BAN_ENABLED", true)
	c.ProgressiveBanMultiplier = r.intMin("PROGRESSIVE_BAN_MULTIPLIER", 2, 1)
	c.ProgressiveBanMaxLevel = r.intMin("PROGRESSIVE_BAN_MAX_LEVEL", 5, 0)
	c.ProgressiveBanResetAfter = int64(r.intMin("PROGRESSIVE_BAN_RESET_AFTER", 86400, 0))
	c.AbuseIPDBEnabled = r.bool("ABUSEIPDB_ENABLED", false)
	c.AbuseIPDBAPIKey = r.str("ABUSEIPDB_API_KEY", "")
	c.AbuseIPDBCategories = r.str("ABUSEIPDB_CATEGORIES", "4")
	c.GeoIPEnabled = r.bool("GEOIP_ENABLED", false)
	c.GeoIPMode = r.enum("GEOIP_MODE", "blocklist", strings.ToLower, "blocklist", "allowlist")
	c.GeoIPCountries = upperCSV(r.str("GEOIP_COUNTRIES", ""))
	c.GeoIPNotify = r.bool("GEOIP_NOTIFY", true)
	c.GeoIPSkipPrivate = r.bool("GEOIP_SKIP_PRIVATE", true)
	c.GeoIPLicenseKey = r.str("GEOIP_LICENSE_KEY", "")
	c.GeoIPMMDBPath = r.str("GEOIP_MMDB_PATH", "")
	c.GeoIPCacheTTL = int64(r.intMin("GEOIP_CACHE_TTL", 86400, 0))
	c.GeoIPCheckInterval = r.intMin("GEOIP_CHECK_INTERVAL", 0, 0)
	c.WebEnabled = r.bool("WEB_ENABLED", false)
	c.WebPort = r.port("WEB_PORT", DefaultWebPort)
	c.WebBasePath = r.basePath("WEB_BASE_PATH", "/")
	c.WebUser = r.str("WEB_USER", "admin")
	c.WebPassword = r.str("WEB_PASSWORD", "")
	if strings.Contains(c.WebUser, ":") {
		r.warnf("WEB_USER=%q enthält einen Doppelpunkt; Basic Auth erlaubt das nicht, eine Anmeldung ist so nicht möglich", c.WebUser)
	}
	return c, r
}

const DefaultWebPort = 8080

// Muss zu firewall.normalizeMode passen.
var firewallModes = []string{"host", "classic", "native", "docker-host", "docker", "docker-bridge", "docker-published", "published", "hybrid", "both"}

// Schlüssel der Shell-Version, die die Go-Version bewusst ignoriert.
var deprecatedKeys = map[string]string{
	"BAN_HISTORY_FILE": "BAN_HISTORY_FILE wird ignoriert (History liegt in der SQLite-Datenbank)",
	"WEB_LISTEN":       "WEB_LISTEN wird ignoriert; die Web-Statusseite lauscht auf allen Schnittstellen, den Port legt WEB_PORT fest",
	"WEB_TLS_CERT":     "WEB_TLS_CERT wird ignoriert; die Web-Statusseite spricht nur HTTP, HTTPS übernimmt ein Reverse-Proxy",
	"WEB_TLS_KEY":      "WEB_TLS_KEY wird ignoriert; die Web-Statusseite spricht nur HTTP, HTTPS übernimmt ein Reverse-Proxy",
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

func (c *Config) DBPath() string { return filepath.Join(c.StateDir, "adguard-shield.db") }

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

type reader struct {
	values   map[string]string
	used     map[string]bool
	warnings []string
}

func (r *reader) warnf(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func (r *reader) lookup(k string) (string, bool) {
	r.used[k] = true
	v, ok := r.values[k]
	return v, ok
}

func (r *reader) str(k, def string) string {
	if v, ok := r.lookup(k); ok {
		return v
	}
	return def
}

func (r *reader) intMin(k string, def, min int) int {
	v, ok := r.lookup(k)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		r.warnf("%s=%q ist keine gültige Zahl, verwende Standardwert %d", k, v, def)
		return def
	}
	if n < min {
		r.warnf("%s=%d ist ungültig (Minimum %d), verwende Standardwert %d", k, n, min, def)
		return def
	}
	return n
}

func (r *reader) bool(k string, def bool) bool {
	v, ok := r.lookup(k)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		r.warnf("%s=%q ist kein gültiger Wahrheitswert (true/false), verwende Standardwert %v", k, v, def)
		return def
	}
}

func (r *reader) enum(k, def string, norm func(string) string, allowed ...string) string {
	v, ok := r.lookup(k)
	v = norm(strings.TrimSpace(v))
	if !ok || v == "" {
		return def
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	r.warnf("%s=%q ist ungültig (erlaubt: %s), verwende Standardwert %s", k, v, strings.Join(allowed, ", "), def)
	return def
}

func (r *reader) unknownKeyWarnings() []string {
	var unknown []string
	for k := range r.values {
		if !r.used[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	out := make([]string, 0, len(unknown))
	for _, k := range unknown {
		if msg, ok := deprecatedKeys[k]; ok {
			out = append(out, msg)
			continue
		}
		out = append(out, fmt.Sprintf("Unbekannter Konfigurationsschlüssel %s wird ignoriert (Tippfehler?)", k))
	}
	return out
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

// ports liest eine Liste aus Ports bzw. Portbereichen (a:b), getrennt durch
// Kommas oder Leerzeichen. Ungültige Einträge werden mit Warnung ignoriert; ist
// kein Eintrag gültig, gilt der Standardwert.
func (r *reader) ports(k, def string) []string {
	v, ok := r.lookup(k)
	if !ok {
		return strings.Fields(def)
	}
	parts := strings.FieldsFunc(v, func(c rune) bool { return c == ',' || unicode.IsSpace(c) })
	if len(parts) == 0 {
		return []string{"53"}
	}
	var out, invalid []string
	for _, p := range parts {
		if n, ok := normalizePort(p); ok {
			out = append(out, n)
		} else {
			invalid = append(invalid, p)
		}
	}
	if len(out) == 0 {
		r.warnf("%s=%q enthält keine gültigen Ports, verwende Standardwert %s", k, v, def)
		return strings.Fields(def)
	}
	if len(invalid) > 0 {
		r.warnf("%s: ungültige Ports %s werden ignoriert (erlaubt: 1-65535 oder Bereich a:b)", k, strings.Join(invalid, ", "))
	}
	return out
}

func normalizePort(s string) (string, bool) {
	lo, hi, isRange := strings.Cut(s, ":")
	a, ok := portNumber(lo)
	if !ok {
		return "", false
	}
	if !isRange {
		return strconv.Itoa(a), true
	}
	b, ok := portNumber(hi)
	if !ok || b < a {
		return "", false
	}
	return strconv.Itoa(a) + ":" + strconv.Itoa(b), true
}

func portNumber(s string) (int, bool) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// port liest einen einzelnen TCP-Port (1-65535).
func (r *reader) port(k string, def int) int {
	v, ok := r.lookup(k)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return def
	}
	n, ok := portNumber(v)
	if !ok {
		r.warnf("%s=%q ist kein gültiger Port (1-65535), verwende Standardwert %d", k, v, def)
		return def
	}
	return n
}

// ErrInsecureListURL meldet eine http://-Liste ohne ALLOW_INSECURE_LIST_URLS=true.
var ErrInsecureListURL = errors.New("unverschlüsseltes http:// ist nicht erlaubt, da die Liste per Man-in-the-Middle manipuliert werden kann; URL auf https:// umstellen oder bewusst ALLOW_INSECURE_LIST_URLS=true setzen")

// CheckListURL prüft eine URL für externe Block-/Whitelists: https:// ist
// immer erlaubt, http:// nur mit allowInsecure (dann ist insecure true), andere
// Schemata und URLs ohne Host nie. Fehler enthalten die URL bewusst nicht, da
// Pfad und Query Tokens enthalten können.
func CheckListURL(raw string, allowInsecure bool) (insecure bool, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false, errors.New("ungültige URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowInsecure {
			return false, ErrInsecureListURL
		}
		insecure = true
	case "":
		return false, errors.New("URL ohne Schema, erlaubt ist nur https://")
	default:
		return false, fmt.Errorf("Schema %s:// wird nicht unterstützt, erlaubt ist nur https://", strings.ToLower(u.Scheme))
	}
	if u.Hostname() == "" {
		return false, errors.New("URL ohne Host")
	}
	return insecure, nil
}

// checkListURLs warnt beim Laden vor Listen-URLs, die der Download ablehnen
// wird oder die unverschlüsselt geladen werden.
func (r *reader) checkListURLs(k string, urls []string, allowInsecure bool) {
	for i, raw := range urls {
		src := fmt.Sprintf("Quelle #%d", i+1)
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			src += fmt.Sprintf(" (%s://%s)", u.Scheme, u.Host)
		}
		insecure, err := CheckListURL(raw, allowInsecure)
		switch {
		case err != nil:
			r.warnf("%s: %s wird nicht geladen: %v", k, src, err)
		case insecure:
			r.warnf("%s: %s wird unverschlüsselt per http:// geladen (ALLOW_INSECURE_LIST_URLS=true); Inhalte können unterwegs manipuliert werden, https:// wird dringend empfohlen", k, src)
		}
	}
}

// basePath normalisiert einen URL-Pfad auf führenden und abschließenden Slash.
func (r *reader) basePath(k, def string) string {
	v, ok := r.lookup(k)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return def
	}
	if p, ok := NormalizeBasePath(v); ok {
		return p
	}
	r.warnf("%s=%q ist kein gültiger Pfad (erlaubt: Buchstaben, Ziffern, - _ . ~ /), verwende Standardwert %s", k, v, def)
	return def
}

// NormalizeBasePath liefert p mit führendem und abschließendem Slash.
func NormalizeBasePath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/", true
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~/", c)) {
			return "", false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	p = path.Clean("/" + p)
	if p != "/" {
		p += "/"
	}
	return p, true
}
