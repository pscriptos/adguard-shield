package installer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"adguard-shield/internal/report"
)

const (
	DefaultInstallDir = "/opt/adguard-shield"
	DefaultStateDir   = "/var/lib/adguard-shield"
	DefaultLogFile    = "/var/log/adguard-shield.log"
	ServiceName       = "adguard-shield.service"
	ServicePath       = "/etc/systemd/system/adguard-shield.service"
)

type Options struct {
	InstallDir   string
	ConfigSource string
	Enable       bool
	SkipDeps     bool
	KeepConfig   bool
}

type Status struct {
	InstallDir     string
	BinaryPath     string
	ConfigPath     string
	BinaryExists   bool
	ConfigExists   bool
	ServiceExists  bool
	ServiceEnabled bool
	ServiceActive  bool
	Version        string
	LegacyFindings []string
}

type LegacyError struct {
	Findings []string
}

func (e *LegacyError) Error() string {
	return "scriptbasierte AdGuard-Shield-Installation gefunden"
}

func DefaultOptions() Options {
	return Options{InstallDir: DefaultInstallDir, Enable: true}
}

func Install(opts Options) error {
	opts = normalize(opts)
	fmt.Println("AdGuard Shield Go-Installation")
	fmt.Printf("Installationspfad: %s\n", opts.InstallDir)
	fmt.Println("1/9 Pruefe Betriebssystem und root-Rechte ...")
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	fmt.Println("2/9 Pruefe auf scriptbasierte Altinstallation ...")
	if findings := DetectLegacy(opts.InstallDir); len(findings) > 0 {
		return &LegacyError{Findings: findings}
	}
	if !opts.SkipDeps {
		fmt.Println("3/9 Pruefe System-Abhaengigkeiten ...")
		if err := ensureDependencies(); err != nil {
			return err
		}
	} else {
		fmt.Println("3/9 System-Abhaengigkeiten uebersprungen (--skip-deps)")
	}
	fmt.Println("4/9 Erstelle Verzeichnisse ...")
	if err := os.MkdirAll(opts.InstallDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(DefaultStateDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opts.InstallDir, "geoip"), 0755); err != nil {
		return err
	}
	fmt.Println("5/9 Installiere Binary ...")
	if err := copySelf(filepath.Join(opts.InstallDir, "adguard-shield")); err != nil {
		return err
	}
	fmt.Println("6/9 Installiere Report-Templates ...")
	if err := report.InstallTemplates(filepath.Join(opts.InstallDir, "templates")); err != nil {
		return err
	}
	fmt.Println("7/9 Installiere oder migriere Konfiguration ...")
	if err := ensureConfig(opts); err != nil {
		return err
	}
	fmt.Println("8/9 Schreibe systemd-Service ...")
	if err := writeService(opts.InstallDir); err != nil {
		return err
	}
	fmt.Println("9/9 Aktualisiere systemd ...")
	_ = run("systemctl", "daemon-reload")
	if opts.Enable {
		fmt.Println("Aktiviere Autostart ...")
		if err := run("systemctl", "enable", ServiceName); err != nil {
			return err
		}
	}
	if askStartService() {
		fmt.Println("Starte Service neu ...")
		if err := run("systemctl", "restart", ServiceName); err != nil {
			return err
		}
	}
	fmt.Println("Installation fertig.")
	return nil
}

func Update(opts Options) error {
	opts = normalize(opts)
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	if findings := DetectLegacy(opts.InstallDir); len(findings) > 0 {
		return &LegacyError{Findings: findings}
	}
	return Install(opts)
}

func Uninstall(opts Options) error {
	opts = normalize(opts)
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	_ = run("systemctl", "stop", ServiceName)
	_ = run("systemctl", "disable", ServiceName)
	if _, err := os.Stat(filepath.Join(opts.InstallDir, "adguard-shield")); err == nil {
		_ = run(filepath.Join(opts.InstallDir, "adguard-shield"), "-config", filepath.Join(opts.InstallDir, "adguard-shield.conf"), "firewall-remove")
	}
	_ = os.Remove(ServicePath)
	_ = run("systemctl", "daemon-reload")
	if opts.KeepConfig {
		for _, p := range []string{
			filepath.Join(opts.InstallDir, "adguard-shield"),
			filepath.Join(opts.InstallDir, "adguard-shield.conf.old"),
		} {
			_ = os.Remove(p)
		}
		return nil
	}
	_ = os.RemoveAll(opts.InstallDir)
	_ = os.RemoveAll(DefaultStateDir)
	_ = os.Remove(DefaultLogFile)
	return nil
}

func GetStatus(installDir string) Status {
	if installDir == "" {
		installDir = DefaultInstallDir
	}
	bin := filepath.Join(installDir, "adguard-shield")
	conf := filepath.Join(installDir, "adguard-shield.conf")
	st := Status{
		InstallDir:     installDir,
		BinaryPath:     bin,
		ConfigPath:     conf,
		BinaryExists:   fileExists(bin),
		ConfigExists:   fileExists(conf),
		ServiceExists:  fileExists(ServicePath),
		LegacyFindings: DetectLegacy(installDir),
	}
	if st.BinaryExists {
		if out, err := exec.Command(bin, "version").Output(); err == nil {
			st.Version = strings.TrimSpace(string(out))
		}
	}
	st.ServiceEnabled = commandOK("systemctl", "is-enabled", "adguard-shield")
	st.ServiceActive = commandOK("systemctl", "is-active", "adguard-shield")
	return st
}

func DetectLegacy(installDir string) []string {
	if installDir == "" {
		installDir = DefaultInstallDir
	}
	var findings []string
	for _, p := range []string{
		"adguard-shield.sh",
		"iptables-helper.sh",
		"db.sh",
		"external-blocklist-worker.sh",
		"external-whitelist-worker.sh",
		"geoip-worker.sh",
		"offense-cleanup-worker.sh",
		"report-generator.sh",
		"unban-expired.sh",
		"adguard-shield-watchdog.sh",
	} {
		full := filepath.Join(installDir, p)
		if fileExists(full) {
			findings = append(findings, full)
		}
	}
	for _, p := range []string{
		"/etc/systemd/system/adguard-shield-watchdog.service",
		"/etc/systemd/system/adguard-shield-watchdog.timer",
	} {
		if fileExists(p) {
			findings = append(findings, p)
		}
	}
	if b, err := os.ReadFile(ServicePath); err == nil {
		s := string(b)
		if strings.Contains(s, ".sh") || strings.Contains(s, "/bin/bash") || strings.Contains(s, "adguard-shield-watchdog") {
			findings = append(findings, ServicePath+" verweist auf Shell/Watchdog")
		}
	}
	sort.Strings(findings)
	return findings
}

func FormatLegacyMessage(err *LegacyError, installDir string) string {
	if installDir == "" {
		installDir = DefaultInstallDir
	}
	var b strings.Builder
	b.WriteString("Die scriptbasierte Installation ist noch vorhanden und muss zuerst deinstalliert werden.\n\n")
	b.WriteString("Gefunden:\n")
	for _, f := range err.Findings {
		b.WriteString("  - ")
		b.WriteString(f)
		b.WriteByte('\n')
	}
	b.WriteString("\nKonfiguration uebernehmen:\n")
	b.WriteString("  1. Backup behalten: ")
	b.WriteString(filepath.Join(installDir, "adguard-shield.conf"))
	b.WriteByte('\n')
	b.WriteString("  2. Alte Shell-Version mit deren uninstall.sh entfernen und die Konfiguration behalten.\n")
	b.WriteString("  3. Danach dieses Binary erneut ausfuehren: adguard-shield install\n")
	return b.String()
}

func PrintStatus(st Status) string {
	var b strings.Builder
	b.WriteString("AdGuard Shield Installationsstatus\n")
	b.WriteString(fmt.Sprintf("Installationspfad: %s\n", st.InstallDir))
	b.WriteString(fmt.Sprintf("Binary: %s\n", yesNo(st.BinaryExists)))
	if st.Version != "" {
		b.WriteString(fmt.Sprintf("Version: %s\n", st.Version))
	}
	b.WriteString(fmt.Sprintf("Konfiguration: %s\n", yesNo(st.ConfigExists)))
	b.WriteString(fmt.Sprintf("systemd Service: %s\n", yesNo(st.ServiceExists)))
	b.WriteString(fmt.Sprintf("Autostart: %s\n", yesNo(st.ServiceEnabled)))
	b.WriteString(fmt.Sprintf("Service aktiv: %s\n", yesNo(st.ServiceActive)))
	if len(st.LegacyFindings) > 0 {
		b.WriteString("\nScriptbasierte Altinstallation/Altartefakte gefunden:\n")
		for _, f := range st.LegacyFindings {
			b.WriteString("  - ")
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func normalize(opts Options) Options {
	if opts.InstallDir == "" {
		opts.InstallDir = DefaultInstallDir
	}
	return opts
}

func askStartService() bool {
	fmt.Print("AdGuard Shield jetzt (neu) starten? [j/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		fmt.Println("Keine Eingabe gelesen, Service wird nicht gestartet.")
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "j", "ja", "y", "yes":
		return true
	default:
		fmt.Println("Service wird nicht gestartet.")
		return false
	}
}

func requireLinuxRoot() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Installation ist nur auf Linux-Servern unterstuetzt")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("Installation muss als root ausgefuehrt werden")
	}
	return nil
}

func ensureDependencies() error {
	missing := missingCommands("iptables", "ip6tables", "ipset", "systemctl")
	if len(missing) == 0 {
		fmt.Println("  Alle benoetigten Befehle sind vorhanden.")
		return nil
	}
	fmt.Printf("  Fehlende Befehle: %s\n", strings.Join(missing, ", "))
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("fehlende Abhaengigkeiten (%s), apt-get nicht gefunden", strings.Join(missing, ", "))
	}
	pkgs := map[string]bool{"iptables": false, "ipset": false, "systemd": false, "ca-certificates": false}
	for _, m := range missing {
		switch m {
		case "iptables", "ip6tables":
			pkgs["iptables"] = true
		case "ipset":
			pkgs["ipset"] = true
		case "systemctl":
			pkgs["systemd"] = true
		}
	}
	var install []string
	for p, needed := range pkgs {
		if needed || p == "ca-certificates" {
			install = append(install, p)
		}
	}
	sort.Strings(install)
	fmt.Printf("  Installiere Pakete via apt-get: %s\n", strings.Join(install, ", "))
	fmt.Println("  apt-get update ...")
	if err := runStreaming("apt-get", "update"); err != nil {
		return err
	}
	fmt.Println("  apt-get install ...")
	args := append([]string{"install", "-y", "-qq"}, install...)
	return runStreaming("apt-get", args...)
}

func missingCommands(names ...string) []string {
	var missing []string
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if sameFile(src, dst) {
		return os.Chmod(dst, 0755)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func sameFile(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

func ensureConfig(opts Options) error {
	target := filepath.Join(opts.InstallDir, "adguard-shield.conf")
	defaults := []byte(defaultConfig)
	if opts.ConfigSource != "" {
		b, err := os.ReadFile(opts.ConfigSource)
		if err != nil {
			return err
		}
		defaults = b
	}
	if !fileExists(target) {
		if err := os.WriteFile(target, defaults, 0600); err != nil {
			return err
		}
		return nil
	}
	current, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	merged, changed := mergeConfig(current, []byte(defaultConfig))
	if !changed {
		return os.Chmod(target, 0600)
	}
	if err := os.WriteFile(target+".old", current, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(target, merged, 0600); err != nil {
		return err
	}
	return nil
}

func mergeConfig(current, defaults []byte) ([]byte, bool) {
	existing := configKeys(current)
	var add [][]byte
	for _, block := range configBlocks(defaults) {
		key := blockKey(block)
		if key == "" || existing[key] {
			continue
		}
		add = append(add, block)
	}
	if len(add) == 0 {
		return current, false
	}
	out := bytes.TrimRight(current, "\r\n")
	out = append(out, '\n', '\n')
	out = append(out, []byte("# Neue Parameter aus der Go-Version\n")...)
	for _, block := range add {
		out = append(out, bytes.Trim(block, "\r\n")...)
		out = append(out, '\n')
	}
	return out, true
}

func configKeys(data []byte) map[string]bool {
	keys := map[string]bool{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if i := bytes.IndexByte(line, '='); i > 0 {
			keys[string(bytes.TrimSpace(line[:i]))] = true
		}
	}
	return keys
}

func configBlocks(data []byte) [][]byte {
	lines := bytes.Split(data, []byte{'\n'})
	var blocks [][]byte
	var comments [][]byte
	for _, line := range lines {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 || trim[0] == '#' {
			comments = append(comments, append([]byte(nil), line...))
			continue
		}
		block := bytes.Join(append(comments, line), []byte{'\n'})
		blocks = append(blocks, block)
		comments = nil
	}
	return blocks
}

func blockKey(block []byte) string {
	for _, line := range bytes.Split(block, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if i := bytes.IndexByte(line, '='); i > 0 {
			return string(bytes.TrimSpace(line[:i]))
		}
	}
	return ""
}

func writeService(installDir string) error {
	service := fmt.Sprintf(`[Unit]
Description=AdGuard Shield - Go DNS Rate-Limit Monitor
After=network.target AdGuardHome.service
Wants=AdGuardHome.service
StartLimitBurst=5
StartLimitIntervalSec=300

[Service]
Type=simple
ExecStart=%s/adguard-shield -config %s/adguard-shield.conf run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
ProtectSystem=full
ReadWritePaths=/var/log /var/lib/adguard-shield /var/run %s/geoip
ProtectHome=true
NoNewPrivileges=false
PrivateTmp=true
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID CAP_CHOWN
StandardOutput=journal
StandardError=journal
SyslogIdentifier=adguard-shield

[Install]
WantedBy=multi-user.target
`, installDir, installDir, installDir)
	return os.WriteFile(ServicePath, []byte(service), 0644)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runStreaming(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func commandOK(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(ok bool) string {
	if ok {
		return "ja"
	}
	return "nein"
}

func IsLegacyError(err error) (*LegacyError, bool) {
	var le *LegacyError
	if errors.As(err, &le) {
		return le, true
	}
	return nil, false
}

const defaultConfig = `# AdGuard Shield Konfiguration

ADGUARD_URL="https://dns1.domain.com"
ADGUARD_USER="admin"
ADGUARD_PASS='changeme'

RATE_LIMIT_MAX_REQUESTS=30
RATE_LIMIT_WINDOW=60
CHECK_INTERVAL=10
API_QUERY_LIMIT=500

SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=50
SUBDOMAIN_FLOOD_WINDOW=60

DNS_FLOOD_WATCHLIST_ENABLED=false
DNS_FLOOD_WATCHLIST=""

BAN_DURATION=3600
IPTABLES_CHAIN="ADGUARD_SHIELD"
BLOCKED_PORTS="53 443 853"
FIREWALL_BACKEND="ipset"
FIREWALL_MODE="host"
DRY_RUN=false

WHITELIST="127.0.0.1,::1"

LOG_FILE="/var/log/adguard-shield.log"
LOG_LEVEL="INFO"
STATE_DIR="/var/lib/adguard-shield"
PID_FILE="/var/run/adguard-shield.pid"

NOTIFY_ENABLED=false
NOTIFY_TYPE="ntfy"
NOTIFY_WEBHOOK_URL=""
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC=""
NTFY_TOKEN=""
NTFY_PRIORITY="4"

REPORT_ENABLED=false
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
REPORT_BUSIEST_DAY_RANGE=30

EXTERNAL_WHITELIST_ENABLED=false
EXTERNAL_WHITELIST_URLS=""
EXTERNAL_WHITELIST_INTERVAL=300
EXTERNAL_WHITELIST_CACHE_DIR="/var/lib/adguard-shield/external-whitelist"

EXTERNAL_BLOCKLIST_ENABLED=false
EXTERNAL_BLOCKLIST_URLS=""
EXTERNAL_BLOCKLIST_INTERVAL=300
EXTERNAL_BLOCKLIST_BAN_DURATION=0
EXTERNAL_BLOCKLIST_AUTO_UNBAN=true
EXTERNAL_BLOCKLIST_NOTIFY=false
EXTERNAL_BLOCKLIST_CACHE_DIR="/var/lib/adguard-shield/external-blocklist"

PROGRESSIVE_BAN_ENABLED=true
PROGRESSIVE_BAN_MULTIPLIER=2
PROGRESSIVE_BAN_MAX_LEVEL=5
PROGRESSIVE_BAN_RESET_AFTER=86400

ABUSEIPDB_ENABLED=false
ABUSEIPDB_API_KEY=""
ABUSEIPDB_CATEGORIES="4"

GEOIP_ENABLED=false
GEOIP_MODE="blocklist"
GEOIP_COUNTRIES=""
GEOIP_CHECK_INTERVAL=0
GEOIP_NOTIFY=true
GEOIP_SKIP_PRIVATE=true
GEOIP_LICENSE_KEY=""
GEOIP_MMDB_PATH=""
GEOIP_CACHE_TTL=86400
`
