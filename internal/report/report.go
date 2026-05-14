package report

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
)

//go:embed templates/report.html templates/report.txt
var embeddedTemplates embed.FS

type Store interface {
	ReportStats(since, until, busiestSince int64, limit int) (db.ReportStats, error)
}

const cronPath = "/etc/cron.d/adguard-shield-report"

func Status(c *config.Config) string {
	cron := "nicht installiert"
	if _, err := os.Stat(cronPath); err == nil {
		cron = "installiert (" + cronPath + ")"
	}
	mailer := "nicht gefunden"
	if parts := strings.Fields(c.ReportMailCmd); len(parts) > 0 {
		if p, err := exec.LookPath(parts[0]); err == nil {
			mailer = "gefunden (" + p + ")"
		}
	}
	return fmt.Sprintf(`AdGuard Shield - Report Status

Report aktiviert:    %v
Intervall:           %s
Uhrzeit:             %s
Format:              %s
Empfaenger:          %s
Absender:            %s
Mail-Befehl:         %s
Mail-Befehl Status:  %s
Aktivster Tag:       letzte %d Tage
Cron:                %s
`, c.ReportEnabled, c.ReportInterval, c.ReportTime, c.ReportFormat, empty(c.ReportEmailTo, "nicht konfiguriert"), c.ReportEmailFrom, c.ReportMailCmd, mailer, c.ReportBusiestDayRange, cron)
}

func InstallTemplates(dir string) error {
	if dir == "" {
		return fmt.Errorf("Template-Zielverzeichnis ist leer")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, name := range []string{"report.html", "report.txt"} {
		data, err := embeddedTemplates.ReadFile("templates/" + name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func Generate(c *config.Config, st Store, format string) (string, error) {
	format = normalizeFormat(format, c.ReportFormat)
	since, until, period := reportWindow(c.ReportInterval, time.Now())
	busiestSince := busiestWindowStart(c, since)
	stats, err := st.ReportStats(since, until, busiestSince, 20)
	if err != nil {
		return "", err
	}
	stats.AbuseIPDBReports = countAbuseReports(c.LogFile, since, until)

	tpl, err := loadTemplate(c, format)
	if err != nil {
		return "", err
	}
	values, err := templateValues(c, st, stats, period, format)
	if err != nil {
		return "", err
	}
	for key, value := range values {
		tpl = strings.ReplaceAll(tpl, "{{"+key+"}}", value)
	}
	return tpl, nil
}

func Send(ctx context.Context, c *config.Config, st Store) error {
	format := normalizeFormat(c.ReportFormat, "html")
	body, err := Generate(c, st, format)
	if err != nil {
		return err
	}
	_, _, period := reportWindow(c.ReportInterval, time.Now())
	return sendMail(ctx, c, "AdGuard Shield "+period+" - "+hostname(), body, format, "AdGuard Shield Report Generator")
}

func SendTest(ctx context.Context, c *config.Config) error {
	format := normalizeFormat(c.ReportFormat, "html")
	body := testBody(c, format)
	return sendMail(ctx, c, "AdGuard Shield Test-Mail - "+hostname(), body, format, "AdGuard Shield Report Generator (Test)")
}

func InstallCron(binary, configPath string, c *config.Config) error {
	if !c.ReportEnabled {
		return fmt.Errorf("Report ist deaktiviert (REPORT_ENABLED=false)")
	}
	minute, hour, err := parseReportTime(c.ReportTime)
	if err != nil {
		return err
	}
	schedule := cronSchedule(c.ReportInterval, minute, hour)
	if binary == "" {
		binary = "/opt/adguard-shield/adguard-shield"
	}
	if configPath == "" {
		configPath = "/opt/adguard-shield/adguard-shield.conf"
	}
	command := shellQuote(binary) + " -config " + shellQuote(configPath) + " report-send"
	if strings.EqualFold(c.ReportInterval, "biweekly") {
		command = "[ $(( $(date +\\%V) \\% 2 )) -eq 1 ] && " + command
	}
	line := fmt.Sprintf(`# AdGuard Shield - Automatischer Report
# Intervall: %s
# Uhrzeit: %s
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

%s root %s >> %s 2>&1
`, c.ReportInterval, c.ReportTime, schedule, command, shellQuote(c.LogFile))
	return os.WriteFile(cronPath, []byte(line), 0644)
}

func RemoveCron() error {
	if err := os.Remove(cronPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sendMail(ctx context.Context, c *config.Config, subject, body, format, xMailer string) error {
	if strings.TrimSpace(c.ReportEmailTo) == "" {
		return fmt.Errorf("REPORT_EMAIL_TO ist leer")
	}
	parts := strings.Fields(c.ReportMailCmd)
	if len(parts) == 0 {
		return fmt.Errorf("REPORT_MAIL_CMD ist leer")
	}
	if _, err := exec.LookPath(parts[0]); err != nil {
		return fmt.Errorf("Mail-Befehl nicht gefunden: %s", parts[0])
	}
	contentType := "text/plain; charset=UTF-8"
	if strings.EqualFold(format, "html") {
		contentType = "text/html; charset=UTF-8"
	}
	msg := strings.Join([]string{
		"From: " + c.ReportEmailFrom,
		"To: " + c.ReportEmailTo,
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"MIME-Version: 1.0",
		"Content-Type: " + contentType,
		"Content-Transfer-Encoding: 8bit",
		"X-Mailer: " + xMailer,
		"",
		body,
	}, "\n")
	args := append(parts[1:], "-t")
	cmd := exec.CommandContext(ctx, parts[0], args...)
	cmd.Stdin = strings.NewReader(msg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func templateValues(c *config.Config, st Store, stats db.ReportStats, period, format string) (map[string]string, error) {
	updateHTML, updateText := checkForUpdate()
	busiestDay := "-"
	if stats.BusiestDay != "" {
		if t, err := time.ParseInLocation("2006-01-02", stats.BusiestDay, time.Local); err == nil {
			busiestDay = t.Format("02.01.2006") + " (" + strconv.Itoa(stats.BusiestDayCount) + ")"
		} else {
			busiestDay = stats.BusiestDay + " (" + strconv.Itoa(stats.BusiestDayCount) + ")"
		}
	}
	busiestLabel := "Aktivster Tag"
	if c.ReportBusiestDayRange > 0 {
		busiestLabel = fmt.Sprintf("Aktivster Tag (%d Tage)", c.ReportBusiestDayRange)
	}

	values := map[string]string{
		"REPORT_PERIOD":           period,
		"REPORT_DATE":             time.Now().Format("02.01.2006 15:04:05"),
		"HOSTNAME":                hostname(),
		"VERSION":                 appinfo.Version,
		"TOTAL_BANS":              strconv.Itoa(stats.TotalBans),
		"TOTAL_UNBANS":            strconv.Itoa(stats.TotalUnbans),
		"UNIQUE_IPS":              strconv.Itoa(stats.UniqueIPs),
		"PERMANENT_BANS":          strconv.Itoa(stats.PermanentBans),
		"ACTIVE_BANS":             strconv.Itoa(stats.ActiveBans),
		"ABUSEIPDB_REPORTS":       strconv.Itoa(stats.AbuseIPDBReports),
		"RATELIMIT_BANS":          strconv.Itoa(stats.RateLimitBans),
		"SUBDOMAIN_FLOOD_BANS":    strconv.Itoa(stats.SubdomainFloodBans),
		"EXTERNAL_BLOCKLIST_BANS": strconv.Itoa(stats.ExternalBlocklistBans),
		"BUSIEST_DAY":             busiestDay,
		"BUSIEST_DAY_LABEL":       busiestLabel,
		"TOP10_IPS_TABLE":         topCountsHTML(stats.TopClients, "IP-Adresse"),
		"TOP10_DOMAINS_TABLE":     topCountsHTML(stats.TopDomains, "Domain"),
		"PROTOCOL_TABLE":          protocolHTML(stats.Protocols),
		"RECENT_BANS_TABLE":       recentBansHTML(stats.RecentBans),
		"TOP10_IPS_TEXT":          topCountsText(stats.TopClients, "IP-Adresse"),
		"TOP10_DOMAINS_TEXT":      topCountsText(stats.TopDomains, "Domain"),
		"PROTOCOL_TEXT":           protocolText(stats.Protocols),
		"RECENT_BANS_TEXT":        recentBansText(stats.RecentBans),
		"UPDATE_NOTICE":           updateHTML,
		"UPDATE_NOTICE_TXT":       updateText,
		"PERIOD_OVERVIEW_TABLE":   "",
		"PERIOD_OVERVIEW_TEXT":    "",
	}
	if strings.EqualFold(format, "html") {
		values["PERIOD_OVERVIEW_TABLE"] = periodOverviewHTML(st)
	} else {
		values["PERIOD_OVERVIEW_TEXT"] = periodOverviewText(st)
	}
	return values, nil
}

func topCountsHTML(rows []db.ReportCount, nameHeader string) string {
	if len(rows) == 0 {
		return `<div class="no-data">Keine Daten im Berichtszeitraum</div>`
	}
	maxCount := rows[0].Count
	var b strings.Builder
	b.WriteString("<table><tr><th>#</th><th>" + html.EscapeString(nameHeader) + "</th><th>Sperren</th></tr>")
	for i, r := range rows {
		width := 100
		if maxCount > 0 {
			width = r.Count * 100 / maxCount
		}
		class := ""
		if i < 3 {
			class = " top3"
		}
		cellClass := ""
		if strings.Contains(strings.ToLower(nameHeader), "ip") {
			cellClass = ` class="ip-cell"`
		}
		fmt.Fprintf(&b, `<tr><td><span class="rank%s">%d</span></td><td%s>%s</td><td><div class="bar-container"><div class="bar" style="width:%d%%"></div><span class="bar-value">%d</span></div></td></tr>`, class, i+1, cellClass, html.EscapeString(r.Name), width, r.Count)
	}
	b.WriteString("</table>")
	return b.String()
}

func protocolHTML(rows []db.ReportCount) string {
	if len(rows) == 0 {
		return `<div class="no-data">Keine Daten im Berichtszeitraum</div>`
	}
	var b strings.Builder
	b.WriteString("<table><tr><th>Protokoll</th><th>Anzahl Sperren</th></tr>")
	for _, r := range rows {
		class := protocolClass(r.Name)
		fmt.Fprintf(&b, `<tr><td><span class="protocol-badge %s">%s</span></td><td>%d</td></tr>`, class, html.EscapeString(r.Name), r.Count)
	}
	b.WriteString("</table>")
	return b.String()
}

func recentBansHTML(rows []db.ReportEvent) string {
	if len(rows) == 0 {
		return `<div class="no-data">Keine Sperren im Berichtszeitraum</div>`
	}
	var b strings.Builder
	b.WriteString("<table><tr><th>Zeitpunkt</th><th>IP</th><th>Domain</th><th>Grund</th></tr>")
	for _, e := range rows {
		reason := fallback(e.Reason, "rate-limit")
		domain := fallbackDash(e.Domain)
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="ip-cell">%s</td><td>%s</td><td><span class="reason-badge %s">%s</span></td></tr>`, html.EscapeString(shortTime(e.Timestamp)), html.EscapeString(e.IP), html.EscapeString(domain), reasonClass(reason), html.EscapeString(reason))
	}
	b.WriteString("</table>")
	return b.String()
}

func periodOverviewHTML(st Store) string {
	rows := periodOverviewRows(st)
	var b strings.Builder
	b.WriteString("<table><tr><th>Zeitraum</th><th>Sperren</th><th>Entsperrt</th><th>Unique IPs</th><th>Dauerhaft gebannt</th></tr>")
	for _, r := range rows {
		class := ""
		if r.Label == "Heute" {
			class = ` class="period-today"`
		} else if r.Label == "Gestern" {
			class = ` class="period-gestern"`
		}
		fmt.Fprintf(&b, `<tr%s><td><strong>%s</strong></td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>`, class, html.EscapeString(r.Label), r.TotalBans, r.TotalUnbans, r.UniqueIPs, r.PermanentBans)
	}
	b.WriteString("</table>")
	return b.String()
}

func topCountsText(rows []db.ReportCount, nameHeader string) string {
	if len(rows) == 0 {
		return "  Keine Daten im Berichtszeitraum"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  %-4s %-42s %s\n", "#", nameHeader, "Sperren")
	fmt.Fprintf(&b, "  %-4s %-42s %s\n", "--", strings.Repeat("-", 42), "-------")
	for i, r := range rows {
		fmt.Fprintf(&b, "  %-4s %-42s %d\n", strconv.Itoa(i+1)+".", r.Name, r.Count)
	}
	return strings.TrimRight(b.String(), "\n")
}

func protocolText(rows []db.ReportCount) string {
	if len(rows) == 0 {
		return "  Keine Daten im Berichtszeitraum"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  %-20s %s\n", "Protokoll", "Anzahl")
	fmt.Fprintf(&b, "  %-20s %s\n", strings.Repeat("-", 20), "------")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-20s %d\n", r.Name, r.Count)
	}
	return strings.TrimRight(b.String(), "\n")
}

func recentBansText(rows []db.ReportEvent) string {
	if len(rows) == 0 {
		return "  Keine Sperren im Berichtszeitraum"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  %-17s %-42s %-30s %s\n", "Zeitpunkt", "IP", "Domain", "Grund")
	fmt.Fprintf(&b, "  %-17s %-42s %-30s %s\n", strings.Repeat("-", 17), strings.Repeat("-", 42), strings.Repeat("-", 30), "----------")
	for _, e := range rows {
		fmt.Fprintf(&b, "  %-17s %-42s %-30s %s\n", shortTime(e.Timestamp), e.IP, fallbackDash(e.Domain), fallback(e.Reason, "rate-limit"))
	}
	return strings.TrimRight(b.String(), "\n")
}

func periodOverviewText(st Store) string {
	rows := periodOverviewRows(st)
	var b strings.Builder
	fmt.Fprintf(&b, "  %-15s %-9s %-12s %-14s %-11s\n", "Zeitraum", "Sperren", "Entsperrt", "Unique IPs", "Dauerhaft")
	fmt.Fprintf(&b, "  %-15s %-9s %-12s %-14s %-11s\n", strings.Repeat("-", 15), strings.Repeat("-", 9), strings.Repeat("-", 12), strings.Repeat("-", 14), strings.Repeat("-", 11))
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-15s %-9d %-12d %-14d %-11d\n", r.Label, r.TotalBans, r.TotalUnbans, r.UniqueIPs, r.PermanentBans)
	}
	return strings.TrimRight(b.String(), "\n")
}

type overviewRow struct {
	Label string
	db.ReportStats
}

func periodOverviewRows(st Store) []overviewRow {
	now := time.Now()
	today := midnight(now)
	defs := []struct {
		label string
		since time.Time
		until time.Time
	}{}
	if now.Hour() >= 20 {
		defs = append(defs, struct {
			label string
			since time.Time
			until time.Time
		}{"Heute", today, now})
	}
	defs = append(defs,
		struct {
			label string
			since time.Time
			until time.Time
		}{"Gestern", today.AddDate(0, 0, -1), today.Add(-time.Second)},
		struct {
			label string
			since time.Time
			until time.Time
		}{"Letzte 7 Tage", today.AddDate(0, 0, -7), now},
		struct {
			label string
			since time.Time
			until time.Time
		}{"Letzte 14 Tage", today.AddDate(0, 0, -14), now},
		struct {
			label string
			since time.Time
			until time.Time
		}{"Letzte 30 Tage", today.AddDate(0, 0, -30), now},
	)
	rows := make([]overviewRow, 0, len(defs))
	for _, d := range defs {
		stats, err := st.ReportStats(d.since.Unix(), d.until.Unix(), d.since.Unix(), 0)
		if err != nil {
			stats = db.ReportStats{}
		}
		rows = append(rows, overviewRow{Label: d.label, ReportStats: stats})
	}
	return rows
}

func loadTemplate(c *config.Config, format string) (string, error) {
	name := "report." + format
	for _, dir := range templateDirs(c) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			return string(data), nil
		}
	}
	data, err := fs.ReadFile(embeddedTemplates, "templates/"+name)
	if err != nil {
		return "", fmt.Errorf("Report-Template nicht gefunden: %s", name)
	}
	return string(data), nil
}

func templateDirs(c *config.Config) []string {
	var dirs []string
	if v := strings.TrimSpace(os.Getenv("ADGUARD_SHIELD_TEMPLATE_DIR")); v != "" {
		dirs = append(dirs, v)
	}
	if c.Path != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(c.Path), "templates"))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(wd, "templates"))
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "templates"))
	}
	seen := map[string]bool{}
	out := dirs[:0]
	for _, d := range dirs {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func parseReportTime(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("REPORT_TIME muss HH:MM sein")
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return "", "", fmt.Errorf("REPORT_TIME hat ungueltige Stunde")
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return "", "", fmt.Errorf("REPORT_TIME hat ungueltige Minute")
	}
	return strconv.Itoa(minute), strconv.Itoa(hour), nil
}

func cronSchedule(interval, minute, hour string) string {
	switch strings.ToLower(interval) {
	case "daily":
		return fmt.Sprintf("%s %s * * *", minute, hour)
	case "biweekly", "weekly":
		return fmt.Sprintf("%s %s * * 1", minute, hour)
	case "monthly":
		return fmt.Sprintf("%s %s 1 * *", minute, hour)
	default:
		return fmt.Sprintf("%s %s * * 1", minute, hour)
	}
}

func reportWindow(interval string, now time.Time) (int64, int64, string) {
	today := midnight(now)
	days, label := 7, "Bericht"
	switch strings.ToLower(interval) {
	case "daily":
		days, label = 1, "Tagesbericht"
	case "weekly":
		days, label = 7, "Wochenbericht"
	case "biweekly":
		days, label = 14, "Zweiwochenbericht"
	case "monthly":
		days, label = 30, "Monatsbericht"
	}
	start := today.AddDate(0, 0, -days)
	end := today.Add(-time.Second)
	if strings.EqualFold(interval, "daily") {
		return start.Unix(), end.Unix(), label + ": " + start.Format("02.01.2006")
	}
	return start.Unix(), end.Unix(), label + ": " + start.Format("02.01.2006") + " - " + end.Format("02.01.2006")
}

func busiestWindowStart(c *config.Config, fallbackSince int64) int64 {
	if c.ReportBusiestDayRange <= 0 {
		return fallbackSince
	}
	return midnight(time.Now()).AddDate(0, 0, -c.ReportBusiestDayRange).Unix()
}

func midnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func countAbuseReports(path string, since, until int64) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "AbuseIPDB:") || !strings.Contains(line, "erfolgreich gemeldet") || len(line) < 21 {
			continue
		}
		ts := strings.TrimPrefix(line[:20], "[")
		t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.Local)
		if err == nil && t.Unix() >= since && t.Unix() <= until {
			count++
		}
	}
	return count
}

func checkForUpdate() (string, string) {
	if appinfo.Version == "" || appinfo.Version == "unknown" || strings.EqualFold(os.Getenv("ADGUARD_SHIELD_SKIP_UPDATE_CHECK"), "true") {
		return "", ""
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://git.techniverse.net/api/v1/repos/scriptos/adguard-shield/releases?limit=1&page=1")
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", ""
	}
	var releases []struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil || len(releases) == 0 {
		return "", ""
	}
	latest := releases[0].TagName
	if !versionGreater(latest, appinfo.Version) {
		return "", ""
	}
	htmlNotice := `<div class="update-notice">Update verfuegbar: <strong>` + html.EscapeString(latest) + `</strong> · <a href="https://git.techniverse.net/scriptos/adguard-shield/releases">Jetzt aktualisieren</a></div>`
	textNotice := "  Neue Version verfuegbar: " + latest + "\n  Update: https://git.techniverse.net/scriptos/adguard-shield/releases\n"
	return htmlNotice, textNotice
}

func versionGreater(a, b string) bool {
	ap := versionParts(a)
	bp := versionParts(b)
	max := len(ap)
	if len(bp) > max {
		max = len(bp)
	}
	for i := 0; i < max; i++ {
		ai, bi := 0, 0
		if i < len(ap) {
			ai = ap[i]
		}
		if i < len(bp) {
			bi = bp[i]
		}
		if ai != bi {
			return ai > bi
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func testBody(c *config.Config, format string) string {
	now := time.Now().Format("02.01.2006 15:04:05")
	host := hostname()
	if strings.EqualFold(format, "html") {
		return `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"></head><body style="font-family:sans-serif;background:#f0f2f5;padding:30px;"><div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);"><div style="background:#0f3460;color:#fff;padding:30px;text-align:center;"><h1 style="margin:0;">AdGuard Shield Test-Mail</h1><p style="margin:6px 0 0;color:#ccd6f6;">E-Mail-Versand funktioniert</p></div><div style="padding:30px;"><table style="width:100%;border-collapse:collapse;"><tr><td>Hostname</td><td><strong>` + html.EscapeString(host) + `</strong></td></tr><tr><td>Zeitpunkt</td><td><strong>` + html.EscapeString(now) + `</strong></td></tr><tr><td>Empfaenger</td><td><strong>` + html.EscapeString(c.ReportEmailTo) + `</strong></td></tr><tr><td>Absender</td><td><strong>` + html.EscapeString(c.ReportEmailFrom) + `</strong></td></tr><tr><td>Mail-Befehl</td><td><strong>` + html.EscapeString(c.ReportMailCmd) + `</strong></td></tr><tr><td>Format</td><td><strong>` + html.EscapeString(format) + `</strong></td></tr></table></div></div></body></html>`
	}
	return fmt.Sprintf(`AdGuard Shield - Test-Mail

E-Mail-Versand funktioniert.

Hostname:     %s
Zeitpunkt:    %s
Empfaenger:   %s
Absender:     %s
Mail-Befehl:  %s
Format:       %s
`, host, now, c.ReportEmailTo, c.ReportEmailFrom, c.ReportMailCmd, format)
}

func normalizeFormat(value, fallback string) string {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(fallback))
	}
	if format != "txt" {
		format = "html"
	}
	return format
}

func shortTime(value string) string {
	if len(value) >= 16 {
		return value[5:16]
	}
	return value
}

func protocolClass(proto string) string {
	s := strings.ToLower(proto)
	switch {
	case strings.HasPrefix(s, "dns"):
		return "dns"
	case strings.HasPrefix(s, "doh"):
		return "doh"
	case strings.HasPrefix(s, "dot"):
		return "dot"
	case strings.HasPrefix(s, "doq"):
		return "doq"
	default:
		return ""
	}
}

func reasonClass(reason string) string {
	s := strings.ToLower(reason)
	switch {
	case strings.Contains(s, "subdomain"):
		return "subdomain-flood"
	case strings.Contains(s, "external"):
		return "external"
	default:
		return "rate-limit"
	}
}

func fallback(value, def string) string {
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}

func fallbackDash(value string) string {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) == "-" {
		return "-"
	}
	return value
}

func empty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return filepath.Base(os.Args[0])
	}
	return name
}
