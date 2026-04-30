package report

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
)

type Store interface {
	ReportStats(since, until int64, limit int) (db.ReportStats, error)
}

const cronPath = "/etc/cron.d/adguard-shield-report"

func Status(c *config.Config) string {
	cron := "nicht installiert"
	if _, err := os.Stat(cronPath); err == nil {
		cron = "installiert (" + cronPath + ")"
	}
	return fmt.Sprintf(`E-Mail Report
Aktiv: %v
Intervall: %s
Zeit: %s
Empfaenger: %s
Absender: %s
Format: %s
Mail-Befehl: %s
Cron: %s
`, c.ReportEnabled, c.ReportInterval, c.ReportTime, c.ReportEmailTo, c.ReportEmailFrom, c.ReportFormat, c.ReportMailCmd, cron)
}

func Generate(c *config.Config, st Store, format string) (string, error) {
	if format == "" {
		format = c.ReportFormat
	}
	since, until := window(c.ReportInterval)
	stats, err := st.ReportStats(since, until, 20)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(format, "html") {
		return renderHTML(c, stats), nil
	}
	return renderText(c, stats), nil
}

func Send(ctx context.Context, c *config.Config, st Store) error {
	body, err := Generate(c, st, c.ReportFormat)
	if err != nil {
		return err
	}
	return sendMail(ctx, c, "AdGuard Shield Report", body)
}

func SendTest(ctx context.Context, c *config.Config) error {
	body := fmt.Sprintf("AdGuard Shield Test-Mail\n\nHostname: %s\nZeitpunkt: %s\nEmpfaenger: %s\nAbsender: %s\n", hostname(), time.Now().Format("2006-01-02 15:04:05"), c.ReportEmailTo, c.ReportEmailFrom)
	if strings.EqualFold(c.ReportFormat, "html") {
		body = "<!doctype html><html><body><h1>AdGuard Shield Test-Mail</h1><p>Hostname: " + html.EscapeString(hostname()) + "</p><p>Zeitpunkt: " + html.EscapeString(time.Now().Format("2006-01-02 15:04:05")) + "</p></body></html>"
	}
	return sendMail(ctx, c, "AdGuard Shield Test-Mail", body)
}

func InstallCron(binary, configPath string, c *config.Config) error {
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
	line := fmt.Sprintf("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n%s root %s -config %s report-send\n", schedule, binary, configPath)
	return os.WriteFile(cronPath, []byte(line), 0644)
}

func RemoveCron() error {
	if err := os.Remove(cronPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sendMail(ctx context.Context, c *config.Config, subject, body string) error {
	if c.ReportEmailTo == "" {
		return fmt.Errorf("REPORT_EMAIL_TO ist leer")
	}
	if c.ReportMailCmd == "" {
		return fmt.Errorf("REPORT_MAIL_CMD ist leer")
	}
	contentType := "text/plain; charset=utf-8"
	if strings.EqualFold(c.ReportFormat, "html") {
		contentType = "text/html; charset=utf-8"
	}
	msg := "From: " + c.ReportEmailFrom + "\n" +
		"To: " + c.ReportEmailTo + "\n" +
		"Subject: " + subject + "\n" +
		"Content-Type: " + contentType + "\n\n" + body
	parts := strings.Fields(c.ReportMailCmd)
	if len(parts) == 0 {
		return fmt.Errorf("REPORT_MAIL_CMD ist leer")
	}
	args := append(parts[1:], "-t")
	cmd := exec.CommandContext(ctx, parts[0], args...)
	cmd.Stdin = strings.NewReader(msg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
	case "biweekly":
		return fmt.Sprintf("%s %s 1,15 * *", minute, hour)
	case "monthly":
		return fmt.Sprintf("%s %s 1 * *", minute, hour)
	default:
		return fmt.Sprintf("%s %s * * 1", minute, hour)
	}
}

func window(interval string) (int64, int64) {
	now := time.Now()
	days := 7
	switch strings.ToLower(interval) {
	case "daily":
		days = 1
	case "biweekly":
		days = 14
	case "monthly":
		days = 30
	}
	return now.AddDate(0, 0, -days).Unix(), now.Unix()
}

func renderText(c *config.Config, st db.ReportStats) string {
	var b strings.Builder
	b.WriteString("AdGuard Shield Report\n")
	b.WriteString("Zeitraum: " + formatTime(st.Since) + " bis " + formatTime(st.Until) + "\n\n")
	b.WriteString("Bans: " + strconv.Itoa(st.TotalBans) + "\n")
	b.WriteString("Unbans: " + strconv.Itoa(st.TotalUnbans) + "\n")
	b.WriteString("Aktive Sperren: " + strconv.Itoa(st.ActiveBans) + "\n\n")
	writeCountsText(&b, "Top Clients", st.TopClients)
	writeCountsText(&b, "Gruende", st.Reasons)
	writeCountsText(&b, "Aktive Quellen", st.Sources)
	if len(st.RecentEvents) > 0 {
		b.WriteString("Letzte Ereignisse\n")
		for _, e := range st.RecentEvents {
			b.WriteString("- " + e + "\n")
		}
	}
	_ = c
	return b.String()
}

func renderHTML(c *config.Config, st db.ReportStats) string {
	var b bytes.Buffer
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>AdGuard Shield Report</title>")
	b.WriteString("<style>body{font-family:Arial,sans-serif;color:#1f2937}table{border-collapse:collapse;margin:12px 0}td,th{border:1px solid #d1d5db;padding:6px 9px;text-align:left}th{background:#f3f4f6}</style>")
	b.WriteString("</head><body>")
	b.WriteString("<h1>AdGuard Shield Report</h1>")
	b.WriteString("<p>Zeitraum: " + html.EscapeString(formatTime(st.Since)) + " bis " + html.EscapeString(formatTime(st.Until)) + "</p>")
	b.WriteString("<ul><li>Bans: " + strconv.Itoa(st.TotalBans) + "</li><li>Unbans: " + strconv.Itoa(st.TotalUnbans) + "</li><li>Aktive Sperren: " + strconv.Itoa(st.ActiveBans) + "</li></ul>")
	writeCountsHTML(&b, "Top Clients", st.TopClients)
	writeCountsHTML(&b, "Gruende", st.Reasons)
	writeCountsHTML(&b, "Aktive Quellen", st.Sources)
	if len(st.RecentEvents) > 0 {
		b.WriteString("<h2>Letzte Ereignisse</h2><table><tr><th>Ereignis</th></tr>")
		for _, e := range st.RecentEvents {
			b.WriteString("<tr><td>" + html.EscapeString(e) + "</td></tr>")
		}
		b.WriteString("</table>")
	}
	b.WriteString("</body></html>")
	_ = c
	return b.String()
}

func writeCountsText(b *strings.Builder, title string, rows []db.ReportCount) {
	b.WriteString(title + "\n")
	if len(rows) == 0 {
		b.WriteString("- keine Daten\n\n")
		return
	}
	for _, r := range rows {
		b.WriteString("- " + r.Name + ": " + strconv.Itoa(r.Count) + "\n")
	}
	b.WriteByte('\n')
}

func writeCountsHTML(b *bytes.Buffer, title string, rows []db.ReportCount) {
	b.WriteString("<h2>" + html.EscapeString(title) + "</h2><table><tr><th>Name</th><th>Anzahl</th></tr>")
	if len(rows) == 0 {
		b.WriteString("<tr><td colspan=\"2\">keine Daten</td></tr>")
	}
	for _, r := range rows {
		b.WriteString("<tr><td>" + html.EscapeString(r.Name) + "</td><td>" + strconv.Itoa(r.Count) + "</td></tr>")
	}
	b.WriteString("</table>")
}

func formatTime(epoch int64) string {
	return time.Unix(epoch, 0).Format("2006-01-02 15:04:05")
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return filepath.Base(os.Args[0])
	}
	return name
}
