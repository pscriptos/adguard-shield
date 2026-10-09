package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
)

func TestGenerateUsesTemplatesAndFullStats(t *testing.T) {
	t.Setenv("ADGUARD_SHIELD_SKIP_UPDATE_CHECK", "true")
	store, err := db.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	yesterday := midnight(time.Now()).AddDate(0, 0, -1).Add(12 * time.Hour)
	events := []struct {
		ip       string
		domain   string
		duration string
		proto    string
		reason   string
	}{
		{"1.2.3.4", "example.com", "3600s", "DNS", "rate-limit"},
		{"1.2.3.4", "example.com", "permanent", "DoH", "subdomain-flood"},
		{"5.6.7.8", "block.example", "permanent", "DoT", "external-blocklist"},
	}
	for i, e := range events {
		ts := yesterday.Add(time.Duration(i) * time.Hour)
		_, err := store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (?, ?, 'BAN', ?, ?, '42', ?, ?, ?)`,
			ts.Unix(), ts.Format("2006-01-02 15:04:05"), e.ip, e.domain, e.duration, e.proto, e.reason)
		if err != nil {
			t.Fatal(err)
		}
	}
	ts := yesterday.Add(4 * time.Hour)
	if _, err := store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (?, ?, 'UNBAN', '1.2.3.4', '-', '-', '-', '-', 'manual')`, ts.Unix(), ts.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertBan(db.Ban{IP: "5.6.7.8", Domain: "block.example", Permanent: true, Reason: "external-blocklist", Protocol: "DoT", Source: "external-blocklist"}); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "shield.log")
	if err := writeTestLog(logPath, yesterday); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path:                  filepath.Join(t.TempDir(), "adguard-shield.conf"),
		ReportInterval:        "weekly",
		ReportFormat:          "html",
		ReportBusiestDayRange: 30,
		LogFile:               logPath,
		ReportEmailTo:         "admin@example.test",
		ReportEmailFrom:       "shield@example.test",
		ReportMailCmd:         "msmtp",
	}

	htmlReport, err := Generate(cfg, store, "html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AdGuard Shield", "example.com", "1.2.3.4", "DoH", "Subdomain-Flood", "AbuseIPDB Reports", "Summe"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("HTML report missing %q\n%s", want, htmlReport)
		}
	}
	if strings.Contains(htmlReport, "{{") {
		t.Fatalf("HTML report still contains placeholders")
	}

	txtReport, err := Generate(cfg, store, "txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Sperren gesamt:          3", "Entsperrungen:           1", "Permanente Sperren:      2", "AbuseIPDB Reports:       1", "block.example"} {
		if !strings.Contains(txtReport, want) {
			t.Fatalf("TXT report missing %q\n%s", want, txtReport)
		}
	}
}

func TestVersionGreater(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.0.1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.2.0", "v1.10.0", false},
	}
	for _, tt := range tests {
		if got := versionGreater(tt.a, tt.b); got != tt.want {
			t.Fatalf("versionGreater(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func writeTestLog(path string, when time.Time) error {
	line := "[" + when.Format("2006-01-02 15:04:05") + "] [INFO] AbuseIPDB: 5.6.7.8 erfolgreich gemeldet\n"
	return os.WriteFile(path, []byte(line), 0644)
}

func TestReportWindowMonthlyCoversPreviousCalendarMonth(t *testing.T) {
	loc := time.Local
	tests := []struct {
		now        time.Time
		start, end string
	}{
		{time.Date(2026, 9, 1, 8, 0, 0, 0, loc), "2026-08-01 00:00:00", "2026-08-31 23:59:59"},
		{time.Date(2026, 10, 1, 8, 0, 0, 0, loc), "2026-09-01 00:00:00", "2026-09-30 23:59:59"},
		{time.Date(2026, 3, 1, 8, 0, 0, 0, loc), "2026-02-01 00:00:00", "2026-02-28 23:59:59"},
		{time.Date(2028, 3, 1, 8, 0, 0, 0, loc), "2028-02-01 00:00:00", "2028-02-29 23:59:59"},
		{time.Date(2027, 1, 1, 8, 0, 0, 0, loc), "2026-12-01 00:00:00", "2026-12-31 23:59:59"},
		{time.Date(2026, 10, 9, 15, 30, 0, 0, loc), "2026-09-01 00:00:00", "2026-09-30 23:59:59"},
	}
	for _, tt := range tests {
		since, until, label := reportWindow("monthly", tt.now)
		gotStart := time.Unix(since, 0).In(loc).Format("2006-01-02 15:04:05")
		gotEnd := time.Unix(until, 0).In(loc).Format("2006-01-02 15:04:05")
		if gotStart != tt.start || gotEnd != tt.end {
			t.Fatalf("monthly %s: got %s - %s, want %s - %s", tt.now.Format("2006-01-02"), gotStart, gotEnd, tt.start, tt.end)
		}
		if !strings.HasPrefix(label, "Monatsbericht: ") {
			t.Fatalf("unexpected label %q", label)
		}
	}
}

func TestReportWindowOtherIntervalsEndYesterday(t *testing.T) {
	loc := time.Local
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, loc) // Montag
	tests := map[string]string{
		"daily":    "2026-10-04 00:00:00",
		"weekly":   "2026-09-28 00:00:00",
		"biweekly": "2026-09-21 00:00:00",
	}
	for interval, wantStart := range tests {
		since, until, _ := reportWindow(interval, now)
		if got := time.Unix(since, 0).In(loc).Format("2006-01-02 15:04:05"); got != wantStart {
			t.Fatalf("%s start = %s, want %s", interval, got, wantStart)
		}
		if got := time.Unix(until, 0).In(loc).Format("2006-01-02 15:04:05"); got != "2026-10-04 23:59:59" {
			t.Fatalf("%s end = %s", interval, got)
		}
	}
}

func TestCountAbuseReportsParsesGoAndLegacyLogFormat(t *testing.T) {
	day := time.Date(2026, 9, 15, 0, 0, 0, 0, time.Local)
	lines := strings.Join([]string{
		day.Add(10*time.Hour).Format("2006/01/02 15:04:05") + " [INFO] [ADGUARD-SHIELDD] AbuseIPDB: 192.0.2.1 erfolgreich gemeldet",
		"[" + day.Add(11*time.Hour).Format("2006-01-02 15:04:05") + "] [INFO] AbuseIPDB: 192.0.2.2 erfolgreich gemeldet",
		day.Add(12*time.Hour).Format("2006/01/02 15:04:05") + " [WARN] [ADGUARD-SHIELDD] AbuseIPDB: HTTP 429 für 192.0.2.3",
		day.AddDate(0, 0, -1).Format("2006/01/02 15:04:05") + " [INFO] [ADGUARD-SHIELDD] AbuseIPDB: 192.0.2.4 erfolgreich gemeldet",
		"kaputt AbuseIPDB: erfolgreich gemeldet",
	}, "\n") + "\n"
	path := filepath.Join(t.TempDir(), "shield.log")
	if err := os.WriteFile(path, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}
	if got := countAbuseReports(path, day.Unix(), day.AddDate(0, 0, 1).Unix()-1); got != 2 {
		t.Fatalf("countAbuseReports = %d, want 2", got)
	}
}

func TestAbuseReportsUsesDatabaseAndLogOnlyBeforeFirstDBEntry(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	day := time.Date(2026, 9, 15, 0, 0, 0, 0, time.Local)
	// Log: 08:00 liegt vor der ersten DB-Meldung, 14:00 ist bereits in der DB und darf nicht doppelt zählen.
	logLines := day.Add(8*time.Hour).Format("2006/01/02 15:04:05") + " [INFO] [ADGUARD-SHIELDD] AbuseIPDB: 192.0.2.1 erfolgreich gemeldet\n" +
		day.Add(14*time.Hour).Format("2006/01/02 15:04:05") + " [INFO] [ADGUARD-SHIELDD] AbuseIPDB: 192.0.2.2 erfolgreich gemeldet\n"
	logPath := filepath.Join(t.TempDir(), "shield.log")
	if err := os.WriteFile(logPath, []byte(logLines), 0644); err != nil {
		t.Fatal(err)
	}
	for _, h := range []int{14, 16} {
		ts := day.Add(time.Duration(h) * time.Hour)
		if _, err := store.DB.Exec(`INSERT INTO abuseipdb_reports (timestamp_epoch, timestamp_text, client_ip) VALUES (?, ?, '192.0.2.2')`, ts.Unix(), ts.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{LogFile: logPath}
	got, err := abuseReports(cfg, store, day.Unix(), day.AddDate(0, 0, 1).Unix()-1)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("abuseReports = %d, want 3", got)
	}
}

func TestGenerateLimitsTopListsAndSumsAttackTypes(t *testing.T) {
	t.Setenv("ADGUARD_SHIELD_SKIP_UPDATE_CHECK", "true")
	store, err := db.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	yesterday := midnight(time.Now()).AddDate(0, 0, -1).Add(time.Hour)
	insert := func(ip, domain, proto, reason string) {
		t.Helper()
		if _, err := store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (?, ?, 'BAN', ?, ?, '1', 'permanent', ?, ?)`,
			yesterday.Unix(), yesterday.Format("2006-01-02 15:04:05"), ip, domain, proto, reason); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 15; i++ {
		insert("192.0.2."+strconv.Itoa(i), "d"+strconv.Itoa(i)+".example", "dns", "rate-limit")
	}
	for i := 0; i < 5; i++ {
		insert("198.51.100."+strconv.Itoa(i), "GeoIP:CN", "-", "geoip")
	}
	insert("203.0.113.1", "manual", "-", "manual")
	cfg := &config.Config{ReportInterval: "weekly", ReportBusiestDayRange: 30, LogFile: filepath.Join(t.TempDir(), "none.log")}

	txt, err := Generate(cfg, store, "txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Sperren gesamt:          21",
		"Rate-Limit               15        71,4 %",
		"GeoIP                    5         23,8 %",
		"Manuell                  1         4,8 %",
		"Summe                    21        100,0 %",
		"ohne Protokoll       6",
		"DNS                  15",
		"  10.  ",
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("TXT report missing %q\n%s", want, txt)
		}
	}
	for _, unwanted := range []string{"Sonstige", "  11.  "} {
		if strings.Contains(txt, unwanted) {
			t.Fatalf("TXT report contains %q\n%s", unwanted, txt)
		}
	}
	domains := txt[strings.Index(txt, "MEISTBETROFFENE DOMAINS"):strings.Index(txt, "PROTOKOLL-VERTEILUNG")]
	if strings.Contains(domains, "GeoIP:") || strings.Contains(domains, "manual") {
		t.Fatalf("top domains contain placeholder entries\n%s", domains)
	}

	htmlReport, err := Generate(cfg, store, "html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(htmlReport, "{{") || !strings.Contains(htmlReport, "reason-badge geoip") || strings.Contains(htmlReport, ">11</span>") {
		t.Fatalf("unexpected HTML report\n%s", htmlReport)
	}
}

func TestPeriodOverviewUsesFullDaysUntilYesterday(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	today := midnight(time.Now())
	for _, ts := range []time.Time{today.Add(time.Second), today.AddDate(0, 0, -1).Add(time.Hour), today.AddDate(0, 0, -7), today.AddDate(0, 0, -8).Add(23 * time.Hour)} {
		if _, err := store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (?, ?, 'BAN', '192.0.2.1', 'a.example', '1', '600s', 'dns', 'rate-limit')`,
			ts.Unix(), ts.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	byLabel := map[string]int{}
	for _, r := range periodOverviewRows(store) {
		byLabel[r.Label] = r.TotalBans
	}
	if byLabel["Gestern"] != 1 || byLabel["Letzte 7 Tage"] != 2 || byLabel["Letzte 14 Tage"] != 3 || byLabel["Letzte 30 Tage"] != 3 {
		t.Fatalf("unexpected overview: %#v", byLabel)
	}
}
