package report

import (
	"os"
	"path/filepath"
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

	yesterday := time.Now().AddDate(0, 0, -1)
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
	for _, want := range []string{"AdGuard Shield", "example.com", "1.2.3.4", "DoH", "Subdomain-Flood Sperren", "AbuseIPDB Reports"} {
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
	for _, want := range []string{"Sperren gesamt:          3", "Entsperrungen:           1", "Permanente Sperren:      2", "block.example"} {
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
