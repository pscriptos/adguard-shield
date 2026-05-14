package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
)

func TestParseListEntry(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4 # comment":   "1.2.3.4",
		"0.0.0.0 bad.example": "bad.example",
		"2001:db8::/32":       "2001:db8::/32",
	}
	for input, want := range cases {
		got := parseListEntry(input)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%q -> %#v, want %q", input, got, want)
		}
	}
	if got := parseListEntry("http://example.invalid/list"); got != nil {
		t.Fatalf("URL should be rejected: %#v", got)
	}
}

func TestNotificationFormatting(t *testing.T) {
	d := &Daemon{Config: &config.Config{
		RateLimitWindow:        60,
		SubdomainFloodWindow:   120,
		ProgressiveBanMaxLevel: 3,
	}}
	b := db.Ban{
		IP:           "203.0.113.7",
		Domain:       "abb.com",
		Count:        110,
		Duration:     3600,
		OffenseLevel: 1,
		Reason:       "rate-limit",
		Protocol:     "dns",
		Source:       "monitor",
	}
	if got, want := d.displayBanReason(b), "110x abb.com in 60s via DNS, Rate-Limit"; got != want {
		t.Fatalf("reason = %q, want %q", got, want)
	}
	if got, want := d.displayBanDuration(b), "1h 0m [Stufe 1/3]"; got != want {
		t.Fatalf("duration = %q, want %q", got, want)
	}

	b.Permanent = true
	b.Duration = 0
	b.OffenseLevel = 3
	if got, want := d.displayBanDuration(b), "PERMANENT [Stufe 3/3]"; got != want {
		t.Fatalf("permanent duration = %q, want %q", got, want)
	}
}

func TestNTFYNotificationTitleDoesNotDuplicateShieldTag(t *testing.T) {
	d := &Daemon{Config: &config.Config{
		NotifyType:    "ntfy",
		NTFYServerURL: "https://ntfy.example",
		NTFYTopic:     "adguard-shield",
		NTFYPriority:  "4",
	}}
	req, err := d.notificationRequest(context.Background(), "🛡️ AdGuard Shield", "test", db.Ban{IP: "203.0.113.7", Reason: "rate-limit", Source: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("request must be created")
	}
	if got, want := req.Header.Get("Title"), "🛡️ AdGuard Shield"; got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
	if got := req.Header.Get("Tags"); strings.Contains(got, "shield") {
		t.Fatalf("tags must not duplicate title shield emoji: %q", got)
	}
}

func TestNotificationRequestsForWebhookProviders(t *testing.T) {
	cases := []struct {
		name        string
		notifyType  string
		wantType    string
		wantPayload []string
	}{
		{
			name:        "discord",
			notifyType:  "discord",
			wantType:    "application/json",
			wantPayload: []string{`"content":"title\n\nmessage"`},
		},
		{
			name:        "slack",
			notifyType:  "slack",
			wantType:    "application/json",
			wantPayload: []string{`"text":"title\n\nmessage"`},
		},
		{
			name:        "generic",
			notifyType:  "generic",
			wantType:    "application/json",
			wantPayload: []string{`"action":"unban"`, `"client":"203.0.113.7"`, `"message":"message"`},
		},
		{
			name:        "gotify",
			notifyType:  "gotify",
			wantType:    "application/x-www-form-urlencoded",
			wantPayload: []string{`title=title`, `message=message`, `priority=5`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{Config: &config.Config{
				NotifyType:    tc.notifyType,
				NotifyWebhook: "https://hooks.example/notify",
			}}
			req, err := d.notificationRequest(context.Background(), "title", "message", db.Ban{IP: "203.0.113.7", Reason: "manual"})
			if err != nil {
				t.Fatal(err)
			}
			if req == nil {
				t.Fatal("request must be created")
			}
			if req.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", req.Method)
			}
			if got := req.Header.Get("Content-Type"); got != tc.wantType {
				t.Fatalf("content type = %q, want %q", got, tc.wantType)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			payload := string(body)
			for _, want := range tc.wantPayload {
				if !strings.Contains(payload, want) {
					t.Fatalf("payload %q does not contain %q", payload, want)
				}
			}
		})
	}
}

func TestServiceNotificationsSendStartAndStopOnce(t *testing.T) {
	requests := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d := &Daemon{
		Config: &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL},
		Client: srv.Client(),
	}
	d.NotifyServiceStart(context.Background())
	d.NotifyServiceStart(context.Background())
	d.NotifyServiceStop(context.Background())
	d.NotifyServiceStop(context.Background())

	var payloads []string
	for len(payloads) < 2 {
		select {
		case payload := <-requests:
			payloads = append(payloads, payload)
		case <-time.After(4 * time.Second):
			t.Fatalf("service notifications sent %d payloads, want 2", len(payloads))
		}
	}
	if !strings.Contains(payloads[0], `"action":"service_start"`) || !strings.Contains(payloads[0], "gestartet") {
		t.Fatalf("unexpected service start payload: %s", payloads[0])
	}
	if !strings.Contains(payloads[1], `"action":"service_stop"`) || !strings.Contains(payloads[1], "gestoppt") {
		t.Fatalf("unexpected service stop payload: %s", payloads[1])
	}
	select {
	case payload := <-requests:
		t.Fatalf("duplicate service notification sent: %s", payload)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestUnbanSendsNotificationForMonitorBan(t *testing.T) {
	requests := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InsertBan(db.Ban{IP: "127.0.0.1", Reason: "rate-limit", Source: "monitor"}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		Config: &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL},
		Store:  store,
		FW:     firewall.New(firewall.OSExecutor{}, "ADGUARD_SHIELD", []string{"53"}, "host", true),
		Client: srv.Client(),
	}
	if err := d.Unban(context.Background(), "127.0.0.1", "manual"); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-requests:
		if !strings.Contains(payload, `"action":"unban"`) || !strings.Contains(payload, "AdGuard Shield Freigabe") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("unban notification was not sent")
	}
}

func TestUnbanStillSendsExternalBlocklistNotificationWhenBanNotificationsDisabled(t *testing.T) {
	requests := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InsertBan(db.Ban{IP: "127.0.0.1", Reason: "external-blocklist", Source: "external-blocklist"}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		Config: &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL, ExternalBlocklistNotify: false},
		Store:  store,
		FW:     firewall.New(firewall.OSExecutor{}, "ADGUARD_SHIELD", []string{"53"}, "host", true),
		Client: srv.Client(),
	}
	if err := d.Unban(context.Background(), "127.0.0.1", "external-blocklist-removed"); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-requests:
		if !strings.Contains(payload, `"action":"unban"`) || !strings.Contains(payload, "AdGuard Shield Freigabe") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("external blocklist unban notification was not sent")
	}
}

func TestUnbanQuietSkipsIndividualNotificationAndBulkSummarySendsOnce(t *testing.T) {
	requests := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InsertBan(db.Ban{IP: "127.0.0.1", Reason: "rate-limit", Source: "monitor"}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		Config: &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL},
		Store:  store,
		FW:     firewall.New(firewall.OSExecutor{}, "ADGUARD_SHIELD", []string{"53"}, "host", true),
		Client: srv.Client(),
	}
	if err := d.UnbanQuiet(context.Background(), "127.0.0.1", "manual-flush"); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-requests:
		t.Fatalf("quiet unban sent individual notification: %s", payload)
	case <-time.After(150 * time.Millisecond):
	}

	d.NotifyBulkUnban(context.Background(), "manual-flush", 1)
	select {
	case payload := <-requests:
		if !strings.Contains(payload, `"action":"manual-flush"`) || !strings.Contains(payload, "Bulk-Freigabe") || !strings.Contains(payload, "Freigegebene IPs: 1") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("bulk unban notification was not sent")
	}
}

func TestAbuseReportingScope(t *testing.T) {
	d := &Daemon{Config: &config.Config{AbuseIPDBEnabled: true, AbuseIPDBAPIKey: "key"}}
	if !d.shouldReportAbuseIPDB(db.Ban{Permanent: true, Source: "monitor"}) {
		t.Fatal("monitor permanent ban should be reported")
	}
	if d.shouldReportAbuseIPDB(db.Ban{Permanent: true, Source: "geoip"}) {
		t.Fatal("geoip ban must not be reported")
	}
	if d.shouldReportAbuseIPDB(db.Ban{Permanent: false, Source: "monitor"}) {
		t.Fatal("temporary ban must not be reported")
	}

	d.Config.RateLimitWindow = 60
	got := d.abuseIPDBComment(db.Ban{Count: 110, Domain: "abb.com", Reason: "rate-limit"})
	want := "DNS flooding on our DNS server: 110x abb.com in 60s. Banned by Adguard Shield 🔗 https://git.techniverse.net/scriptos/adguard-shield.git"
	if got != want {
		t.Fatalf("comment = %q, want %q", got, want)
	}
}

func TestAbuseIPDBCheckURL(t *testing.T) {
	if got := abuseIPDBCheckURL("65.185.189.75"); !strings.Contains(got, "https://www.abuseipdb.com/check/65.185.189.75") {
		t.Fatalf("unexpected AbuseIPDB url: %s", got)
	}
}

func TestBaseDomain(t *testing.T) {
	if got := baseDomain("a.b.example.com"); got != "example.com" {
		t.Fatalf("unexpected base domain: %s", got)
	}
	if got := baseDomain("a.b.example.co.uk"); got != "example.co.uk" {
		t.Fatalf("unexpected multipart base domain: %s", got)
	}
}

func TestDryRunDoesNotInsertActiveBan(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := &Daemon{
		Config: &config.Config{DryRun: true, BanDuration: 60},
		Store:  store,
		FW:     firewall.New(firewall.OSExecutor{}, "ADGUARD_SHIELD", []string{"53"}, "host", true),
		wl:     map[string]bool{},
	}
	if err := d.Ban(context.Background(), "1.2.3.4", "example.com", 99, "dns", "rate-limit", "monitor", "", false); err != nil {
		t.Fatal(err)
	}
	ok, err := store.BanExists("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("dry-run must not create an active ban")
	}
}
