package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/syslog"
)

func webTestConfig(t *testing.T) *config.Config {
	return &config.Config{
		RateLimitMaxRequests: 30, RateLimitWindow: 60, CheckInterval: 10,
		SubdomainFloodEnabled: true, SubdomainFloodMaxUnique: 50, SubdomainFloodWindow: 60,
		LogFile:   filepath.Join(t.TempDir(), "adguard-shield.log"),
		Whitelist: []string{"127.0.0.1", "::1"},
	}
}

func TestStatusUsesInMemoryEventsWithoutNetwork(t *testing.T) {
	var hits atomic.Int32
	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer agh.Close()
	cfg := webTestConfig(t)
	cfg.AdGuardURL = agh.URL
	d, _ := newTestDaemon(t, cfg)
	d.AdGuardClient = agh.Client()
	now := time.Now()
	d.startedAt = now.Add(-90 * time.Second)
	d.lastPollAt, d.lastPollEntries = now.Add(-2*time.Second), 77
	for i := 0; i < 20; i++ {
		d.events = append(d.events, queryEvent{At: now.Add(-time.Duration(i) * time.Second), Client: "192.0.2.10", Domain: "flood.example.com", Protocol: "doh"})
	}
	for i := 0; i < 3; i++ {
		d.events = append(d.events, queryEvent{At: now.Add(-time.Duration(i) * time.Second), Client: "192.0.2.11", Domain: string(rune('a'+i)) + ".sub.example.org", Protocol: "dns"})
	}
	if err := d.Store.InsertBan(db.Ban{IP: "198.51.100.1", Domain: "x.example", Reason: "rate-limit", Source: "monitor", BanUntil: now.Add(time.Hour).Unix(), Duration: 3600}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.InsertBan(db.Ban{IP: "198.51.100.2", Domain: "-", Reason: "manual", Source: "manual", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.History("BAN", "198.51.100.1", "x.example", "40", "3600s", "DNS", "rate-limit"); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.ReplaceWhitelist([]string{"203.0.113.1", "127.0.0.1"}, "external"); err != nil {
		t.Fatal(err)
	}

	st, err := d.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("Status darf das AdGuard-Querylog nicht abfragen (%d Aufrufe)", hits.Load())
	}
	if st.UptimeSeconds < 89 || st.Poll.Entries != 77 || st.Poll.LastSuccess == nil {
		t.Fatalf("Laufzeit/Poll falsch: %+v / %+v", st.UptimeSeconds, st.Poll)
	}
	if st.Tiles.ActiveBans != 2 || st.Tiles.PermanentBans != 1 || st.Tiles.BansToday != 1 || st.Tiles.Bans7Days != 1 || st.Tiles.WhitelistEntries != 3 {
		t.Fatalf("Kacheln falsch: %+v", st.Tiles)
	}
	if st.Live.EventsInMemory != 23 || len(st.Live.Recent) != webListLimit {
		t.Fatalf("Live: events=%d recent=%d", st.Live.EventsInMemory, len(st.Live.Recent))
	}
	if top := st.Live.Top[0]; top.Client != "192.0.2.10" || top.Count != 20 || top.Protocol != "DoH" {
		t.Fatalf("Top falsch: %+v", top)
	}
	if len(st.Live.Subdomains) != 2 || st.Live.Subdomains[0].Domain != "example.org" || st.Live.Subdomains[0].Count != 3 {
		t.Fatalf("Subdomains falsch: %+v", st.Live.Subdomains)
	}
	if len(st.Bans) != 2 || len(st.History) != 1 || st.History[0].Action != "BAN" || st.History[0].Reason != "rate-limit" {
		t.Fatalf("Sperren/History falsch: %+v / %+v", st.Bans, st.History)
	}
	for _, b := range st.Bans {
		if b.IP == "198.51.100.2" && (!b.Permanent || b.Until != nil) {
			t.Fatalf("permanente Sperre falsch: %+v", b)
		}
		if b.IP == "198.51.100.1" && (b.Permanent || b.Until == nil) {
			t.Fatalf("befristete Sperre falsch: %+v", b)
		}
	}
	if len(d.events) != 23 {
		t.Fatal("Status darf das Ereignisfenster nicht verändern")
	}
}

func TestStatusDoesNotExposeSecrets(t *testing.T) {
	cfg := webTestConfig(t)
	secrets := map[string]string{
		"ADGUARD_PASS":       "adguard-pass-0815",
		"NOTIFY_WEBHOOK_URL": "https://discord.example/api/webhooks/123/hook-secret-xyz",
		"NTFY_TOPIC":         "ntfy-topic-geheim",
		"NTFY_TOKEN":         "tk_ntfytoken4711",
		"ABUSEIPDB_API_KEY":  "abuseipdb-key-abcdef",
		"GEOIP_LICENSE_KEY":  "maxmind-license-123456",
		"WEB_PASSWORD":       "web-pass-geheim",
	}
	cfg.AdGuardURL = "http://127.0.0.1:1"
	cfg.AdGuardPass = secrets["ADGUARD_PASS"]
	cfg.NotifyEnabled, cfg.NotifyType = true, "discord"
	cfg.NotifyWebhook = secrets["NOTIFY_WEBHOOK_URL"]
	cfg.NTFYTopic = secrets["NTFY_TOPIC"]
	cfg.NTFYToken = secrets["NTFY_TOKEN"]
	cfg.AbuseIPDBEnabled, cfg.AbuseIPDBAPIKey = true, secrets["ABUSEIPDB_API_KEY"]
	cfg.GeoIPEnabled, cfg.GeoIPLicenseKey = true, secrets["GEOIP_LICENSE_KEY"]
	cfg.WebEnabled, cfg.WebPassword = true, secrets["WEB_PASSWORD"]
	cfg.ExternalBlocklistEnabled = true
	cfg.ExternalBlocklistURLs = []string{"https://lists.example/block.txt?token=list-token-999"}
	d, _ := newTestDaemon(t, cfg)

	var log strings.Builder
	for _, s := range secrets {
		log.WriteString("2026-01-01 00:00:00 [WARN] Fehler mit " + s + "\n")
	}
	if err := os.WriteFile(cfg.LogFile, []byte(log.String()), 0600); err != nil {
		t.Fatal(err)
	}
	d.recordJob("geoip-refresh", errors.New(`Get "https://download.maxmind.com/app?license_key=`+secrets["GEOIP_LICENSE_KEY"]+`": timeout`))
	d.recordJob("external-blocklist", errors.New("webhook "+secrets["NOTIFY_WEBHOOK_URL"]))
	d.lastPollErr, d.lastPollErrAt = "auth failed for "+secrets["ADGUARD_PASS"], time.Now()

	st, err := d.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for k, s := range secrets {
		if strings.Contains(body, s) {
			t.Errorf("%s erscheint im Status-JSON", k)
		}
	}
	for _, s := range []string{"list-token-999", "lists.example", "127.0.0.1:1"} {
		if strings.Contains(body, s) {
			t.Errorf("%q erscheint im Status-JSON", s)
		}
	}
	if len(st.Logs) != len(secrets) || !strings.Contains(body, webRedacted) {
		t.Fatalf("Logzeilen nicht geschwärzt übernommen: %v", st.Logs)
	}
}

func TestRunJobRecordsResult(t *testing.T) {
	d, _ := newTestDaemon(t, webTestConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	d.runJob(ctx, "external-whitelist", true, time.Hour, true, func(context.Context) error {
		defer close(done)
		return errors.New("kaputt")
	})
	<-done
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r, ok := d.jobState("external-whitelist"); ok {
			if r.err != "kaputt" {
				t.Fatalf("Ergebnis %q", r.err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Lauf nicht erfasst")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPollOnceTracksPollState(t *testing.T) {
	_, d := newFakeAGH(t, 3, time.Second)
	d.Config.RateLimitMaxRequests = 1000
	if err := d.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.lastPollAt.IsZero() || d.lastPollEntries != 3 {
		t.Fatalf("Poll nicht erfasst: %v %d", d.lastPollAt, d.lastPollEntries)
	}
	d.Config.AdGuardURL = "http://127.0.0.1:1/"
	if err := d.pollOnce(context.Background()); err == nil || d.lastPollErr == "" {
		t.Fatal("Poll-Fehler nicht erfasst")
	}
}

func TestParseHistoryLine(t *testing.T) {
	h := parseHistoryLine("2026-01-01 10:00:00 | BAN | 192.0.2.1 | a.example | 31 | 3600s | DNS | rate-limit")
	if h.Time != "2026-01-01 10:00:00" || h.Action != "BAN" || h.IP != "192.0.2.1" || h.Reason != "rate-limit" || h.Duration != "3600s" {
		t.Fatalf("%+v", h)
	}
	if h := parseHistoryLine("kaputt"); h.Time != "kaputt" || h.Reason != "" {
		t.Fatalf("%+v", h)
	}
}

func TestStartWebLifecycle(t *testing.T) {
	cfg := webTestConfig(t)
	cfg.WebEnabled, cfg.WebPort, cfg.WebBasePath = true, 0, "/"
	var buf safeBuffer
	d, _ := newTestDaemon(t, cfg)
	d.Logger = syslog.New(&buf, "INFO")
	stop := d.startWeb(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "Web-Statusseite gestartet") {
		if time.Now().After(deadline) {
			t.Fatalf("nicht gestartet: %s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if !strings.Contains(buf.String(), "Web-Statusseite gestoppt") {
		t.Fatalf("nicht geordnet gestoppt: %s", buf.String())
	}

}

type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *safeBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}
