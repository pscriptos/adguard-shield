package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"adguard-shield/internal/syslog"
	"adguard-shield/internal/web"
)

func TestListURLsNotExposed(t *testing.T) {
	var body atomic.Value
	body.Store("203.0.113.5\n")
	srv := listServer(t, &body)
	host := strings.TrimPrefix(srv.URL, "https://")
	blockURL := "https://listuser:pw-geheim-77@" + host + "/block.txt?token=list-token-999"
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	deadURL := dead.URL + "/x.txt?token=dead-token-555"
	dead.Close()
	wlURL := srv.URL + "/allow.txt?key=wl-token-4242"

	cfg := webTestConfig(t)
	cfg.ExternalBlocklistEnabled = true
	cfg.ExternalBlocklistURLs = []string{blockURL, deadURL}
	cfg.ExternalBlocklistCacheDir = t.TempDir()
	cfg.ExternalWhitelistEnabled = true
	cfg.ExternalWhitelistURLs = []string{wlURL}
	cfg.NTFYServerURL = "https://ntfy-user:ntfy-pw-31337@ntfy.example"
	d, _ := newTestDaemon(t, cfg)
	useListServer(d, srv)
	logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	d.Logger = syslog.New(logFile, "DEBUG")

	ctx := context.Background()
	// Erster Lauf füllt den Cache, der zweite nutzt ihn ("nutze Cache").
	err = d.SyncBlocklist(ctx)
	d.recordJob("external-blocklist", err)
	body.Store("FAIL")
	err = d.SyncBlocklist(ctx)
	if err == nil {
		t.Fatal("Fehler der Quellen muss gemeldet werden")
	}
	d.recordJob("external-blocklist", err)

	tokens := []string{"list-token-999", "pw-geheim-77", "dead-token-555", "wl-token-4242", "ntfy-pw-31337", "block.txt", "x.txt?"}
	raw, err := os.ReadFile(cfg.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(raw)
	for _, want := range []string{"nutze Cache: Quelle #1 (https://" + host + ")", "Quelle #2 (https://"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("Log enthält %q nicht:\n%s", want, logged)
		}
	}
	for _, tok := range tokens {
		if strings.Contains(logged, tok) {
			t.Errorf("Log enthält %q:\n%s", tok, logged)
		}
	}

	// Ältere Logzeilen und Fehler können die URL noch in voller Länge enthalten.
	ue := &url.Error{Op: "Get", URL: blockURL, Err: errors.New("timeout")}
	for _, line := range []string{
		"blocklist Download Warnung " + blockURL + ": " + ue.Error(),
		"escaped " + url.PathEscape(blockURL) + " " + url.QueryEscape(deadURL),
		"whitelist Download Warnung " + wlURL,
		"ntfy " + cfg.NTFYServerURL,
	} {
		d.warn("%s", line)
	}
	d.recordJob("external-whitelist", fmt.Errorf("Download %s: %w", wlURL, ue))
	d.recordJob("geoip-refresh", errors.New(ue.Error()))

	st, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	out := string(js)
	for _, tok := range tokens {
		if strings.Contains(out, tok) {
			t.Errorf("Status-JSON enthält %q", tok)
		}
	}
	if !strings.Contains(out, "von 2 Quellen fehlgeschlagen") {
		t.Errorf("Job-Fehler fehlt im Status: %s", out)
	}
}

func TestURLSecretsVariants(t *testing.T) {
	got := strings.Join(urlSecrets("https://u:p4ss-word@h.example/p?a=1&token=t%2Bk"), "\n")
	for _, want := range []string{"https://u:p4ss-word@h.example/p?a=1&token=t%2Bk", "a=1&token=t%2Bk", "a=1&token=t+k", "u:p4ss-word", "p4ss-word", "https://u:xxxxx@h.example/p?a=1&token=t%2Bk"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q fehlt in %q", want, got)
		}
	}
	if urlSecrets("  ") != nil {
		t.Fatal("leere URL")
	}
}

func TestUnbanLegacyRows(t *testing.T) {
	d, _ := newTestDaemon(t, webTestConfig(t))
	now := time.Now().Unix()
	rows := []struct {
		ip    string
		until int64
		perm  int
	}{
		{"2001:DB8::0001", now - 10, 0},
		{"::ffff:192.0.2.5", 0, 1},
		{"10.0.0.1/8", 0, 1},
		{"2001:DB8::00AA", 0, 1},
	}
	for _, r := range rows {
		if _, err := d.Store.DB.Exec(`INSERT INTO active_bans (client_ip, ban_until_epoch, is_permanent, reason, source) VALUES (?, ?, ?, 'rate-limit', 'monitor')`, r.ip, r.until, r.perm); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if err := d.reconcileFirewall(ctx); err != nil {
		t.Fatal(err)
	}
	expired, err := d.Store.ExpiredBans(time.Now().Unix())
	if err != nil || len(expired) != 0 {
		t.Fatalf("abgelaufene Altzeile nicht entfernt: %v %v", expired, err)
	}
	for _, ip := range []string{"192.0.2.5", "10.0.0.1/8", "2001:db8::aa"} {
		if err := d.Unban(ctx, ip, "manual"); err != nil {
			t.Fatalf("manuelles Unban %s: %v", ip, err)
		}
	}
	if n, _ := d.Store.CountActiveBans(); n != 0 {
		bans, _ := d.Store.ActiveBans()
		t.Fatalf("%d Altzeilen verblieben: %+v", n, bans)
	}
	for _, r := range rows {
		if countHistory(t, d.Store, r.ip, "UNBAN") != 1 {
			t.Errorf("UNBAN für %s nicht mit gespeicherter Schreibweise protokolliert", r.ip)
		}
	}
	if err := d.Unban(ctx, "192.0.2.99", "manual"); err == nil {
		t.Fatal("Unban ohne Sperre muss fehlschlagen")
	}
}

func TestSyncBlocklistReportsStaleCache(t *testing.T) {
	var body atomic.Value
	body.Store("203.0.113.7\n")
	srv := listServer(t, &body)
	cfg := webTestConfig(t)
	cfg.ExternalBlocklistURLs = []string{srv.URL}
	cfg.ExternalBlocklistCacheDir = t.TempDir()
	d, _ := newTestDaemon(t, cfg)
	useListServer(d, srv)
	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	body.Store("FAIL")
	err := d.SyncBlocklist(context.Background())
	if err == nil || err.Error() != "1 von 1 Quellen fehlgeschlagen (Cache genutzt bzw. übersprungen)" {
		t.Fatalf("Fehler = %v", err)
	}
	if ok, _ := d.Store.BanExists("203.0.113.7"); !ok {
		t.Fatal("Einträge aus dem Cache müssen weiter gesperrt bleiben")
	}
}

func TestStatusStopsOnCancelledContext(t *testing.T) {
	d, _ := newTestDaemon(t, webTestConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Status(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Status: %v", err)
	}
	if err := d.statusTiles(ctx, new(web.Status), time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("statusTiles: %v", err)
	}
}
