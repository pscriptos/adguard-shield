package daemon

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
)

func TestNewWhitelistSkipsBroadPrefixes(t *testing.T) {
	w, skipped := newWhitelist([]string{
		"::ffff:0:0/96", "::ffff:0.0.0.0/96", "::ffff:0:0/100", "0.0.0.0/0", "::/0", "10.0.0.0/7", "2000::/15",
		"10.0.0.0/8", "2001:db8::/16", "::ffff:0:0/80", "192.0.2.1",
	})
	if len(skipped) != 7 {
		t.Fatalf("skipped = %v, want 7 entries", skipped)
	}
	for ip, want := range map[string]bool{
		"8.8.8.8":         false,
		"1.1.1.1":         false,
		"::ffff:8.8.8.8":  false,
		"2a00::1":         false,
		"10.200.0.1":      true,
		"2001:db8:ff::1":  true,
		"192.0.2.1":       true,
		"203.0.113.0/24":  false,
		"0.0.0.0/0":       true, // überlappt 10.0.0.0/8
		"198.51.100.0/24": false,
	} {
		if got := w.contains(ip); got != want {
			t.Errorf("contains(%q) = %v, want %v", ip, got, want)
		}
	}
	for _, e := range []string{"::ffff:0:0/96", "0.0.0.0/0", "::/0", "10.0.0.0/7"} {
		if whitelistEntryOK(e) {
			t.Errorf("whitelistEntryOK(%q) must be false", e)
		}
	}
	for _, e := range []string{"10.0.0.0/8", "192.0.2.1", "2001:db8::/16"} {
		if !whitelistEntryOK(e) {
			t.Errorf("whitelistEntryOK(%q) must be true", e)
		}
	}
}

func TestSyncWhitelistIgnoresBroadEntries(t *testing.T) {
	var body atomic.Value
	body.Store("::ffff:0:0/96\n0.0.0.0/0\n::/0\n198.51.100.0/24\n")
	srv := listServer(t, &body)
	cfg := &config.Config{ExternalWhitelistURLs: []string{srv.URL}, ExternalWhitelistCacheDir: t.TempDir()}
	d, _ := newTestDaemon(t, cfg)
	for _, ip := range []string{"203.0.113.1", "198.51.100.7"} {
		if err := d.Store.InsertBan(db.Ban{IP: ip, Source: "monitor", Reason: "rate-limit", Permanent: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SyncWhitelist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.Store.BanExists("203.0.113.1"); !ok {
		t.Fatal("broad whitelist entries must not unban unrelated IPs")
	}
	if ok, _ := d.Store.BanExists("198.51.100.7"); ok {
		t.Fatal("valid whitelist network must still lift bans")
	}
	wl, _ := d.Store.AllWhitelist()
	if len(wl) != 1 || !wl["198.51.100.0/24"] {
		t.Fatalf("broad entries must not be stored: %v", wl)
	}
	if d.IsWhitelisted("8.8.8.8") {
		t.Fatal("8.8.8.8 must not be whitelisted")
	}
}

func insertBans(t *testing.T, st *db.Store, prefix string, n int) {
	t.Helper()
	tx, err := st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if _, err := tx.Exec(`INSERT INTO active_bans (client_ip, is_permanent, reason, source) VALUES (?, 1, 'rate-limit', 'monitor')`, fmt.Sprintf("%s.%d", prefix, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestWhitelistSweepTooLarge(t *testing.T) {
	for _, tc := range []struct {
		lift, active int
		want         bool
	}{
		{100, 100, false},
		{101, 150, true},
		{101, 202, false},
		{101, 201, true},
		{12000, 25600, false},
		{13000, 25600, true},
		{0, 0, false},
	} {
		if got := whitelistSweepTooLarge(tc.lift, tc.active); got != tc.want {
			t.Errorf("whitelistSweepTooLarge(%d, %d) = %v, want %v", tc.lift, tc.active, got, tc.want)
		}
	}
}

func TestSyncWhitelistSafetyBrake(t *testing.T) {
	var body atomic.Value
	body.Store("10.0.0.0/16\n")
	srv := listServer(t, &body)
	cfg := &config.Config{ExternalWhitelistURLs: []string{srv.URL}, ExternalWhitelistCacheDir: t.TempDir()}
	d, _ := newTestDaemon(t, cfg)
	insertBans(t, d.Store, "10.0.0", 150)
	insertBans(t, d.Store, "203.0.113", 10)
	if err := d.SyncWhitelist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Store.CountActiveBans(); n != 160 {
		t.Fatalf("safety brake must keep all bans, got %d", n)
	}
	if !d.IsWhitelisted("10.0.0.1") {
		t.Fatal("whitelist itself must still be applied")
	}

	insertBans(t, d.Store, "203.0.114", 200)
	if err := d.SyncWhitelist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Store.CountActiveBans(); n != 210 {
		t.Fatalf("sweep below threshold must unban the 150 whitelisted IPs, active=%d", n)
	}
}

func TestBanChecksDBWhitelistOnSnapshotMiss(t *testing.T) {
	d, ex := newTestDaemon(t, &config.Config{})
	if err := d.loadCaches(); err != nil {
		t.Fatal(err)
	}
	// Eintrag aus einem anderen Prozess (CLI whitelist-sync), Snapshot unverändert.
	if err := d.Store.ReplaceWhitelist([]string{"203.0.113.9"}, "external"); err != nil {
		t.Fatal(err)
	}
	if d.isWhitelisted("203.0.113.9") {
		t.Fatal("snapshot must not know the new entry yet")
	}
	if err := d.Ban(context.Background(), BanRequest{IP: "::ffff:203.0.113.9", Source: "monitor", Reason: "rate-limit"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Store.CountActiveBans(); n != 0 || len(ex.ipsetAdds()) != 0 {
		t.Fatalf("DB-whitelisted IP must not be banned (bans=%d)", n)
	}
	if !d.IsWhitelisted("203.0.113.9") {
		t.Fatal("IsWhitelisted must consult the DB")
	}
	if err := d.loadCaches(); err != nil {
		t.Fatal(err)
	}
	if !d.isWhitelisted("203.0.113.9") {
		t.Fatal("reload must pick up the DB entry")
	}
}

func TestBanRejectsZeroPrefix(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{})
	for _, ip := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96"} {
		if err := d.Ban(context.Background(), BanRequest{IP: ip, Source: "manual", Reason: "manual", Permanent: true}); err == nil {
			t.Errorf("Ban(%q) must fail", ip)
		}
	}
	if n, _ := d.Store.CountActiveBans(); n != 0 {
		t.Fatalf("no ban expected, got %d", n)
	}
}

type ctxExec struct {
	mu      sync.Mutex
	delErrs []error
}

func (c *ctxExec) Run(ctx context.Context, name string, args ...string) error {
	if len(args) > 0 && args[0] == "del" {
		c.mu.Lock()
		c.delErrs = append(c.delErrs, ctx.Err())
		c.mu.Unlock()
	}
	return ctx.Err()
}

func (c *ctxExec) RunInput(ctx context.Context, _ string, _ string, _ ...string) error {
	return ctx.Err()
}

func (c *ctxExec) Output(context.Context, string, ...string) ([]byte, error) { return nil, nil }

func TestUnbanDeletesFirewallEntryDespiteCancelledContext(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{})
	ex := &ctxExec{}
	d.FW = firewall.New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := d.Store.InsertBan(db.Ban{IP: "203.0.113.1", Source: "manual", Reason: "manual", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Unban(ctx, "203.0.113.1", "manual"); err != nil {
		t.Fatal(err)
	}
	if len(ex.delErrs) != 1 || ex.delErrs[0] != nil {
		t.Fatalf("ipset del must run with a live context: %v", ex.delErrs)
	}
	if ok, _ := d.Store.BanExists("203.0.113.1"); ok {
		t.Fatal("ban must be deleted")
	}
}

func TestSweepsStopOnCancelledContext(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{GeoIPEnabled: false})
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if err := d.Store.InsertBan(db.Ban{IP: ip, Source: "geoip", Reason: "geoip", Permanent: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Store.InsertBan(db.Ban{IP: "203.0.113.3", Source: "monitor", Reason: "rate-limit", BanUntil: 1, Duration: 60}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.AutoUnbanGeoIP(ctx); err == nil {
		t.Fatal("cancelled GeoIP sweep must report ctx error")
	}
	if err := d.reconcileFirewall(ctx); err == nil {
		t.Fatal("cancelled reconcile must report ctx error")
	}
	if n, _ := d.Store.CountActiveBans(); n != 3 {
		t.Fatalf("cancelled sweeps must not unban, active=%d", n)
	}
	if err := d.AutoUnbanGeoIP(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Store.CountActiveBans(); n != 1 {
		t.Fatalf("GeoIP sweep must unban both GeoIP bans, active=%d", n)
	}
}

func TestUnbanWaitsForBanMutex(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{})
	if err := d.Store.InsertBan(db.Ban{IP: "203.0.113.1", Source: "manual", Reason: "manual", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	d.banMu.Lock()
	done := make(chan error, 1)
	go func() { done <- d.Unban(context.Background(), "203.0.113.1", "manual") }()
	select {
	case <-done:
		d.banMu.Unlock()
		t.Fatal("unban must wait for banMu")
	case <-time.After(50 * time.Millisecond):
	}
	if ok, _ := d.Store.BanExists("203.0.113.1"); !ok {
		t.Fatal("ban must still exist while banMu is held")
	}
	d.banMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unban did not finish")
	}
}

func TestBanDurationZeroMeansPermanentMonitorBan(t *testing.T) {
	d, ex := newTestDaemon(t, &config.Config{ProgressiveBanEnabled: true, ProgressiveBanMultiplier: 2, ProgressiveBanMaxLevel: 5, ProgressiveBanResetAfter: 86400})
	d.Config.BanDuration = 0
	if err := d.Ban(context.Background(), BanRequest{IP: "203.0.113.1", Source: "monitor", Reason: "rate-limit"}); err != nil {
		t.Fatal(err)
	}
	b, ok, _ := d.Store.BanByIP("203.0.113.1")
	if !ok || b.BanUntil != 0 || b.Duration != 0 {
		t.Fatalf("unexpected ban: %+v", b)
	}
	adds := ex.ipsetAdds()
	if len(adds) != 1 || strings.Contains(strings.Join(adds[0], " "), "timeout") {
		t.Fatalf("ban without duration must not get a timeout: %v", adds)
	}
	if expired, _ := d.Store.ExpiredBans(time.Now().Unix() + 1<<30); len(expired) != 0 {
		t.Fatalf("ban must never expire: %v", expired)
	}
	if got := durationForLevel(0, 4, 2); got != 0 {
		t.Fatalf("durationForLevel(0) = %d", got)
	}
}

func TestRetentionSkipsGeoIPPruningWithZeroTTL(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{HistoryRetentionDays: 30, GeoIPCacheTTL: 0})
	if _, err := d.Store.DB.Exec(`INSERT INTO geoip_cache (ip, country_code, looked_up_at_epoch) VALUES ('203.0.113.1', 'DE', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := d.runRetention(time.Now()); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = d.Store.DB.QueryRow(`SELECT COUNT(*) FROM geoip_cache`).Scan(&n)
	if n != 1 {
		t.Fatalf("GEOIP_CACHE_TTL=0 must keep cache entries, rows=%d", n)
	}
}

func TestNotificationsUseNotifyClient(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	d := &Daemon{
		Config:       &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL},
		Client:       &http.Client{Transport: newTransport(false)},
		NotifyClient: &http.Client{Transport: newTransport(false)},
	}
	d.notifyUnban("203.0.113.1", "manual")
	if hits.Load() != 0 {
		t.Fatal("NOTIFY_TLS_INSECURE=false must verify certificates")
	}
	d.NotifyClient = &http.Client{Transport: newTransport(true)}
	d.notifyUnban("203.0.113.1", "manual")
	if hits.Load() != 1 {
		t.Fatal("NOTIFY_TLS_INSECURE=true must accept self-signed certificates")
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := d.Client.Do(req); err == nil {
		t.Fatal("general client (AbuseIPDB, lists) must verify certificates")
	}
}

func TestQueryLogLimitWarningRateLimited(t *testing.T) {
	d := &Daemon{}
	now := time.Now()
	if !d.shouldWarnQueryLogLimit(now) {
		t.Fatal("first warning must be logged")
	}
	if d.shouldWarnQueryLogLimit(now.Add(time.Minute)) {
		t.Fatal("repeated warning within 5 minutes must be suppressed")
	}
	if !d.shouldWarnQueryLogLimit(now.Add(queryLogLimitWarnEvery + time.Second)) {
		t.Fatal("warning must be logged again after 5 minutes")
	}
}
