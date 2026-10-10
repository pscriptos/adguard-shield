package daemon

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
	"adguard-shield/internal/geoip"
	"adguard-shield/internal/syslog"
)

func newNilGeo(dir string) *geoip.Resolver {
	return geoip.New("", "", dir, 0, nil)
}

type fakeExec struct {
	mu     sync.Mutex
	runs   [][]string
	inputs []string
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, append([]string{name}, args...))
	return nil
}

func (f *fakeExec) RunInput(_ context.Context, input string, name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, input)
	return nil
}

func (f *fakeExec) Output(context.Context, string, ...string) ([]byte, error) { return nil, nil }

func (f *fakeExec) ipsetAdds() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, r := range f.runs {
		if len(r) > 1 && r[0] == "ipset" && r[1] == "add" {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeExec) restoreInputs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.inputs...)
}

type notifySink struct {
	srv   *httptest.Server
	count atomic.Int32
	mu    sync.Mutex
	body  []string
}

func newNotifySink(t *testing.T) *notifySink {
	s := &notifySink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.body = append(s.body, string(b))
		s.mu.Unlock()
		s.count.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *notifySink) bodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.body...)
}

func newTestDaemon(t *testing.T, cfg *config.Config) (*Daemon, *fakeExec) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if cfg.BanDuration == 0 {
		cfg.BanDuration = 3600
	}
	ex := &fakeExec{}
	d := &Daemon{
		Config:  cfg,
		Store:   store,
		FW:      firewall.New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false),
		Client:  http.DefaultClient,
		geoSeen: map[string]time.Time{},
	}
	return d, ex
}

func countHistory(t *testing.T, st *db.Store, ip, action string) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE client_ip=? AND action=?`, ip, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWhitelistMatchesAddressesAndPrefixes(t *testing.T) {
	w, _ := newWhitelist([]string{"10.0.0.0/24", "2001:db8::/48", "192.168.1.1", "::ffff:172.16.0.5", " fd00::1 ", "kein-eintrag", "::ffff:100.64.0.0/112"})
	cases := map[string]bool{
		"10.0.0.7":               true,
		"10.0.0.255":             true,
		"10.0.1.1":               false,
		"::ffff:10.0.0.9":        true,
		"2001:db8:0:1::5":        true,
		"2001:db8:1::1":          false,
		"2001:DB8::abcd":         true,
		"172.16.0.5":             true,
		"::ffff:172.16.0.5":      true,
		"192.168.1.1":            true,
		"192.168.1.2":            false,
		"fd00::1":                true,
		"fd00:0:0::1":            true,
		"fe80::1%eth0":           false,
		"100.64.255.1":           true,
		"100.65.0.1":             false,
		"10.0.0.128/25":          true,
		"10.0.0.0/16":            true,
		"192.168.0.0/16":         true,
		"192.168.2.0/24":         false,
		"203.0.113.0/24":         false,
		"::ffff:10.0.0.0/120":    true,
		"2001:db8::/32":          true,
		"2001:db9::/32":          false,
		"fd00::/64":              true,
		"kein-eintrag":           false,
		"":                       false,
		"300.1.1.1":              false,
		"10.0.0.0/33":            false,
		"192.168.1.1/32":         true,
		"::ffff:192.168.1.1/128": true,
	}
	for in, want := range cases {
		if got := w.contains(in); got != want {
			t.Errorf("contains(%q) = %v, want %v", in, got, want)
		}
	}
	if w.size() != 6 {
		t.Fatalf("size = %d, want 6 (invalid entry ignored)", w.size())
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":             "1.2.3.4",
		"::ffff:1.2.3.4":      "1.2.3.4",
		"2001:0DB8::0001":     "2001:db8::1",
		"10.1.2.3/8":          "10.0.0.0/8",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"fe80::1%eth0":        "fe80::1",
	}
	for in, want := range cases {
		got, ok := normalizeTarget(in)
		if !ok || got != want {
			t.Errorf("normalizeTarget(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"foo", "", "1.2.3", "1.2.3.4/40", "example.com"} {
		if _, ok := normalizeTarget(bad); ok {
			t.Errorf("normalizeTarget(%q) must fail", bad)
		}
	}
}

func TestDaemonWhitelistCombinesStaticAndDBEntriesLazily(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{Whitelist: []string{"192.0.2.0/28"}})
	if err := d.Store.ReplaceWhitelist([]string{"198.51.100.0/24", "203.0.113.9"}, "external"); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"192.0.2.5": true, "192.0.2.17": false, "198.51.100.77": true, "203.0.113.9": true, "203.0.113.10": false} {
		if got := d.IsWhitelisted(ip); got != want {
			t.Errorf("IsWhitelisted(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestWhitelistConcurrentReadAndReload(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{Whitelist: []string{"10.0.0.0/8"}})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if !d.isWhitelisted("10.1.2.3") {
						t.Error("static whitelist entry lost during reload")
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		if err := d.loadCaches(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestBanValidation(t *testing.T) {
	d, ex := newTestDaemon(t, &config.Config{Whitelist: []string{"10.0.0.0/24"}})
	ctx := context.Background()
	for _, bad := range []string{"foo", "", "1.2.3.4/33", "999.1.1.1"} {
		if err := d.Ban(ctx, BanRequest{IP: bad, Source: "manual", Reason: "manual"}); err == nil {
			t.Errorf("Ban(%q) must fail", bad)
		}
	}
	if n, _ := d.Store.CountActiveBans(); n != 0 {
		t.Fatalf("invalid bans must not create rows, got %d", n)
	}
	err := d.Ban(ctx, BanRequest{IP: "10.0.0.5", Source: "manual", Reason: "manual", Permanent: true})
	if err == nil || !strings.Contains(err.Error(), "Whitelist") {
		t.Fatalf("manual ban of whitelisted IP must explain itself, got %v", err)
	}
	if err := d.Ban(ctx, BanRequest{IP: "10.0.0.6", Source: "monitor", Reason: "rate-limit"}); err != nil {
		t.Fatalf("automatic ban of whitelisted IP must be silent, got %v", err)
	}
	if n, _ := d.Store.CountActiveBans(); n != 0 {
		t.Fatalf("whitelisted IPs must not be banned, got %d", n)
	}
	if err := d.Ban(ctx, BanRequest{IP: "::ffff:203.0.113.4", Source: "manual", Reason: "manual", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	b, ok, _ := d.Store.BanByIP("203.0.113.4")
	if !ok || !b.Permanent || b.Duration != 0 || b.BanUntil != 0 {
		t.Fatalf("manual ban not stored canonically/permanent: %+v ok=%v", b, ok)
	}
	adds := ex.ipsetAdds()
	if len(adds) != 1 || strings.Join(adds[0], " ") != "ipset add adguard_shield_v4 203.0.113.4 -exist" {
		t.Fatalf("permanent ban must be added without timeout: %v", adds)
	}
}

func TestConcurrentBansCreateExactlyOneBan(t *testing.T) {
	sink := newNotifySink(t)
	d, ex := newTestDaemon(t, &config.Config{
		NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: sink.srv.URL,
		ProgressiveBanEnabled: true, ProgressiveBanMultiplier: 2, ProgressiveBanResetAfter: 86400, GeoIPNotify: true,
		RateLimitWindow: 60,
	})
	d.Client = sink.srv.Client()
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := "monitor"
			if i%3 == 1 {
				src = "geoip"
			}
			errs <- d.Ban(context.Background(), BanRequest{IP: "203.0.113.50", Domain: "example.com", Count: 100, Protocol: "dns", Reason: "rate-limit", Source: src})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := countHistory(t, d.Store, "203.0.113.50", "BAN"); got != 1 {
		t.Fatalf("history BAN rows = %d, want 1", got)
	}
	if got := len(ex.ipsetAdds()); got != 1 {
		t.Fatalf("firewall adds = %d, want 1", got)
	}
	if got := sink.count.Load(); got != 1 {
		t.Fatalf("notifications = %d, want 1", got)
	}
	o, ok, _ := d.Store.OffenseByIP("203.0.113.50")
	if ok && o.Level > 1 {
		t.Fatalf("offense incremented %d times", o.Level)
	}
}

func TestBanSkipsWhenRowInsertedByOtherProcess(t *testing.T) {
	sink := newNotifySink(t)
	d, ex := newTestDaemon(t, &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: sink.srv.URL})
	d.Client = sink.srv.Client()
	if err := d.Store.InsertBan(db.Ban{IP: "203.0.113.60", Source: "manual", Reason: "manual", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.Ban(context.Background(), BanRequest{IP: "203.0.113.60", Source: "monitor", Reason: "rate-limit"}); err != nil {
		t.Fatal(err)
	}
	if len(ex.ipsetAdds()) != 0 || sink.count.Load() != 0 || countHistory(t, d.Store, "203.0.113.60", "BAN") != 0 {
		t.Fatal("existing ban must not trigger firewall, history or notification")
	}
}

func listServer(t *testing.T, body *atomic.Value) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := body.Load().(string)
		if v == "FAIL" {
			http.Error(w, "kaputt", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func deadURL(t *testing.T) string {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL + "/list.txt"
	srv.Close()
	return u
}

func TestSyncWhitelistFailureKeepsOldEntries(t *testing.T) {
	var body atomic.Value
	body.Store("198.51.100.0/24\n")
	srv := listServer(t, &body)
	cfg := &config.Config{ExternalWhitelistURLs: []string{srv.URL, deadURL(t)}, ExternalWhitelistCacheDir: t.TempDir()}
	d, _ := newTestDaemon(t, cfg)
	if err := d.Store.ReplaceWhitelist([]string{"192.0.2.1"}, "external"); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.InsertBan(db.Ban{IP: "198.51.100.20", Source: "monitor", Reason: "rate-limit"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SyncWhitelist(context.Background()); err == nil {
		t.Fatal("sync with unavailable source must fail")
	}
	if !d.IsWhitelisted("192.0.2.1") {
		t.Fatal("old whitelist entry must be kept in memory")
	}
	if ok, _ := d.Store.WhitelistContains("192.0.2.1"); !ok {
		t.Fatal("old whitelist entry must be kept in DB")
	}
	if ok, _ := d.Store.BanExists("198.51.100.20"); !ok {
		t.Fatal("failed sync must not unban")
	}

	cfg.ExternalWhitelistURLs = cfg.ExternalWhitelistURLs[:1]
	if err := d.SyncWhitelist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.IsWhitelisted("192.0.2.1") || !d.IsWhitelisted("198.51.100.200") {
		t.Fatal("successful sync must replace whitelist and support CIDR")
	}
	if ok, _ := d.Store.BanExists("198.51.100.20"); ok {
		t.Fatal("ban inside new whitelisted network must be lifted")
	}
}

func TestSyncBlocklistFailureSkipsAutoUnban(t *testing.T) {
	var body atomic.Value
	body.Store("203.0.113.5\n")
	srv := listServer(t, &body)
	cfg := &config.Config{
		ExternalBlocklistURLs:      []string{srv.URL, deadURL(t)},
		ExternalBlocklistCacheDir:  t.TempDir(),
		ExternalBlocklistAutoUnban: true,
	}
	d, _ := newTestDaemon(t, cfg)
	if err := d.Store.InsertBan(db.Ban{IP: "198.51.100.7", Source: "external-blocklist", Reason: "external-blocklist", Permanent: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.Store.BanExists("198.51.100.7"); !ok {
		t.Fatal("auto-unban must be skipped while a source is unavailable")
	}
	if ok, _ := d.Store.BanExists("203.0.113.5"); !ok {
		t.Fatal("entries of available sources must still be banned")
	}
	cfg.ExternalBlocklistURLs = cfg.ExternalBlocklistURLs[:1]
	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.Store.BanExists("198.51.100.7"); ok {
		t.Fatal("removed entry must be unbanned when all sources are available")
	}
}

func TestSyncBlocklistAddsOnlyNewEntriesInOneBatch(t *testing.T) {
	var body atomic.Value
	body.Store(strings.Join([]string{
		"203.0.113.1", "203.0.113.2 # Kommentar", "198.51.100.0/24", "2001:DB8:0::/48",
		"10.0.0.0/8", "0.0.0.0", "127.0.0.1", "0.0.0.0/0", "::ffff:203.0.113.3", "",
	}, "\n"))
	srv := listServer(t, &body)
	cfg := &config.Config{
		Whitelist:                 []string{"10.1.2.3"},
		ExternalBlocklistURLs:     []string{srv.URL},
		ExternalBlocklistCacheDir: t.TempDir(),
		ExternalBlocklistDuration: 7200,
	}
	d, ex := newTestDaemon(t, cfg)
	if err := d.Store.InsertBan(db.Ban{IP: "203.0.113.2", Source: "monitor", Reason: "rate-limit", BanUntil: time.Now().Unix() + 100, Duration: 100}); err != nil {
		t.Fatal(err)
	}
	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	inputs := ex.restoreInputs()
	if len(inputs) != 1 {
		t.Fatalf("expected one ipset restore batch, got %d", len(inputs))
	}
	want := []string{
		"add adguard_shield_v4 198.51.100.0/24 timeout 7200",
		"add adguard_shield_v6 2001:db8::/48 timeout 7200",
		"add adguard_shield_v4 203.0.113.1 timeout 7200",
		"add adguard_shield_v4 203.0.113.3 timeout 7200",
	}
	got := strings.Split(strings.TrimSpace(inputs[0]), "\n")
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("batch = %q, want %q", got, want)
	}
	if len(ex.ipsetAdds()) != 0 {
		t.Fatal("blocklist must not use single ipset add calls")
	}
	for _, ip := range []string{"10.0.0.0/8", "0.0.0.0", "127.0.0.1", "0.0.0.0/0"} {
		if ok, _ := d.Store.BanExists(ip); ok {
			t.Fatalf("%s must not be banned", ip)
		}
	}
	if b, _, _ := d.Store.BanByIP("203.0.113.2"); b.Source != "monitor" {
		t.Fatal("existing ban must not be replaced")
	}
	if n := countHistory(t, d.Store, "203.0.113.1", "BAN"); n != 1 {
		t.Fatalf("history rows = %d", n)
	}

	if err := d.SyncBlocklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(ex.restoreInputs()); got != 1 {
		t.Fatalf("second sync must not touch the firewall again, batches = %d", got)
	}
	if n := countHistory(t, d.Store, "203.0.113.1", "BAN"); n != 1 {
		t.Fatalf("second sync must not write history again: %d", n)
	}
}

func TestSyncBlocklistNotificationSummary(t *testing.T) {
	for _, tc := range []struct {
		entries int
		want    int32
	}{{3, 3}, {5, 5}, {7, 1}} {
		t.Run(strconv.Itoa(tc.entries), func(t *testing.T) {
			var lines []string
			for i := 1; i <= tc.entries; i++ {
				lines = append(lines, fmt.Sprintf("203.0.113.%d", i))
			}
			var body atomic.Value
			body.Store(strings.Join(lines, "\n"))
			srv := listServer(t, &body)
			sink := newNotifySink(t)
			d, _ := newTestDaemon(t, &config.Config{
				NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: sink.srv.URL,
				ExternalBlocklistNotify: true, ExternalBlocklistURLs: []string{srv.URL}, ExternalBlocklistCacheDir: t.TempDir(),
			})
			if err := d.SyncBlocklist(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := sink.count.Load(); got != tc.want {
				t.Fatalf("notifications = %d, want %d", got, tc.want)
			}
			if tc.want == 1 && !strings.Contains(sink.bodies()[0], "Neue Sperren: 7") {
				t.Fatalf("unexpected summary: %s", sink.bodies()[0])
			}
		})
	}
}

func TestReconcileFirewallUsesBatch(t *testing.T) {
	d, ex := newTestDaemon(t, &config.Config{})
	now := time.Now().Unix()
	for i := 0; i < 300; i++ {
		if err := d.Store.InsertBan(db.Ban{IP: fmt.Sprintf("10.%d.%d.1", i/250, i%250), Permanent: true, Source: "geoip", Reason: "geoip"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Store.InsertBan(db.Ban{IP: "198.51.100.1", BanUntil: now + 500, Duration: 600, Source: "monitor"}); err != nil {
		t.Fatal(err)
	}
	if err := d.reconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	inputs := ex.restoreInputs()
	if len(inputs) != 1 || len(ex.ipsetAdds()) != 0 {
		t.Fatalf("reconcile must use one batch, got %d batches and %d single adds", len(inputs), len(ex.ipsetAdds()))
	}
	if strings.Count(inputs[0], "\n") != 301 || !strings.Contains(inputs[0], "add adguard_shield_v4 198.51.100.1 timeout ") {
		t.Fatalf("unexpected batch content")
	}
}

func TestNotificationQueueDropsWhenFullAndDrains(t *testing.T) {
	d := &Daemon{Config: &config.Config{}, notifyQueueSize: 2}
	var ran atomic.Int32
	block := make(chan struct{})
	started := make(chan struct{})
	d.startNotifier()
	d.enqueueNotification("blocker", func(context.Context) {
		close(started)
		<-block
		ran.Add(1)
	})
	<-started
	for i := 0; i < 4; i++ {
		d.enqueueNotification("job", func(context.Context) { ran.Add(1) })
	}
	close(block)
	if !d.stopNotifier(2 * time.Second) {
		t.Fatal("queue must drain")
	}
	if got := ran.Load(); got != 3 {
		t.Fatalf("executed %d jobs, want 3 (blocker + 2 queued, 2 dropped)", got)
	}
	d.enqueueNotification("late", func(context.Context) { ran.Add(1) })
	if ran.Load() != 3 {
		t.Fatal("jobs after shutdown must be dropped")
	}
}

func TestNotificationQueueDrainTimeout(t *testing.T) {
	d := &Daemon{Config: &config.Config{}}
	block := make(chan struct{})
	defer close(block)
	d.startNotifier()
	d.enqueueNotification("hang", func(context.Context) { <-block })
	start := time.Now()
	if d.stopNotifier(50 * time.Millisecond) {
		t.Fatal("hanging job must hit the drain timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("drain timeout not honoured")
	}
}

func TestNotificationsRunSynchronouslyWithoutWorker(t *testing.T) {
	d := &Daemon{Config: &config.Config{}}
	ran := false
	d.enqueueNotification("cli", func(context.Context) { ran = true })
	if !ran {
		t.Fatal("without worker the job must run synchronously")
	}
}

func TestServiceStopAfterQueueDrain(t *testing.T) {
	var mu sync.Mutex
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		switch {
		case strings.Contains(string(b), "service_stop"):
			order = append(order, "stop")
		case strings.Contains(string(b), "Freigabe"):
			time.Sleep(100 * time.Millisecond)
			order = append(order, "unban")
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := &Daemon{Config: &config.Config{NotifyEnabled: true, NotifyType: "generic", NotifyWebhook: srv.URL}, Client: srv.Client()}
	d.startNotifier()
	d.notifyUnban("203.0.113.1", "manual")
	d.stopNotifier(notifyDrainTimeout)
	d.NotifyServiceStop(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "unban,stop" {
		t.Fatalf("order = %v", order)
	}
}

type fakeAGH struct {
	t        *testing.T
	times    []time.Time
	requests atomic.Int32
	olders   []string
	mu       sync.Mutex
}

func (f *fakeAGH) format(tm time.Time) string {
	return tm.In(time.FixedZone("CEST", 2*3600)).Format(time.RFC3339Nano)
}

func (f *fakeAGH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	older := r.URL.Query().Get("older_than")
	f.mu.Lock()
	f.olders = append(f.olders, older)
	f.mu.Unlock()
	start := 0
	if older != "" {
		ot, err := time.Parse(time.RFC3339Nano, older)
		if err != nil {
			http.Error(w, "bad older_than", http.StatusBadRequest)
			return
		}
		start = len(f.times)
		for i, tm := range f.times {
			if tm.Before(ot) {
				start = i
				break
			}
		}
	}
	end := min(start+limit, len(f.times))
	var items []string
	oldest := ""
	for _, tm := range f.times[start:end] {
		items = append(items, fmt.Sprintf(`{"time":%q,"client":"203.0.113.1","question":{"name":"x%d.example.com"}}`, f.format(tm), tm.UnixNano()))
		oldest = f.format(tm)
	}
	fmt.Fprintf(w, `{"data":[%s],"oldest":%q}`, strings.Join(items, ","), oldest)
}

func newFakeAGH(t *testing.T, n int, step time.Duration) (*fakeAGH, *Daemon) {
	f := &fakeAGH{t: t}
	base := time.Now().Truncate(time.Millisecond).Add(123456 * time.Nanosecond)
	for i := 0; i < n; i++ {
		f.times = append(f.times, base.Add(-time.Duration(i)*step))
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	d := &Daemon{Config: &config.Config{AdGuardURL: srv.URL + "/", APIQueryLimit: 5, RateLimitWindow: 60, SubdomainFloodWindow: 60}, Client: srv.Client()}
	return f, d
}

func TestQueryLogPaginationStopsOnShortPage(t *testing.T) {
	f, d := newFakeAGH(t, 12, time.Second)
	items, err := d.fetchQueryLogSince(context.Background(), time.Now().Add(-time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 12 || f.requests.Load() != 3 {
		t.Fatalf("items=%d requests=%d", len(items), f.requests.Load())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.olders[0] != "" || f.olders[1] != f.format(f.times[4]) || f.olders[2] != f.format(f.times[9]) {
		t.Fatalf("older_than not round-tripped exactly: %q", f.olders)
	}
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Time] {
			t.Fatalf("duplicate entry %s", it.Time)
		}
		seen[it.Time] = true
	}
}

func TestQueryLogPaginationStopsAtCutoff(t *testing.T) {
	f, d := newFakeAGH(t, 100, time.Second)
	cutoff := f.times[12]
	items, err := d.fetchQueryLogSince(context.Background(), cutoff, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 3 || len(items) != 15 {
		t.Fatalf("requests=%d items=%d, want 3/15", f.requests.Load(), len(items))
	}
}

func TestQueryLogPaginationStopsAtSeenEntries(t *testing.T) {
	f, d := newFakeAGH(t, 100, time.Second)
	items, err := d.fetchQueryLogSince(context.Background(), time.Now().Add(-time.Hour), f.times[7])
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 2 || len(items) != 10 {
		t.Fatalf("requests=%d items=%d, want 2/10", f.requests.Load(), len(items))
	}
}

func TestQueryLogPaginationHardCap(t *testing.T) {
	f, d := newFakeAGH(t, 1000, time.Millisecond)
	items, err := d.fetchQueryLogSince(context.Background(), time.Now().Add(-time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != queryLogMaxPages || len(items) != queryLogMaxPages*5 {
		t.Fatalf("requests=%d items=%d", f.requests.Load(), len(items))
	}
}

func TestPollOnceUsesPaginationAndTracksNewest(t *testing.T) {
	f, d := newFakeAGH(t, 12, time.Second)
	d.Config.RateLimitMaxRequests = 1000
	if err := d.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.events) != 12 || !d.lastNewest.Equal(f.times[0]) {
		t.Fatalf("events=%d newest=%v", len(d.events), d.lastNewest)
	}
	before := f.requests.Load()
	if err := d.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load()-before != 1 || len(d.events) != 12 {
		t.Fatalf("second poll must stop after the first page, requests=%d events=%d", f.requests.Load()-before, len(d.events))
	}
}

func TestFetchQueryLogUsesAdGuardClient(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	d := &Daemon{
		Config:        &config.Config{AdGuardURL: srv.URL, APIQueryLimit: 5},
		Client:        &http.Client{Transport: newTransport(false)},
		AdGuardClient: &http.Client{Transport: newTransport(true)},
	}
	if _, err := d.FetchQueryLog(context.Background()); err != nil {
		t.Fatalf("AdGuard client with ADGUARD_TLS_INSECURE must accept self-signed cert: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := d.Client.Do(req); err == nil {
		t.Fatal("general client must verify certificates")
	}
	d.AdGuardClient = &http.Client{Transport: newTransport(false)}
	if _, err := d.FetchQueryLog(context.Background()); err == nil {
		t.Fatal("ADGUARD_TLS_INSECURE=false must verify certificates")
	}
}

func TestRetentionPrunesHistoryAndGeoIPCache(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{HistoryRetentionDays: 30, GeoIPCacheTTL: 86400})
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour).Unix()
	for _, ep := range []int64{old, now.Unix()} {
		if _, err := d.Store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip) VALUES (?, 'x', 'BAN', '203.0.113.1')`, ep); err != nil {
			t.Fatal(err)
		}
	}
	for ip, ep := range map[string]int64{"203.0.113.1": now.Add(-2 * 24 * time.Hour).Unix(), "203.0.113.2": now.Unix()} {
		if _, err := d.Store.DB.Exec(`INSERT INTO geoip_cache (ip, country_code, looked_up_at_epoch) VALUES (?, 'DE', ?)`, ip, ep); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.runRetention(now); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, d.Store, "203.0.113.1", "BAN"); n != 1 {
		t.Fatalf("history rows = %d, want 1", n)
	}
	var geo int
	_ = d.Store.DB.QueryRow(`SELECT COUNT(*) FROM geoip_cache`).Scan(&geo)
	if geo != 1 {
		t.Fatalf("geoip cache rows = %d, want 1", geo)
	}

	d.Config.HistoryRetentionDays = 0
	if _, err := d.Store.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip) VALUES (?, 'x', 'BAN', '203.0.113.1')`, old); err != nil {
		t.Fatal(err)
	}
	if err := d.runRetention(now); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, d.Store, "203.0.113.1", "BAN"); n != 2 {
		t.Fatalf("retention 0 must keep history, rows = %d", n)
	}
}

func TestRecentLogLinesReadsTailOfLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	levels := []string{"INFO", "DEBUG", "WARN", "INFO", "ERROR"}
	const total = 60000
	for i := 0; i < total; i++ {
		fmt.Fprintf(f, "2026/10/10 12:00:00 [%s] [ADGUARD-SHIELDD] Zeile %06d %s\n", levels[i%len(levels)], i, strings.Repeat("ä", i%40))
	}
	f.Close()
	if st, _ := os.Stat(path); st.Size() < 4<<20 {
		t.Fatalf("test file too small: %d", st.Size())
	}
	lines := RecentLogLines(path, "INFO", 7)
	if len(lines) != 7 {
		t.Fatalf("got %d lines", len(lines))
	}
	var want []string
	for i := total - 1; i >= 0 && len(want) < 7; i-- {
		if levels[i%len(levels)] != "DEBUG" {
			want = append([]string{fmt.Sprintf("Zeile %06d %s", i, strings.Repeat("ä", i%40))}, want...)
		}
	}
	for i := range want {
		if !strings.HasSuffix(lines[i], want[i]) {
			t.Fatalf("line %d = %q, want suffix %q", i, lines[i], want[i])
		}
	}
	errs := RecentLogLines(path, "ERROR", 2000)
	if len(errs) != 2000 || !strings.Contains(errs[1999], fmt.Sprintf("Zeile %06d", total-1)) {
		t.Fatalf("unexpected ERROR tail: %d lines", len(errs))
	}
	for i := 1; i < len(errs); i++ {
		if errs[i-1] >= errs[i] || !strings.Contains(errs[i], "[ERROR]") {
			t.Fatalf("ERROR lines out of order or wrong level at %d", i)
		}
	}
	oldMax := logTailMaxRead
	logTailMaxRead = 1 << 20
	all := RecentLogLines(path, "DEBUG", total+10)
	logTailMaxRead = oldMax
	if len(all) == 0 || len(all) >= total {
		t.Fatalf("read must be capped, got %d lines", len(all))
	}
	if RecentLogLines(path, "off", 5) != nil || RecentLogLines(filepath.Join(t.TempDir(), "fehlt.log"), "INFO", 5) != nil {
		t.Fatal("off/missing must return nil")
	}
}

func TestRecentLogLinesSmallFileWithoutTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.log")
	if err := os.WriteFile(path, []byte("a [INFO] eins\r\n\nb [DEBUG] zwei\nc [WARN] drei"), 0640); err != nil {
		t.Fatal(err)
	}
	got := RecentLogLines(path, "INFO", 10)
	if strings.Join(got, "|") != "a [INFO] eins|c [WARN] drei" {
		t.Fatalf("got %q", got)
	}
}

func TestTrimIsRuneSafe(t *testing.T) {
	if got := trim("äöüäöü", 4); got != "äöü~" {
		t.Fatalf("got %q", got)
	}
	if got := trim("abc", 3); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := trim("äbc", 1); got != "ä" {
		t.Fatalf("got %q", got)
	}
	if got := trim("abc", 0); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestScheduleGeoIPRunsSingleBoundedBatch(t *testing.T) {
	d, _ := newTestDaemon(t, &config.Config{GeoIPEnabled: true})
	ips := make([]string, geoIPPendingMax+50)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
	}
	d.scheduleGeoIP(context.Background(), ips)
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.geoMu.Lock()
		running := d.geoRunning
		d.geoMu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("GeoIP batch did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunWritesConfigWarningsAndRotatesLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "shield.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", 2<<20)), 0640); err != nil {
		t.Fatal(err)
	}
	lf, err := syslog.OpenFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"data":[]}`) }))
	defer agh.Close()
	d, _ := newTestDaemon(t, &config.Config{
		Warnings: []string{"TEST_KEY unbekannt"}, LogMaxSizeMB: 1, CheckInterval: 1, APIQueryLimit: 5,
		RateLimitWindow: 60, SubdomainFloodWindow: 60, AdGuardURL: agh.URL, Path: filepath.Join(dir, "x.conf"),
	})
	d.LogFile = lf
	d.Logger = syslog.New(lf, "INFO")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	d.Geo = newNilGeo(dir)
	_ = d.Run(ctx)
	cur, _ := os.ReadFile(logPath)
	if !strings.Contains(string(cur), "[WARN] [ADGUARD-SHIELDD] Konfiguration: TEST_KEY unbekannt") {
		t.Fatalf("config warning not logged: %q", cur)
	}
	if len(cur) > 1<<20 {
		t.Fatal("log must have been rotated")
	}
	if st, err := os.Stat(logPath + ".1"); err != nil || st.Size() != 2<<20 {
		t.Fatal("rotated backup missing")
	}
}
