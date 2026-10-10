package db

import (
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStoreBanAndGeoIPCache(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.InsertBan(Ban{IP: "1.2.3.4", Domain: "example.com", Permanent: true, Reason: "geoip", Source: "geoip", GeoIPCountry: "CN"}); err != nil {
		t.Fatal(err)
	}
	ok, err := s.BanExists("1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("ban not found: %v %v", ok, err)
	}
	if err := s.UpsertGeoIP("1.2.3.4", "CN", 123); err != nil {
		t.Fatal(err)
	}
	cache, err := s.LoadGeoIPCache(86400, 123)
	if err != nil {
		t.Fatal(err)
	}
	if cache["1.2.3.4"] != "CN" {
		t.Fatalf("unexpected cache: %#v", cache)
	}
}

func TestLoadGeoIPCacheZeroTTLLoadsAll(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.DB.Exec(`INSERT INTO geoip_cache (ip, country_code, looked_up_at_epoch, db_mtime) VALUES ('1.2.3.4', 'CN', 1000, 0)`); err != nil {
		t.Fatal(err)
	}
	if cache, err := s.LoadGeoIPCache(86400, 123); err != nil || len(cache) != 0 {
		t.Fatalf("old entry must expire with ttl>0: %v %v", cache, err)
	}
	cache, err := s.LoadGeoIPCache(0, 123)
	if err != nil || cache["1.2.3.4"] != "CN" {
		t.Fatalf("ttl=0 must load all entries: %v %v", cache, err)
	}
}

func TestStoreIPStatusQueries(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ban := Ban{
		IP:           "192.0.2.10",
		Domain:       "example.com",
		Count:        42,
		BanUntil:     1234567890,
		Duration:     600,
		OffenseLevel: 2,
		Reason:       "rate-limit",
		Protocol:     "dns",
		Source:       "monitor",
	}
	if err := s.InsertBan(ban); err != nil {
		t.Fatal(err)
	}
	gotBan, ok, err := s.BanByIP("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotBan.IP != ban.IP || gotBan.Count != ban.Count || gotBan.Reason != ban.Reason {
		t.Fatalf("unexpected ban lookup: %#v found=%v", gotBan, ok)
	}
	if _, ok, err := s.BanByIP("192.0.2.11"); err != nil || ok {
		t.Fatalf("unexpected missing ban lookup: found=%v err=%v", ok, err)
	}

	if _, err := s.DB.Exec(`INSERT INTO whitelist_cache (ip_address, source) VALUES (?, ?)`, "192.0.2.10", "external"); err != nil {
		t.Fatal(err)
	}
	wl, ok, err := s.WhitelistByIP("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || wl.Source != "external" {
		t.Fatalf("unexpected whitelist lookup: %#v found=%v", wl, ok)
	}

	if _, err := s.IncrementOffense("192.0.2.10", 86400); err != nil {
		t.Fatal(err)
	}
	offense, ok, err := s.OffenseByIP("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || offense.Level != 1 || offense.LastEpoch == 0 {
		t.Fatalf("unexpected offense lookup: %#v found=%v", offense, ok)
	}

	if err := s.UpsertGeoIP("192.0.2.10", "DE", 456); err != nil {
		t.Fatal(err)
	}
	geo, ok, err := s.GeoIPCacheByIP("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || geo.CountryCode != "DE" || geo.DBMtime != 456 {
		t.Fatalf("unexpected geo lookup: %#v found=%v", geo, ok)
	}

	if err := s.History("BAN", "192.0.2.10", "example.com", "42", "600s", "dns", "rate-limit"); err != nil {
		t.Fatal(err)
	}
	history, err := s.RecentHistoryByIP("192.0.2.10", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("unexpected history: %#v", history)
	}
}

func TestReportStatsAttackTypesAndFilters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows := []struct {
		action, ip, domain, duration, proto, reason string
	}{
		{"BAN", "192.0.2.1", "a.example", "600s", "dns", "rate-limit"},
		{"BAN", "192.0.2.2", "*.b.example", "600s", "dns", "subdomain-flood"},
		{"BAN", "192.0.2.3", "c.example", "permanent", "doh", "dns-flood-watchlist"},
		{"BAN", "192.0.2.4", "-", "permanent", "-", "external-blocklist"},
		{"BAN", "192.0.2.5", "GeoIP:CN", "permanent", "-", "geoip"},
		{"BAN", "192.0.2.6", "GeoIP:RU", "permanent", "-", "geoip"},
		{"BAN", "192.0.2.7", "manual", "permanent", "-", "manual"},
		{"BAN", "192.0.2.8", "d.example", "600s", "DNS", "legacy-reason"},
		{"DRY", "192.0.2.9", "e.example", "dry-run", "dns", "dry-run (rate-limit)"},
		{"UNBAN", "192.0.2.1", "-", "-", "-", "expired"},
	}
	for i, r := range rows {
		if _, err := s.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (?, '2026-09-15 12:00:00', ?, ?, ?, '1', ?, ?, ?)`,
			int64(1000+i), r.action, r.ip, r.domain, r.duration, r.proto, r.reason); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.ReportStats(1000, 2000, 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalBans != 8 || st.TotalUnbans != 1 {
		t.Fatalf("totals: bans=%d unbans=%d", st.TotalBans, st.TotalUnbans)
	}
	got := []int{st.RateLimitBans, st.SubdomainFloodBans, st.WatchlistBans, st.ExternalBlocklistBans, st.GeoIPBans, st.ManualBans, st.OtherBans}
	want := []int{1, 1, 1, 1, 2, 1, 1}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("attack types = %v, want %v", got, want)
		}
	}
	sum := 0
	for _, v := range got {
		sum += v
	}
	if sum != st.TotalBans {
		t.Fatalf("attack type sum %d != total %d", sum, st.TotalBans)
	}
	for _, d := range st.TopDomains {
		if d.Name == "GeoIP:CN" || d.Name == "GeoIP:RU" || d.Name == "manual" || d.Name == "-" {
			t.Fatalf("placeholder domain in top domains: %#v", st.TopDomains)
		}
	}
	if len(st.TopDomains) != 4 {
		t.Fatalf("unexpected top domains: %#v", st.TopDomains)
	}
	protocols := map[string]int{}
	for _, p := range st.Protocols {
		protocols[p.Name] = p.Count
	}
	if protocols["n/a"] != 4 || protocols["dns"] != 3 || protocols["doh"] != 1 || len(protocols) != 3 {
		t.Fatalf("unexpected protocols: %#v", st.Protocols)
	}
}

func TestAbuseIPDBReportStats(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	count, first, err := s.AbuseIPDBReportStats(0, 1<<40)
	if err != nil || count != 0 || first != 0 {
		t.Fatalf("empty table: count=%d first=%d err=%v", count, first, err)
	}
	if err := s.RecordAbuseIPDBReport("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO abuseipdb_reports (timestamp_epoch, timestamp_text, client_ip) VALUES (500, 'x', '192.0.2.2')`); err != nil {
		t.Fatal(err)
	}
	count, first, err = s.AbuseIPDBReportStats(400, 600)
	if err != nil || count != 1 || first != 500 {
		t.Fatalf("window: count=%d first=%d err=%v", count, first, err)
	}
	count, _, err = s.AbuseIPDBReportStats(0, 1<<40)
	if err != nil || count != 2 {
		t.Fatalf("all: count=%d err=%v", count, err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBanQueriesShareScan(t *testing.T) {
	s := openTestStore(t)
	for i, b := range []Ban{
		{IP: "192.0.2.1", Reason: "rate-limit", Source: "monitor", Permanent: true, GeoIPCountry: "DE"},
		{IP: "192.0.2.2", Reason: "geoip", Source: "geoip"},
		{IP: "192.0.2.3", Reason: "geoip", Source: "geoip"},
	} {
		if err := s.InsertBan(b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`UPDATE active_bans SET created_at=? WHERE client_ip=?`, "2026-01-01 00:00:0"+strconv.Itoa(i), b.IP); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ActiveBans()
	if err != nil || len(all) != 3 || all[0].IP != "192.0.2.3" || !all[2].Permanent || all[2].GeoIPCountry != "DE" {
		t.Fatalf("ActiveBans = %#v, %v", all, err)
	}
	recent, err := s.RecentActiveBans(2)
	if err != nil || len(recent) != 2 || recent[0].IP != "192.0.2.3" || recent[1].IP != "192.0.2.2" {
		t.Fatalf("RecentActiveBans = %#v, %v", recent, err)
	}
	if n, err := s.CountActiveBans(); err != nil || n != 3 {
		t.Fatalf("CountActiveBans = %d, %v", n, err)
	}
	if bans, err := s.BansBySource("geoip"); err != nil || len(bans) != 2 {
		t.Fatalf("BansBySource = %#v, %v", bans, err)
	}
	if bans, err := s.BansByReason("rate-limit"); err != nil || len(bans) != 1 || bans[0].IP != "192.0.2.1" {
		t.Fatalf("BansByReason = %#v, %v", bans, err)
	}
}

func TestInsertBanIfAbsent(t *testing.T) {
	s := openTestStore(t)
	ok, err := s.InsertBanIfAbsent(Ban{IP: "192.0.2.1", Reason: "rate-limit", Count: 5})
	if err != nil || !ok {
		t.Fatalf("first insert: %v %v", ok, err)
	}
	ok, err = s.InsertBanIfAbsent(Ban{IP: "192.0.2.1", Reason: "geoip", Count: 9})
	if err != nil || ok {
		t.Fatalf("second insert: %v %v", ok, err)
	}
	b, _, err := s.BanByIP("192.0.2.1")
	if err != nil || b.Reason != "rate-limit" || b.Count != 5 {
		t.Fatalf("existing ban overwritten: %#v %v", b, err)
	}

	// Parallele Aufrufe: genau einer darf die Sperre anlegen.
	var wg sync.WaitGroup
	var mu sync.Mutex
	inserted := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.InsertBanIfAbsent(Ban{IP: "192.0.2.2"})
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				inserted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if inserted != 1 {
		t.Fatalf("inserted %d times, want 1", inserted)
	}
}

func TestIncrementOffenseLevelsAndReset(t *testing.T) {
	s := openTestStore(t)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.Local)
	step := func(at time.Time, want int) {
		t.Helper()
		got, err := s.incrementOffenseAt("192.0.2.1", 3600, at)
		if err != nil || got != want {
			t.Fatalf("level at %s = %d, %v; want %d", at.Format("15:04:05"), got, err, want)
		}
	}
	step(base, 1)
	step(base.Add(10*time.Minute), 2)
	step(base.Add(70*time.Minute), 3) // genau 3600s Abstand: noch kein Reset
	o, _, _ := s.OffenseByIP("192.0.2.1")
	if o.First != base.Format("2006-01-02 15:04:05") || o.LastEpoch != base.Add(70*time.Minute).Unix() {
		t.Fatalf("unexpected offense: %#v", o)
	}
	reset := base.Add(70*time.Minute + time.Hour + time.Second)
	step(reset, 1)
	o, _, _ = s.OffenseByIP("192.0.2.1")
	if o.Level != 1 || o.First != reset.Format("2006-01-02 15:04:05") || o.Last != o.First {
		t.Fatalf("unexpected offense after reset: %#v", o)
	}
	step(reset.Add(time.Second), 2)

	// Altbestand ohne last_offense_epoch wird nicht zurückgesetzt.
	if _, err := s.DB.Exec(`INSERT INTO offense_tracking (client_ip, offense_level, first_offense) VALUES ('192.0.2.9', 4, 'alt')`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.incrementOffenseAt("192.0.2.9", 60, base); err != nil || got != 5 {
		t.Fatalf("legacy row level = %d, %v", got, err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.IncrementOffense("192.0.2.50", 86400); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if o, _, _ := s.OffenseByIP("192.0.2.50"); o.Level != 20 {
		t.Fatalf("concurrent increments lost: level=%d", o.Level)
	}
}

func TestPruneHistoryAndGeoIPCache(t *testing.T) {
	s := openTestStore(t)
	for _, ts := range []int64{100, 200, 300} {
		if _, err := s.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip) VALUES (?, 'x', 'BAN', '192.0.2.1')`, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`INSERT INTO abuseipdb_reports (timestamp_epoch, timestamp_text, client_ip) VALUES (?, 'x', '192.0.2.1')`, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`INSERT INTO geoip_cache (ip, country_code, looked_up_at_epoch) VALUES (?, 'DE', ?)`, "192.0.2."+strconv.FormatInt(ts, 10), ts); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneHistory(250)
	if err != nil || n != 4 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	var left int
	if err := s.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM ban_history) + (SELECT COUNT(*) FROM abuseipdb_reports)`).Scan(&left); err != nil || left != 2 {
		t.Fatalf("rows left = %d, %v", left, err)
	}
	n, err = s.PruneGeoIPCache(200)
	if err != nil || n != 1 {
		t.Fatalf("PruneGeoIPCache = %d, %v", n, err)
	}
	if _, ok, _ := s.GeoIPCacheByIP("192.0.2.200"); !ok {
		t.Fatal("entry at cutoff must be kept")
	}
}

func TestMigrationsUpgradeLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Zustand einer älteren Version herstellen: nur Schema-Version 1.
	if _, err := s.DB.Exec(`DELETE FROM schema_version WHERE version > 1; DROP INDEX idx_bans_created; DROP INDEX idx_history_action_timestamp;`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	want := migrations[len(migrations)-1].version
	for i := 0; i < 2; i++ {
		s, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.SchemaVersion()
		if err != nil || v != want {
			t.Fatalf("schema version = %d, %v; want %d", v, err, want)
		}
		var rows, idx int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_bans_created', 'idx_history_action_timestamp')`).Scan(&idx); err != nil {
			t.Fatal(err)
		}
		if rows != want || idx != 2 {
			t.Fatalf("open %d: version rows=%d indexes=%d", i, rows, idx)
		}
		s.Close()
	}
}

func TestPeriodSummaryMatchesReportStats(t *testing.T) {
	s := openTestStore(t)
	rows := []struct{ action, ip, duration string }{
		{"BAN", "192.0.2.1", "600s"},
		{"BAN", "192.0.2.1", "PERMANENT"},
		{"BAN", "192.0.2.2", "permanent"},
		{"UNBAN", "192.0.2.1", "-"},
		{"DRY", "192.0.2.3", "permanent"},
		{"UNBAN", "192.0.2.4", ""},
	}
	for i, r := range rows {
		if _, err := s.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, duration) VALUES (?, '2026-09-15 12:00:00', ?, ?, ?)`, int64(i), r.action, r.ip, r.duration); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range [][2]int64{{0, 100}, {0, 0}, {1, 3}, {200, 300}} {
		full, err := s.ReportStats(w[0], w[1], w[0], 10)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := s.PeriodSummary(w[0], w[1])
		if err != nil {
			t.Fatal(err)
		}
		got := []int{sum.TotalBans, sum.TotalUnbans, sum.UniqueIPs, sum.PermanentBans}
		want := []int{full.TotalBans, full.TotalUnbans, full.UniqueIPs, full.PermanentBans}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("window %v: summary %v != report stats %v", w, got, want)
			}
		}
	}
	sum, _ := s.PeriodSummary(0, 100)
	if sum.TotalBans != 3 || sum.TotalUnbans != 2 || sum.UniqueIPs != 2 || sum.PermanentBans != 2 {
		t.Fatalf("unexpected summary: %#v", sum)
	}
}

func TestReportStatsSourcesWithZeroWindow(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertBan(Ban{IP: "192.0.2.1", Source: "monitor"}); err != nil {
		t.Fatal(err)
	}
	st, err := s.ReportStats(0, 0, 0, 10)
	if err != nil || len(st.Sources) != 1 || st.Sources[0].Name != "monitor" {
		t.Fatalf("sources = %#v, %v", st.Sources, err)
	}
}
