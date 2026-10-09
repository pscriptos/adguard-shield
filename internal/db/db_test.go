package db

import (
	"path/filepath"
	"testing"
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
