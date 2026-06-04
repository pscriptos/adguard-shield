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
