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
