package geoip

import "testing"

type fakeGeoIPStore struct {
	ip      string
	country string
	mtime   int64
}

func (s *fakeGeoIPStore) LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *fakeGeoIPStore) UpsertGeoIP(ip, country string, dbMtime int64) error {
	s.ip = ip
	s.country = country
	s.mtime = dbMtime
	return nil
}

func TestShouldBlockModes(t *testing.T) {
	countries := []string{"CN", "RU"}
	if !ShouldBlock("cn", "blocklist", countries) {
		t.Fatal("blocklist should block listed country")
	}
	if ShouldBlock("DE", "blocklist", countries) {
		t.Fatal("blocklist should allow unlisted country")
	}
	if ShouldBlock("CN", "allowlist", countries) {
		t.Fatal("allowlist should allow listed country")
	}
	if !ShouldBlock("DE", "allowlist", countries) {
		t.Fatal("allowlist should block unlisted country")
	}
}

func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "192.168.1.10", "10.1.2.3", "100.64.0.1", "::1", "fd00::1"} {
		if !IsPrivateIP(ip) {
			t.Fatalf("%s should be private", ip)
		}
	}
	if IsPrivateIP("8.8.8.8") {
		t.Fatal("8.8.8.8 should be public")
	}
}

func TestStoreCachePersistsLegacyLookupResult(t *testing.T) {
	store := &fakeGeoIPStore{}
	r := New("", "", "", 86400, store)
	r.mtime = 123

	r.storeCache("203.0.113.7", "cn")

	if got := r.cache["203.0.113.7"]; got != "CN" {
		t.Fatalf("cache = %q, want CN", got)
	}
	if store.ip != "203.0.113.7" || store.country != "CN" || store.mtime != 123 {
		t.Fatalf("store got ip=%q country=%q mtime=%d", store.ip, store.country, store.mtime)
	}
}
