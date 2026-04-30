package geoip

import "testing"

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
