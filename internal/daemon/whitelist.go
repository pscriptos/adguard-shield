package daemon

import (
	"net/netip"
	"strings"
)

// Kürzere Whitelist-Prefixe würden praktisch eine ganze Adressfamilie freigeben.
const (
	whitelistMinBits4 = 8
	whitelistMinBits6 = 16
)

// whitelist ist nach dem Aufbau unveränderlich und wird als Ganzes ausgetauscht.
type whitelist struct {
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

// newWhitelist baut die Whitelist auf. Ungültige Einträge werden ignoriert,
// zu breite Netze (siehe whitelistPrefixOK) übersprungen und zurückgegeben,
// damit der Aufrufer warnen kann.
func newWhitelist(entries ...[]string) (*whitelist, []string) {
	w := &whitelist{addrs: map[netip.Addr]struct{}{}}
	var skipped []string
	for _, list := range entries {
		for _, e := range list {
			a, p, ok := parseTarget(e)
			if !ok {
				continue
			}
			if !p.IsValid() {
				w.addrs[a] = struct{}{}
				continue
			}
			if !whitelistPrefixOK(p) {
				skipped = append(skipped, strings.TrimSpace(e))
				continue
			}
			w.prefixes = append(w.prefixes, p)
		}
	}
	return w, skipped
}

// whitelistPrefixOK lehnt /0 und zu breite Netze ab (IPv4 kürzer als /8,
// IPv6 kürzer als /16; geprüft nach dem Entpacken IPv4-mapped Adressen).
func whitelistPrefixOK(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() >= whitelistMinBits4
	}
	return p.Bits() >= whitelistMinBits6
}

// whitelistEntryOK prüft einen Rohwert wie newWhitelist (gültig und nicht zu breit).
func whitelistEntryOK(s string) bool {
	_, p, ok := parseTarget(s)
	return ok && (!p.IsValid() || whitelistPrefixOK(p))
}

func (w *whitelist) size() int {
	if w == nil {
		return 0
	}
	return len(w.addrs) + len(w.prefixes)
}

// contains prüft eine IP oder ein Netz. Ein Netz gilt als gewhitelistet, sobald
// es eine gewhitelistete Adresse oder ein gewhitelistetes Netz überlappt.
func (w *whitelist) contains(s string) bool {
	if w == nil {
		return false
	}
	a, p, ok := parseTarget(s)
	if !ok {
		return false
	}
	if !p.IsValid() {
		if _, ok := w.addrs[a]; ok {
			return true
		}
		for _, wp := range w.prefixes {
			if wp.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, wp := range w.prefixes {
		if wp.Overlaps(p) {
			return true
		}
	}
	for wa := range w.addrs {
		if p.Contains(wa) {
			return true
		}
	}
	return false
}

// parseTarget normalisiert eine IP (Zone entfernt, IPv4-mapped IPv6 entpackt)
// oder ein Netz (maskiert). IPv4-mapped Netze werden nur ab /96 entpackt, ein
// kürzeres Netz bleibt ein IPv6-Netz. Bei einer Adresse ist der
// Prefix-Rückgabewert ungültig.
func parseTarget(s string) (netip.Addr, netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, netip.Prefix{}, false
		}
		a, bits := p.Addr(), p.Bits()
		if a.Is4In6() && bits >= 96 {
			a, bits = a.Unmap(), bits-96
		}
		p, err = a.Prefix(bits)
		if err != nil {
			return netip.Addr{}, netip.Prefix{}, false
		}
		return netip.Addr{}, p, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, false
	}
	return a.WithZone("").Unmap(), netip.Prefix{}, true
}

// normalizeTarget liefert die kanonische Schreibweise einer IP oder eines Netzes.
func normalizeTarget(s string) (string, bool) {
	a, p, ok := parseTarget(s)
	if !ok {
		return "", false
	}
	if p.IsValid() {
		return p.String(), true
	}
	return a.String(), true
}
