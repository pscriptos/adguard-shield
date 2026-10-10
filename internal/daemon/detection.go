package daemon

import (
	"context"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type queryEvent struct {
	At       time.Time
	Client   string
	Domain   string
	Protocol string
}

func (d *Daemon) analysisCutoff(now time.Time) time.Time {
	maxWindow := max(d.Config.RateLimitWindow, d.Config.SubdomainFloodWindow)
	return now.Add(-time.Duration(maxWindow+30) * time.Second)
}

func (d *Daemon) pollOnce(ctx context.Context) error {
	d.mu.Lock()
	seenUntil := d.lastNewest
	d.mu.Unlock()
	entries, err := d.fetchQueryLogSince(ctx, d.analysisCutoff(time.Now()), seenUntil)
	if err != nil {
		d.mu.Lock()
		d.lastPollErr, d.lastPollErrAt = err.Error(), time.Now()
		d.mu.Unlock()
		return err
	}
	events := d.toEvents(entries)
	var geoIPs []string
	geoSet := map[string]bool{}
	d.mu.Lock()
	d.lastPollAt, d.lastPollEntries = time.Now(), len(entries)
	if d.seen == nil {
		d.seen = map[string]time.Time{}
	}
	for _, ev := range events {
		key := ev.At.Format(time.RFC3339Nano) + "|" + ev.Client + "|" + ev.Domain + "|" + ev.Protocol
		if _, ok := d.seen[key]; ok {
			continue
		}
		d.seen[key] = ev.At
		d.events = append(d.events, ev)
		if ev.At.After(d.lastNewest) {
			d.lastNewest = ev.At
		}
		if d.Config.GeoIPEnabled && !geoSet[ev.Client] {
			geoSet[ev.Client] = true
			geoIPs = append(geoIPs, ev.Client)
		}
	}
	d.pruneLocked()
	snapshot := append([]queryEvent(nil), d.events...)
	d.mu.Unlock()
	d.scheduleGeoIP(ctx, geoIPs)
	return d.analyze(ctx, snapshot)
}

func (d *Daemon) toEvents(items []queryItem) []queryEvent {
	var out []queryEvent
	for _, it := range items {
		t, err := parseAGHTime(it.Time)
		if err != nil {
			continue
		}
		client := strings.TrimSpace(it.Client)
		if client == "" {
			client = strings.TrimSpace(it.ClientInfo.IP)
		}
		domain := strings.TrimSuffix(strings.ToLower(firstNonEmpty(it.Question.Name, it.Question.Host)), ".")
		if client == "" || domain == "" {
			continue
		}
		proto := it.ClientProto
		if proto == "" {
			proto = "dns"
		}
		out = append(out, queryEvent{At: t, Client: client, Domain: domain, Protocol: proto})
	}
	return out
}

func (d *Daemon) ToEventsForCommand(items []queryItem) []string {
	seen := map[string]bool{}
	var out []string
	for _, ev := range d.toEvents(items) {
		if seen[ev.Client] {
			continue
		}
		seen[ev.Client] = true
		out = append(out, ev.Client)
	}
	return out
}

func parseAGHTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (d *Daemon) pruneLocked() {
	cut := d.analysisCutoff(time.Now())
	var kept []queryEvent
	for _, ev := range d.events {
		if ev.At.After(cut) {
			kept = append(kept, ev)
		}
	}
	d.events = kept
	for k, t := range d.seen {
		if t.Before(cut) {
			delete(d.seen, k)
		}
	}
}

func (d *Daemon) analyze(ctx context.Context, events []queryEvent) error {
	now := time.Now()
	rateCut := now.Add(-time.Duration(d.Config.RateLimitWindow) * time.Second)
	counts := map[string]int{}
	protos := map[string]string{}
	for _, ev := range events {
		if ev.At.Before(rateCut) {
			continue
		}
		key := ev.Client + "|" + ev.Domain
		counts[key]++
		protos[key] = ev.Protocol
	}
	for key, count := range counts {
		if count <= d.Config.RateLimitMaxRequests {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		reason := "rate-limit"
		if d.watchlisted(parts[1]) {
			reason = "dns-flood-watchlist"
		}
		perm := reason == "dns-flood-watchlist"
		if err := d.Ban(ctx, BanRequest{IP: parts[0], Domain: parts[1], Count: count, Protocol: protos[key], Reason: reason, Source: "monitor", Permanent: perm}); err != nil {
			d.error("Ban Fehler: %v", err)
		}
	}
	if d.Config.SubdomainFloodEnabled {
		d.analyzeSubdomains(ctx, events, now)
	}
	return nil
}

func (d *Daemon) analyzeSubdomains(ctx context.Context, events []queryEvent, now time.Time) {
	cut := now.Add(-time.Duration(d.Config.SubdomainFloodWindow) * time.Second)
	sets := map[string]map[string]bool{}
	for _, ev := range events {
		if ev.At.Before(cut) {
			continue
		}
		base := baseDomain(ev.Domain)
		if base == "" || base == ev.Domain {
			continue
		}
		key := ev.Client + "|" + base
		if sets[key] == nil {
			sets[key] = map[string]bool{}
		}
		sets[key][ev.Domain] = true
	}
	for key, set := range sets {
		if len(set) <= d.Config.SubdomainFloodMaxUnique {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		reason := "subdomain-flood"
		perm := d.watchlisted(parts[1])
		if perm {
			reason = "dns-flood-watchlist"
		}
		if err := d.Ban(ctx, BanRequest{IP: parts[0], Domain: "*." + parts[1], Count: len(set), Protocol: "dns", Reason: reason, Source: "monitor", Permanent: perm}); err != nil {
			d.error("Ban Fehler: %v", err)
		}
	}
}

func (d *Daemon) watchlisted(domain string) bool {
	if !d.Config.DNSFloodWatchlistEnabled {
		return false
	}
	for _, w := range d.Config.DNSFloodWatchlist {
		w = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(w)), ".")
		if domain == w || strings.HasSuffix(domain, "."+w) {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// baseDomain liefert die registrierbare Domain (eTLD+1) laut Public Suffix
// List. Private Suffixe (github.io, cloudfront.net, ...) zählen dabei als
// öffentlich, damit CDN-Subdomains nicht als Subdomain-Flood gelten.
func baseDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return base
}
