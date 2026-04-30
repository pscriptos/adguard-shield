package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"adguard-shield/internal/db"
	"adguard-shield/internal/syslog"
)

type LiveOptions struct {
	Interval time.Duration
	Top      int
	Recent   int
	LogLevel string
	Once     bool
}

type liveSnapshot struct {
	At              time.Time
	APIEntries      int
	Window          int
	Limit           int
	Events          []queryEvent
	TopPairs        []liveCount
	SubdomainGroups []liveCount
	ActiveBans      []db.Ban
	Offenses        int
	ExpiredOffenses int
	WhitelistCount  int
	BlocklistBans   int
	SystemLogs      []string
}

type liveCount struct {
	Client   string
	Domain   string
	Count    int
	Protocol string
}

func (d *Daemon) Live(ctx context.Context, w io.Writer, opts LiveOptions) error {
	if opts.Interval <= 0 {
		opts.Interval = time.Duration(d.Config.CheckInterval) * time.Second
	}
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.Top <= 0 {
		opts.Top = 10
	}
	if opts.Recent <= 0 {
		opts.Recent = 12
	}
	if strings.TrimSpace(opts.LogLevel) == "" {
		opts.LogLevel = "INFO"
	}

	for {
		snap, err := d.liveSnapshot(ctx, opts)
		renderLive(w, d, snap, err, opts)
		if opts.Once {
			return err
		}
		timer := time.NewTimer(opts.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *Daemon) liveSnapshot(ctx context.Context, opts LiveOptions) (liveSnapshot, error) {
	snap := liveSnapshot{
		At:     time.Now(),
		Window: d.Config.RateLimitWindow,
		Limit:  d.Config.RateLimitMaxRequests,
	}
	items, err := d.FetchQueryLog(ctx)
	if err != nil {
		return snap, err
	}
	snap.APIEntries = len(items)
	events := dedupeEvents(d.toEvents(items))
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	if len(events) > opts.Recent {
		snap.Events = append([]queryEvent(nil), events[:opts.Recent]...)
	} else {
		snap.Events = append([]queryEvent(nil), events...)
	}
	snap.TopPairs = topQueryPairs(events, d.Config.RateLimitWindow, opts.Top)
	snap.SubdomainGroups = topSubdomainGroups(events, d.Config.SubdomainFloodWindow, opts.Top)

	if bans, err := d.Store.ActiveBans(); err == nil {
		snap.ActiveBans = bans
	}
	if n, err := d.Store.CountOffenses(); err == nil {
		snap.Offenses = n
	}
	if n, err := d.Store.CountExpiredOffenses(d.Config.ProgressiveBanResetAfter); err == nil {
		snap.ExpiredOffenses = n
	}
	if wl, err := d.Store.AllWhitelist(); err == nil {
		snap.WhitelistCount = len(wl)
	}
	if n, err := d.Store.CountBySource("external-blocklist"); err == nil {
		snap.BlocklistBans = n
	}
	snap.SystemLogs = RecentLogLines(d.Config.LogFile, opts.LogLevel, opts.Recent)
	return snap, nil
}

func dedupeEvents(events []queryEvent) []queryEvent {
	seen := map[string]bool{}
	out := make([]queryEvent, 0, len(events))
	for _, ev := range events {
		key := ev.At.Format(time.RFC3339Nano) + "|" + ev.Client + "|" + ev.Domain + "|" + ev.Protocol
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ev)
	}
	return out
}

func topQueryPairs(events []queryEvent, window, limit int) []liveCount {
	cut := time.Now().Add(-time.Duration(window) * time.Second)
	counts := map[string]*liveCount{}
	protos := map[string]map[string]bool{}
	for _, ev := range events {
		if ev.At.Before(cut) {
			continue
		}
		key := ev.Client + "|" + ev.Domain
		if counts[key] == nil {
			counts[key] = &liveCount{Client: ev.Client, Domain: ev.Domain}
			protos[key] = map[string]bool{}
		}
		counts[key].Count++
		protos[key][formatProtocol(ev.Protocol)] = true
	}
	out := make([]liveCount, 0, len(counts))
	for key, item := range counts {
		item.Protocol = strings.Join(sortedKeys(protos[key]), ",")
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Client+"|"+out[i].Domain < out[j].Client+"|"+out[j].Domain
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func topSubdomainGroups(events []queryEvent, window, limit int) []liveCount {
	cut := time.Now().Add(-time.Duration(window) * time.Second)
	sets := map[string]map[string]bool{}
	protos := map[string]map[string]bool{}
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
			protos[key] = map[string]bool{}
		}
		sets[key][ev.Domain] = true
		protos[key][formatProtocol(ev.Protocol)] = true
	}
	out := make([]liveCount, 0, len(sets))
	for key, set := range sets {
		client, domain, _ := strings.Cut(key, "|")
		out = append(out, liveCount{
			Client:   client,
			Domain:   domain,
			Count:    len(set),
			Protocol: strings.Join(sortedKeys(protos[key]), ","),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Client+"|"+out[i].Domain < out[j].Client+"|"+out[j].Domain
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func renderLive(w io.Writer, d *Daemon, snap liveSnapshot, snapErr error, opts LiveOptions) {
	fmt.Fprint(w, "\033[H\033[2J")
	fmt.Fprintf(w, "AdGuard Shield Live | %s | Strg+C beendet\n", snap.At.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, strings.Repeat("=", 92))
	fmt.Fprintf(w, "Config: %s | API: %s | Log: %s (ab %s)\n", d.Config.Path, d.Config.AdGuardURL, d.Config.LogFile, strings.ToUpper(opts.LogLevel))
	if snapErr != nil {
		fmt.Fprintf(w, "\nFEHLER: Live-Snapshot konnte nicht geladen werden: %v\n", snapErr)
		return
	}

	fmt.Fprintf(w, "\nWorker und Module\n")
	fmt.Fprintf(w, "  Query-Poller: alle %ds | API-Eintraege: %d | Zeitfenster: %ds | Limit: %d\n", d.Config.CheckInterval, snap.APIEntries, snap.Window, snap.Limit)
	fmt.Fprintf(w, "  GeoIP: %s | Modus: %s | Laender: %s\n", enabled(d.Config.GeoIPEnabled), d.Config.GeoIPMode, listOrDash(d.Config.GeoIPCountries))
	fmt.Fprintf(w, "  Externe Blocklist: %s | Intervall: %ds | URLs: %d | aktive Sperren: %d\n", enabled(d.Config.ExternalBlocklistEnabled), d.Config.ExternalBlocklistInterval, len(d.Config.ExternalBlocklistURLs), snap.BlocklistBans)
	fmt.Fprintf(w, "  Externe Whitelist: %s | Intervall: %ds | URLs: %d | aufgeloeste IPs: %d\n", enabled(d.Config.ExternalWhitelistEnabled), d.Config.ExternalWhitelistInterval, len(d.Config.ExternalWhitelistURLs), snap.WhitelistCount)
	fmt.Fprintf(w, "  Offense-Cleanup: %s | Zaehler: %d | davon abgelaufen: %d\n", enabled(d.Config.ProgressiveBanEnabled), snap.Offenses, snap.ExpiredOffenses)

	fmt.Fprintf(w, "\nTop Client/Domain im Rate-Limit-Fenster\n")
	if len(snap.TopPairs) == 0 {
		fmt.Fprintln(w, "  Keine Anfragen im aktuellen Zeitfenster.")
	} else {
		for _, item := range snap.TopPairs {
			fmt.Fprintf(w, "  %5s  %-39s  %-34s  %s\n", fmt.Sprintf("%d/%d", item.Count, snap.Limit), trim(item.Client, 39), trim(item.Domain, 34), item.Protocol)
		}
	}

	if d.Config.SubdomainFloodEnabled {
		fmt.Fprintf(w, "\nSubdomain-Flood-Kandidaten\n")
		if len(snap.SubdomainGroups) == 0 {
			fmt.Fprintln(w, "  Keine Subdomain-Gruppen im aktuellen Zeitfenster.")
		} else {
			for _, item := range snap.SubdomainGroups {
				fmt.Fprintf(w, "  %5s  %-39s  %-34s  %s\n", fmt.Sprintf("%d/%d", item.Count, d.Config.SubdomainFloodMaxUnique), trim(item.Client, 39), trim(item.Domain, 34), item.Protocol)
			}
		}
	}

	fmt.Fprintf(w, "\nLetzte Queries\n")
	if len(snap.Events) == 0 {
		fmt.Fprintln(w, "  Keine Querylog-Eintraege gefunden.")
	} else {
		for _, ev := range snap.Events {
			fmt.Fprintf(w, "  %s  %-39s  %-8s  %s\n", ev.At.Local().Format("15:04:05"), trim(ev.Client, 39), formatProtocol(ev.Protocol), trim(ev.Domain, 44))
		}
	}

	fmt.Fprintf(w, "\nAktive Sperren\n")
	if len(snap.ActiveBans) == 0 {
		fmt.Fprintln(w, "  Keine aktiven Sperren.")
	} else {
		maxBans := opts.Top
		if len(snap.ActiveBans) < maxBans {
			maxBans = len(snap.ActiveBans)
		}
		for _, b := range snap.ActiveBans[:maxBans] {
			fmt.Fprintf(w, "  %-39s  %-20s  %-18s  %s\n", trim(b.IP, 39), trim(b.Source, 20), trim(b.Reason, 18), banUntil(b))
		}
		if len(snap.ActiveBans) > maxBans {
			fmt.Fprintf(w, "  ... %d weitere\n", len(snap.ActiveBans)-maxBans)
		}
	}

	if strings.ToLower(opts.LogLevel) != "off" {
		fmt.Fprintf(w, "\nSystemereignisse\n")
		if len(snap.SystemLogs) == 0 {
			fmt.Fprintln(w, "  Keine passenden Logeintraege.")
		} else {
			for _, line := range snap.SystemLogs {
				fmt.Fprintf(w, "  %s\n", trim(line, 88))
			}
		}
	}
}

func RecentLogLines(path, minLevel string, limit int) []string {
	if strings.EqualFold(strings.TrimSpace(minLevel), "off") || path == "" || limit <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	min := syslog.ParseLevel(minLevel, syslog.Info)
	ring := make([]string, limit)
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if logLineLevel(line) < min {
			continue
		}
		ring[count%limit] = line
		count++
	}
	n := count
	if n > limit {
		n = limit
	}
	out := make([]string, 0, n)
	start := count - n
	for i := 0; i < n; i++ {
		out = append(out, ring[(start+i)%limit])
	}
	return out
}

func logLineLevel(line string) syslog.Level {
	for _, level := range []syslog.Level{syslog.Error, syslog.Warn, syslog.Info, syslog.Debug} {
		if strings.Contains(line, "["+syslog.LevelName(level)+"]") {
			return level
		}
	}
	return syslog.Info
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func formatProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "doh":
		return "DoH"
	case "dot":
		return "DoT"
	case "doq":
		return "DoQ"
	case "dnscrypt":
		return "DNSCrypt"
	case "", "dns":
		return "DNS"
	default:
		return proto
	}
}

func enabled(ok bool) string {
	if ok {
		return "aktiv"
	}
	return "inaktiv"
}

func listOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ",")
}

func trim(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "~"
}

func banUntil(b db.Ban) string {
	if b.Permanent || b.BanUntil == 0 {
		return "permanent"
	}
	return time.Unix(b.BanUntil, 0).Format("2006-01-02 15:04:05")
}
