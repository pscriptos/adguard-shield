package daemon

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/web"
)

const (
	webListLimit   = 15
	webTopLimit    = 10
	webSecretMin   = 4
	webRedacted    = "***"
	webDayDuration = 24 * time.Hour
)

type jobRun struct {
	at  time.Time
	err string
}

func (d *Daemon) recordJob(name string, err error) {
	run := jobRun{at: time.Now()}
	if err != nil {
		run.err = err.Error()
	}
	d.jobMu.Lock()
	if d.jobs == nil {
		d.jobs = map[string]jobRun{}
	}
	d.jobs[name] = run
	d.jobMu.Unlock()
}

func (d *Daemon) jobState(name string) (jobRun, bool) {
	d.jobMu.Lock()
	defer d.jobMu.Unlock()
	r, ok := d.jobs[name]
	return r, ok
}

type webLogger struct{ d *Daemon }

func (l webLogger) Infof(format string, args ...any)  { l.d.info(format, args...) }
func (l webLogger) Warnf(format string, args ...any)  { l.d.warn(format, args...) }
func (l webLogger) Errorf(format string, args ...any) { l.d.error(format, args...) }

// startWeb startet die Statusseite, falls aktiviert. Die zurückgegebene
// Funktion stoppt sie und wartet auf das Ende.
func (d *Daemon) startWeb(ctx context.Context) func() {
	if !d.Config.WebEnabled {
		return func() {}
	}
	opts := web.OptionsFromConfig(d.Config)
	opts.Version = appinfo.Version
	opts.Hostname = hostname()
	srv, err := web.New(opts, d, webLogger{d})
	if err != nil {
		d.warn("Web-Statusseite wird nicht gestartet: %v", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Run(ctx); err != nil {
			d.error("Web-Statusseite: %v", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// Status liefert den Snapshot für die Web-Statusseite. Live-Daten stammen aus
// dem Ereignisfenster von pollOnce; es gibt keinen zusätzlichen API-Aufruf.
func (d *Daemon) Status(ctx context.Context) (*web.Status, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := d.Config
	now := time.Now()
	st := &web.Status{GeneratedAt: now, Version: appinfo.Version, Hostname: hostname(), DryRun: c.DryRun}

	d.mu.Lock()
	started := d.startedAt
	events := append([]queryEvent(nil), d.events...)
	st.Poll = web.Poll{IntervalSeconds: c.CheckInterval, Entries: d.lastPollEntries}
	if !d.lastPollAt.IsZero() {
		t := d.lastPollAt
		st.Poll.LastSuccess = &t
	}
	if d.lastPollErr != "" {
		t := d.lastPollErrAt
		st.Poll.LastError = d.redact(d.lastPollErr)
		st.Poll.LastErrorAt = &t
	}
	d.mu.Unlock()
	if !started.IsZero() {
		st.StartedAt = started
		st.UptimeSeconds = int64(now.Sub(started) / time.Second)
	}

	if err := d.statusTiles(ctx, st, now); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blocklistBans, err := d.Store.CountBySource("external-blocklist")
	if err != nil {
		return nil, err
	}
	st.Modules = d.statusModules(blocklistBans)
	st.Live = d.statusLive(events)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bans, err := d.Store.RecentActiveBans(webListLimit)
	if err != nil {
		return nil, err
	}
	st.Bans = make([]web.Ban, 0, len(bans))
	for _, b := range bans {
		wb := web.Ban{IP: b.IP, Source: b.Source, Reason: b.Reason, Domain: b.Domain, Country: b.GeoIPCountry,
			Permanent: b.Permanent || b.BanUntil <= 0}
		if !wb.Permanent {
			t := time.Unix(b.BanUntil, 0)
			wb.Until = &t
		}
		st.Bans = append(st.Bans, wb)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lines, err := d.Store.RecentHistory(webListLimit)
	if err != nil {
		return nil, err
	}
	st.History = make([]web.HistoryEntry, 0, len(lines))
	for _, l := range lines {
		st.History = append(st.History, parseHistoryLine(l))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	logs := RecentLogLines(c.LogFile, "INFO", webListLimit)
	st.Logs = make([]string, 0, len(logs))
	for _, l := range logs {
		st.Logs = append(st.Logs, d.redact(l))
	}
	return st, nil
}

func (d *Daemon) statusTiles(ctx context.Context, st *web.Status, now time.Time) error {
	t := &st.Tiles
	steps := []func() error{
		func() (err error) { t.ActiveBans, err = d.Store.CountActiveBans(); return err },
		func() (err error) { t.PermanentBans, err = d.Store.CountPermanentActiveBans(); return err },
		func() error {
			y, m, day := now.Date()
			midnight := time.Date(y, m, day, 0, 0, 0, 0, now.Location())
			today, err := d.Store.PeriodSummary(midnight.Unix(), now.Unix())
			t.BansToday = today.TotalBans
			return err
		},
		func() error {
			week, err := d.Store.PeriodSummary(now.Add(-7*webDayDuration).Unix(), now.Unix())
			t.Bans7Days = week.TotalBans
			return err
		},
		func() (err error) { t.Offenses, err = d.Store.CountOffenses(); return err },
		func() (err error) { t.WhitelistEntries, err = d.countWhitelist(); return err },
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// countWhitelist zählt statische und externe Einträge; statische Einträge, die
// zusätzlich in der Datenbank stehen, werden nur einmal gezählt.
func (d *Daemon) countWhitelist() (int, error) {
	n, err := d.Store.CountWhitelist()
	if err != nil {
		return 0, err
	}
	static := map[string]bool{}
	for _, e := range d.Config.Whitelist {
		static[canonicalOrRaw(strings.TrimSpace(e))] = true
	}
	for e := range static {
		dup, err := d.Store.WhitelistContains(e)
		if err != nil {
			return 0, err
		}
		if !dup {
			n++
		}
	}
	return n, nil
}

func (d *Daemon) statusModules(blocklistBans int) []web.Module {
	c := d.Config
	withJob := func(m web.Module, job string) web.Module {
		if r, ok := d.jobState(job); ok {
			t := r.at
			m.LastRun = &t
			m.LastResult = "ok"
			if r.err != "" {
				m.LastResult = d.redact(r.err)
			}
		}
		return m
	}
	countries := "alle"
	if len(c.GeoIPCountries) > 0 {
		countries = strings.Join(c.GeoIPCountries, ", ")
	}
	notifyDetail := "Typ " + c.NotifyType
	return []web.Module{
		{Name: "Rate-Limit", Active: true, Detail: fmt.Sprintf("%d Anfragen / %d s, Polling alle %d s", c.RateLimitMaxRequests, c.RateLimitWindow, c.CheckInterval)},
		{Name: "Subdomain-Flood", Active: c.SubdomainFloodEnabled, Detail: fmt.Sprintf("max. %d Subdomains / %d s", c.SubdomainFloodMaxUnique, c.SubdomainFloodWindow)},
		{Name: "DNS-Flood-Watchlist", Active: c.DNSFloodWatchlistEnabled, Detail: fmt.Sprintf("%d Domains", len(c.DNSFloodWatchlist))},
		withJob(web.Module{Name: "GeoIP", Active: c.GeoIPEnabled, Detail: fmt.Sprintf("Modus %s · Länder: %s", c.GeoIPMode, countries)}, "geoip-refresh"),
		withJob(web.Module{Name: "Externe Blocklist", Active: c.ExternalBlocklistEnabled, Detail: fmt.Sprintf("%d URLs · alle %d s · %d aktive Sperren", len(c.ExternalBlocklistURLs), c.ExternalBlocklistInterval, blocklistBans)}, "external-blocklist"),
		withJob(web.Module{Name: "Externe Whitelist", Active: c.ExternalWhitelistEnabled, Detail: fmt.Sprintf("%d URLs · alle %d s", len(c.ExternalWhitelistURLs), c.ExternalWhitelistInterval)}, "external-whitelist"),
		{Name: "Progressive Ban", Active: c.ProgressiveBanEnabled, Detail: fmt.Sprintf("Faktor %d · max. Stufe %d · Reset nach %d s", c.ProgressiveBanMultiplier, c.ProgressiveBanMaxLevel, c.ProgressiveBanResetAfter)},
		{Name: "AbuseIPDB", Active: c.AbuseIPDBEnabled, Detail: "meldet permanente Sperren"},
		{Name: "Benachrichtigungen", Active: c.NotifyEnabled, Detail: notifyDetail},
		{Name: "E-Mail-Report", Active: c.ReportEnabled, Detail: "Intervall " + c.ReportInterval},
		{Name: "Firewall", Active: !c.DryRun, Detail: fmt.Sprintf("%s/%s · Chain %s", c.FirewallBackend, c.FirewallMode, c.Chain)},
		{Name: "Dry-Run", Active: c.DryRun, Detail: "nur protokollieren, nicht sperren"},
	}
}

func (d *Daemon) statusLive(events []queryEvent) web.Live {
	c := d.Config
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	l := web.Live{
		WindowSeconds: c.RateLimitWindow, Limit: c.RateLimitMaxRequests,
		SubdomainEnabled: c.SubdomainFloodEnabled, SubdomainWindowSeconds: c.SubdomainFloodWindow,
		SubdomainLimit: c.SubdomainFloodMaxUnique, EventsInMemory: len(events),
		Top: webCounts(topQueryPairs(events, c.RateLimitWindow, webTopLimit)),
	}
	if c.SubdomainFloodEnabled {
		l.Subdomains = webCounts(topSubdomainGroups(events, c.SubdomainFloodWindow, webTopLimit))
	} else {
		l.Subdomains = []web.Count{}
	}
	n := min(len(events), webListLimit)
	l.Recent = make([]web.Query, 0, n)
	for _, ev := range events[:n] {
		l.Recent = append(l.Recent, web.Query{Time: ev.At, Client: ev.Client, Protocol: formatProtocol(ev.Protocol), Domain: ev.Domain})
	}
	return l
}

func webCounts(in []liveCount) []web.Count {
	out := make([]web.Count, 0, len(in))
	for _, c := range in {
		out = append(out, web.Count{Client: c.Client, Domain: c.Domain, Count: c.Count, Protocol: c.Protocol})
	}
	return out
}

func parseHistoryLine(line string) web.HistoryEntry {
	f := strings.SplitN(line, " | ", 8)
	for len(f) < 8 {
		f = append(f, "")
	}
	return web.HistoryEntry{Time: f[0], Action: f[1], IP: f[2], Domain: f[3], Count: f[4], Duration: f[5], Protocol: f[6], Reason: f[7]}
}

// redact entfernt Geheimnisse aus Fehlermeldungen und Logzeilen, z.B. den
// MaxMind-Key aus einer Download-URL oder Tokens in Listen-URLs.
func (d *Daemon) redact(s string) string {
	c := d.Config
	secrets := []string{c.AdGuardPass, c.NotifyWebhook, c.NTFYToken, c.NTFYTopic, c.AbuseIPDBAPIKey, c.GeoIPLicenseKey, c.WebPassword}
	urls := append([]string{c.NTFYServerURL, c.NotifyWebhook}, c.ExternalBlocklistURLs...)
	urls = append(urls, c.ExternalWhitelistURLs...)
	for _, u := range urls {
		secrets = append(secrets, urlSecrets(u)...)
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		if len(secret) >= webSecretMin {
			s = strings.ReplaceAll(s, secret, webRedacted)
		}
	}
	return s
}

// urlSecrets liefert eine URL in den Schreibweisen, in denen sie in Logs und
// Fehlern auftauchen kann, sowie Query und Zugangsdaten einzeln.
func urlSecrets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := []string{raw, url.PathEscape(raw), url.QueryEscape(raw)}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	out = append(out, u.String(), u.Redacted(), u.RawQuery)
	if q, err := url.QueryUnescape(u.RawQuery); err == nil {
		out = append(out, q)
	}
	if u.User != nil {
		out = append(out, u.User.String())
		if p, ok := u.User.Password(); ok {
			out = append(out, p)
		}
	}
	return out
}
