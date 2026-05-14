package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
	"adguard-shield/internal/geoip"
	"adguard-shield/internal/syslog"
)

type Daemon struct {
	Config *config.Config
	Store  *db.Store
	FW     *firewall.Firewall
	Geo    *geoip.Resolver
	Client *http.Client
	Logger *syslog.Logger

	mu      sync.Mutex
	seen    map[string]time.Time
	events  []queryEvent
	geoSeen map[string]bool
	wl      map[string]bool

	serviceMu            sync.Mutex
	serviceStartNotified bool
	serviceStopNotified  bool
}

type queryLogResponse struct {
	Data []queryItem `json:"data"`
}

type queryItem struct {
	Time        string `json:"time"`
	Client      string `json:"client"`
	ClientProto string `json:"client_proto"`
	ClientInfo  struct {
		IP string `json:"ip"`
	} `json:"client_info"`
	Question struct {
		Name string `json:"name"`
		Host string `json:"host"`
	} `json:"question"`
}

type queryEvent struct {
	At       time.Time
	Client   string
	Domain   string
	Protocol string
}

func New(c *config.Config) (*Daemon, error) {
	if err := os.MkdirAll(c.StateDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(c.LogFile), 0755); err != nil {
		return nil, err
	}
	st, err := db.Open(c.DBPath())
	if err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(c.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	logger := syslog.New(io.MultiWriter(os.Stderr, logFile), c.LogLevel)
	fw := firewall.New(firewall.OSExecutor{}, c.Chain, c.BlockedPorts, c.FirewallMode, c.DryRun)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	d := &Daemon{
		Config: c, Store: st, FW: fw, Logger: logger,
		Client: &http.Client{Timeout: 20 * time.Second, Transport: tr},
		seen:   map[string]time.Time{}, geoSeen: map[string]bool{},
	}
	d.Geo = geoip.New(c.GeoIPMMDBPath, c.GeoIPLicenseKey, filepath.Join(filepath.Dir(c.Path), "geoip"), c.GeoIPCacheTTL, st)
	return d, nil
}

func (d *Daemon) Close() {
	if d.Geo != nil {
		_ = d.Geo.Close()
	}
	if d.Store != nil {
		_ = d.Store.Close()
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	d.info("AdGuard Shield Go-Daemon gestartet")
	d.info("Konfiguration: Limit %d Anfragen/%ds, Polling alle %ds, Dry-Run: %v", d.Config.RateLimitMaxRequests, d.Config.RateLimitWindow, d.Config.CheckInterval, d.Config.DryRun)
	d.info("Module: GeoIP=%v, externe Blocklist=%v, externe Whitelist=%v, Progressive-Ban=%v", d.Config.GeoIPEnabled, d.Config.ExternalBlocklistEnabled, d.Config.ExternalWhitelistEnabled, d.Config.ProgressiveBanEnabled)
	d.NotifyServiceStart(context.Background())
	defer d.NotifyServiceStop(context.Background())
	if err := d.FW.Setup(ctx); err != nil {
		d.warn("Firewall Setup Warnung: %v", err)
	}
	if err := d.Geo.Open(ctx); err != nil && d.Config.GeoIPEnabled {
		d.warn("GeoIP Warnung: %v", err)
	}
	if err := d.loadCaches(); err != nil {
		return err
	}
	if err := d.AutoUnbanGeoIP(ctx); err != nil {
		d.warn("GeoIP Auto-Unban Warnung: %v", err)
	}
	if err := d.reconcileFirewall(ctx); err != nil {
		d.warn("Firewall Reconcile Warnung: %v", err)
	}
	d.runJob(ctx, "external-whitelist", d.Config.ExternalWhitelistEnabled, time.Duration(d.Config.ExternalWhitelistInterval)*time.Second, d.SyncWhitelist)
	d.runJob(ctx, "external-blocklist", d.Config.ExternalBlocklistEnabled, time.Duration(d.Config.ExternalBlocklistInterval)*time.Second, d.SyncBlocklist)
	d.runJob(ctx, "ban-expiry", true, 60*time.Second, func(ctx context.Context) error {
		expired, err := d.Store.ExpiredBans(time.Now().Unix())
		if err != nil {
			return err
		}
		for _, ip := range expired {
			_ = d.Unban(ctx, ip, "expired")
		}
		return nil
	})
	d.runJob(ctx, "offense-cleanup", d.Config.ProgressiveBanEnabled, time.Hour, func(ctx context.Context) error {
		n, err := d.Store.CleanupOffenses(d.Config.ProgressiveBanResetAfter)
		if n > 0 {
			d.info("Offense-Cleanup: %d abgelaufene Zähler entfernt", n)
		}
		return err
	})
	ticker := time.NewTicker(time.Duration(d.Config.CheckInterval) * time.Second)
	defer ticker.Stop()
	for {
		if err := d.pollOnce(ctx); err != nil {
			d.error("Poll Fehler: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *Daemon) runJob(ctx context.Context, name string, enabled bool, interval time.Duration, fn func(context.Context) error) {
	if !enabled || interval <= 0 {
		d.debug("Worker %s deaktiviert", name)
		return
	}
	go func() {
		d.info("Worker %s gestartet (Intervall: %s)", name, interval)
		if err := fn(ctx); err != nil {
			d.error("%s Fehler: %v", name, err)
		} else {
			d.debug("%s Lauf abgeschlossen", name)
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				d.info("Worker %s gestoppt", name)
				return
			case <-t.C:
				if err := fn(ctx); err != nil {
					d.error("%s Fehler: %v", name, err)
				} else {
					d.debug("%s Lauf abgeschlossen", name)
				}
			}
		}
	}()
}

func (d *Daemon) loadCaches() error {
	wl, err := d.Store.AllWhitelist()
	if err != nil {
		return err
	}
	d.wl = wl
	for _, ip := range d.Config.Whitelist {
		d.wl[ip] = true
	}
	return nil
}

func (d *Daemon) reconcileFirewall(ctx context.Context) error {
	now := time.Now().Unix()
	expired, err := d.Store.ExpiredBans(now)
	if err != nil {
		return err
	}
	for _, ip := range expired {
		_ = d.Unban(ctx, ip, "expired")
	}
	bans, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	for _, b := range bans {
		timeout := int64(0)
		if !b.Permanent && b.BanUntil > now {
			timeout = b.BanUntil - now
		}
		_ = d.FW.Add(ctx, b.IP, timeout)
	}
	return nil
}

func (d *Daemon) pollOnce(ctx context.Context) error {
	entries, err := d.FetchQueryLog(ctx)
	if err != nil {
		return err
	}
	events := d.toEvents(entries)
	d.mu.Lock()
	for _, ev := range events {
		key := ev.At.Format(time.RFC3339Nano) + "|" + ev.Client + "|" + ev.Domain + "|" + ev.Protocol
		if _, ok := d.seen[key]; ok {
			continue
		}
		d.seen[key] = ev.At
		d.events = append(d.events, ev)
		if d.Config.GeoIPEnabled {
			d.debug("GeoIP-Prüfung geplant: %s", ev.Client)
			go d.checkGeoIP(context.Background(), ev.Client)
		}
	}
	d.pruneLocked()
	snapshot := append([]queryEvent(nil), d.events...)
	d.mu.Unlock()
	return d.analyze(ctx, snapshot)
}

func (d *Daemon) FetchQueryLog(ctx context.Context) ([]queryItem, error) {
	url := strings.TrimRight(d.Config.AdGuardURL, "/") + "/control/querylog?limit=" + strconv.Itoa(d.Config.APIQueryLimit) + "&response_status=all"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if d.Config.AdGuardUser != "" || d.Config.AdGuardPass != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Config.AdGuardUser+":"+d.Config.AdGuardPass)))
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AdGuard API HTTP %d", resp.StatusCode)
	}
	var out queryLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data, nil
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

func (d *Daemon) CheckGeoIPForCommand(ctx context.Context, ip string) {
	d.checkGeoIP(ctx, ip)
}

func parseAGHTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (d *Daemon) pruneLocked() {
	maxWindow := max(d.Config.RateLimitWindow, d.Config.SubdomainFloodWindow)
	cut := time.Now().Add(-time.Duration(maxWindow+30) * time.Second)
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
		if err := d.Ban(ctx, parts[0], parts[1], count, protos[key], reason, "monitor", "", perm); err != nil {
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
		_ = d.Ban(ctx, parts[0], "*."+parts[1], len(set), "dns", reason, "monitor", "", perm)
	}
}

func (d *Daemon) checkGeoIP(ctx context.Context, ip string) {
	if d.Config.GeoIPSkipPrivate && geoip.IsPrivateIP(ip) {
		return
	}
	d.mu.Lock()
	if d.geoSeen[ip] {
		d.mu.Unlock()
		return
	}
	d.geoSeen[ip] = true
	d.mu.Unlock()
	if d.isWhitelisted(ip) {
		return
	}
	exists, _ := d.Store.BanExists(ip)
	if exists {
		return
	}
	cc, err := d.Geo.Lookup(ip)
	if err != nil || cc == "" {
		return
	}
	if geoip.ShouldBlock(cc, d.Config.GeoIPMode, d.Config.GeoIPCountries) {
		_ = d.Ban(ctx, ip, "GeoIP:"+cc, 0, "-", "geoip", "geoip", cc, true)
	}
}

func (d *Daemon) Ban(ctx context.Context, ip, domain string, count int, proto, reason, source, country string, permanent bool) error {
	if d.isWhitelisted(ip) {
		return nil
	}
	exists, err := d.Store.BanExists(ip)
	if err != nil || exists {
		return err
	}
	if d.Config.DryRun {
		_ = d.Store.History("DRY", ip, domain, strconv.Itoa(count), "dry-run", proto, "dry-run ("+reason+")")
		d.warn("[DRY-RUN] Würde sperren: %s (%s, %s)", ip, reason, domain)
		return nil
	}
	duration := d.Config.BanDuration
	level := 0
	if source == "monitor" && d.Config.ProgressiveBanEnabled && !permanent {
		level, err = d.Store.IncrementOffense(ip, d.Config.ProgressiveBanResetAfter)
		if err != nil {
			return err
		}
		duration = durationForLevel(d.Config.BanDuration, level, d.Config.ProgressiveBanMultiplier)
		if d.Config.ProgressiveBanMaxLevel > 0 && level >= d.Config.ProgressiveBanMaxLevel {
			permanent = true
			duration = 0
		}
	}
	banUntil := int64(0)
	if !permanent && duration > 0 {
		banUntil = time.Now().Unix() + duration
	}
	if err := d.FW.Add(ctx, ip, duration); err != nil {
		d.warn("Firewall Add Warnung: %v", err)
	}
	b := db.Ban{IP: ip, Domain: domain, Count: count, BanUntil: banUntil, Duration: duration, OffenseLevel: level, Permanent: permanent, Reason: reason, Protocol: proto, Source: source, GeoIPCountry: country, GeoIPMode: d.Config.GeoIPMode}
	if err := d.Store.InsertBan(b); err != nil {
		return err
	}
	_ = d.Store.History("BAN", ip, domain, strconv.Itoa(count), formatDuration(duration, permanent), proto, reason)
	abuseReported := d.shouldReportAbuseIPDB(b)
	d.notifyBan(context.Background(), b, abuseReported)
	if abuseReported {
		d.reportAbuseIPDB(context.Background(), b)
	}
	d.warn("BAN %s (%s, %s)", ip, reason, domain)
	return nil
}

func (d *Daemon) Unban(ctx context.Context, ip, reason string) error {
	return d.unban(ctx, ip, reason, true)
}

func (d *Daemon) UnbanQuiet(ctx context.Context, ip, reason string) error {
	return d.unban(ctx, ip, reason, false)
}

func (d *Daemon) unban(ctx context.Context, ip, reason string, notify bool) error {
	_ = d.FW.Del(ctx, ip)
	if err := d.Store.DeleteBan(ip); err != nil {
		return err
	}
	_ = d.Store.History("UNBAN", ip, "-", "-", "-", "-", reason)
	if notify {
		d.notifyUnban(context.Background(), ip, reason)
	}
	d.info("UNBAN %s (%s)", ip, reason)
	return nil
}

func (d *Daemon) AutoUnbanGeoIP(ctx context.Context) error {
	bans, err := d.Store.BansByReason("geoip")
	if err != nil {
		return err
	}
	for _, b := range bans {
		shouldUnban := false
		if !d.Config.GeoIPEnabled {
			shouldUnban = true
		} else if b.GeoIPMode != "" && b.GeoIPMode != d.Config.GeoIPMode {
			shouldUnban = true
		} else if b.GeoIPCountry != "" && !geoip.ShouldBlock(b.GeoIPCountry, d.Config.GeoIPMode, d.Config.GeoIPCountries) {
			shouldUnban = true
		}
		if shouldUnban {
			_ = d.Unban(ctx, b.IP, "geoip-auto-unban")
		}
	}
	return nil
}

func (d *Daemon) isWhitelisted(ip string) bool {
	if d.wl == nil {
		_ = d.loadCaches()
	}
	if d.wl[ip] {
		return true
	}
	ok, _ := d.Store.WhitelistContains(ip)
	return ok
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

func (d *Daemon) SyncWhitelist(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.ExternalWhitelistCacheDir, 0755); err != nil {
		return err
	}
	ips := map[string]bool{}
	for i, u := range d.Config.ExternalWhitelistURLs {
		lines, err := d.fetchCachedLines(ctx, u, d.Config.ExternalWhitelistCacheDir, "whitelist", i)
		if err != nil {
			d.warn("Whitelist Download Warnung %s: %v", u, err)
			continue
		}
		for _, line := range lines {
			for _, ip := range parseListEntry(line) {
				for _, resolved := range resolveEntry(ip) {
					ips[resolved] = true
				}
			}
		}
	}
	var list []string
	for ip := range ips {
		list = append(list, ip)
	}
	sort.Strings(list)
	if err := d.Store.ReplaceWhitelist(list, "external"); err != nil {
		return err
	}
	_ = d.loadCaches()
	bans, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	for _, b := range bans {
		if d.isWhitelisted(b.IP) {
			_ = d.Unban(ctx, b.IP, "external-whitelist")
		}
	}
	d.info("Externe Whitelist synchronisiert: %d IPs", len(list))
	return nil
}

func (d *Daemon) SyncBlocklist(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.ExternalBlocklistCacheDir, 0755); err != nil {
		return err
	}
	desired := map[string]bool{}
	for i, u := range d.Config.ExternalBlocklistURLs {
		lines, err := d.fetchCachedLines(ctx, u, d.Config.ExternalBlocklistCacheDir, "blocklist", i)
		if err != nil {
			d.warn("Blocklist Download Warnung %s: %v", u, err)
			continue
		}
		for _, line := range lines {
			for _, entry := range parseListEntry(line) {
				for _, resolved := range resolveEntry(entry) {
					desired[resolved] = true
				}
			}
		}
	}
	for ip := range desired {
		if d.isWhitelisted(ip) {
			continue
		}
		if d.Config.DryRun {
			_ = d.Store.History("DRY", ip, "-", "-", "dry-run", "-", "dry-run (external-blocklist)")
			d.warn("[DRY-RUN] Würde externe Blocklist-IP sperren: %s", ip)
			continue
		}
		perm := d.Config.ExternalBlocklistDuration == 0
		dur := d.Config.ExternalBlocklistDuration
		if dur == 0 {
			dur = 0
		}
		_ = d.FW.Add(ctx, ip, dur)
		exists, _ := d.Store.BanExists(ip)
		if !exists {
			banUntil := int64(0)
			if !perm && dur > 0 {
				banUntil = time.Now().Unix() + dur
			}
			b := db.Ban{IP: ip, Domain: "-", BanUntil: banUntil, Duration: dur, Permanent: perm, Reason: "external-blocklist", Protocol: "-", Source: "external-blocklist"}
			_ = d.Store.InsertBan(b)
			_ = d.Store.History("BAN", ip, "-", "-", formatDuration(dur, perm), "-", "external-blocklist")
			d.notifyBan(context.Background(), b, false)
		}
	}
	if d.Config.ExternalBlocklistAutoUnban {
		current, err := d.Store.BansBySource("external-blocklist")
		if err != nil {
			return err
		}
		for _, b := range current {
			if !desired[b.IP] {
				_ = d.Unban(ctx, b.IP, "external-blocklist-removed")
			}
		}
	}
	d.info("Externe Blocklist synchronisiert: %d IPs/Netze", len(desired))
	return nil
}

func (d *Daemon) notifyBan(ctx context.Context, b db.Ban, abuseReported bool) {
	if !d.Config.NotifyEnabled {
		return
	}
	if b.Source == "geoip" && !d.Config.GeoIPNotify {
		return
	}
	if b.Source == "external-blocklist" && !d.Config.ExternalBlocklistNotify {
		return
	}
	title := notificationTitle(b)
	msg := d.banNotificationMessage(ctx, b, abuseReported)
	d.sendNotification(ctx, title, msg, b)
}

func (d *Daemon) notifyUnban(ctx context.Context, ip, reason string) {
	if !d.Config.NotifyEnabled {
		return
	}
	host := d.serverHostname()
	ptr := lookupPTR(ctx, ip)
	msg := fmt.Sprintf("✅ AdGuard Shield Freigabe auf %s\n---\nIP: %s\nHostname: %s\n\nAbuseIPDB: %s", host, ip, ptr, abuseIPDBCheckURL(ip))
	d.sendNotification(ctx, "🛡️ AdGuard Shield", msg, db.Ban{IP: ip, Reason: reason})
}

func (d *Daemon) NotifyBulkUnban(ctx context.Context, reason string, count int) {
	if !d.Config.NotifyEnabled || count <= 0 {
		return
	}
	msg := fmt.Sprintf("✅ AdGuard Shield Bulk-Freigabe auf %s\n---\nFreigegebene IPs: %d\nAktion: %s", d.serverHostname(), count, displayReason(reason))
	d.sendNotification(ctx, "🛡️ AdGuard Shield", msg, db.Ban{Reason: reason})
}

func (d *Daemon) NotifyServiceStart(ctx context.Context) {
	d.notifyServiceOnce(ctx, "service_start")
}

func (d *Daemon) NotifyServiceStop(ctx context.Context) {
	d.notifyServiceOnce(ctx, "service_stop")
}

func (d *Daemon) notifyServiceOnce(ctx context.Context, action string) {
	d.serviceMu.Lock()
	switch action {
	case "service_start":
		if d.serviceStartNotified {
			d.serviceMu.Unlock()
			return
		}
		d.serviceStartNotified = true
	case "service_stop":
		if d.serviceStopNotified {
			d.serviceMu.Unlock()
			return
		}
		d.serviceStopNotified = true
	}
	d.serviceMu.Unlock()

	notifyCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	d.notifyService(notifyCtx, action)
}

func (d *Daemon) notifyService(ctx context.Context, action string) {
	if !d.Config.NotifyEnabled {
		return
	}
	state := "gestartet"
	icon := "🟢"
	if action == "service_stop" {
		state = "gestoppt"
		icon = "🔴"
	}
	msg := fmt.Sprintf("%s AdGuard Shield %s wurde auf %s %s.", icon, appinfo.Version, d.serverHostname(), state)
	d.sendNotification(ctx, "🛡️ AdGuard Shield", msg, db.Ban{Reason: action, Source: "service"})
}

func (d *Daemon) banNotificationMessage(ctx context.Context, b db.Ban, abuseReported bool) string {
	host := d.serverHostname()
	if b.Source == "geoip" {
		return fmt.Sprintf("🌍 AdGuard Shield GeoIP-Sperre auf %s\n---\nIP: %s\nLand: %s\nModus: %s\nDauer: %s\n\nAbuseIPDB: %s",
			host, b.IP, b.GeoIPCountry, displayGeoIPMode(b.GeoIPMode), formatNotificationDuration(b.Duration, b.Permanent), abuseIPDBCheckURL(b.IP))
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("🚫 AdGuard Shield Ban auf %s", host))
	if abuseReported {
		lines = append(lines, "⚠️ IP wurde an AbuseIPDB gemeldet")
	}
	lines = append(lines, "---")
	lines = append(lines, "IP: "+b.IP)
	lines = append(lines, "Hostname: "+lookupPTR(ctx, b.IP))
	lines = append(lines, "Grund: "+d.displayBanReason(b))
	lines = append(lines, "Dauer: "+d.displayBanDuration(b))
	lines = append(lines, "", "AbuseIPDB: "+abuseIPDBCheckURL(b.IP))
	return strings.Join(lines, "\n")
}

func (d *Daemon) displayBanReason(b db.Ban) string {
	if b.Count > 0 && strings.TrimSpace(b.Domain) != "" && b.Domain != "-" {
		return fmt.Sprintf("%dx %s in %ds via %s, %s", b.Count, b.Domain, d.notificationWindow(b), displayProtocol(b.Protocol), displayReason(b.Reason))
	}
	return displayReason(b.Reason)
}

func (d *Daemon) displayBanDuration(b db.Ban) string {
	out := formatNotificationDuration(b.Duration, b.Permanent)
	if b.OffenseLevel > 0 {
		if d.Config.ProgressiveBanMaxLevel > 0 {
			out += fmt.Sprintf(" [Stufe %d/%d]", b.OffenseLevel, d.Config.ProgressiveBanMaxLevel)
		} else {
			out += fmt.Sprintf(" [Stufe %d]", b.OffenseLevel)
		}
	}
	return out
}

func (d *Daemon) notificationWindow(b db.Ban) int {
	if b.Reason == "subdomain-flood" || strings.HasPrefix(b.Domain, "*.") {
		return d.Config.SubdomainFloodWindow
	}
	return d.Config.RateLimitWindow
}

func (d *Daemon) shouldReportAbuseIPDB(b db.Ban) bool {
	return b.Source == "monitor" && b.Permanent && d.Config.AbuseIPDBEnabled && d.Config.AbuseIPDBAPIKey != ""
}

func (d *Daemon) serverHostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unbekannt"
	}
	return strings.TrimSpace(name)
}

func notificationTitle(b db.Ban) string {
	return "🛡️ AdGuard Shield"
}

func lookupPTR(ctx context.Context, ip string) string {
	if _, err := netip.ParseAddr(ip); err != nil {
		return "(unbekannt)"
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		return "(unbekannt)"
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}

func abuseIPDBCheckURL(ip string) string {
	return "https://www.abuseipdb.com/check/" + ip
}

func displayGeoIPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "allowlist":
		return "Allowlist"
	default:
		return "Blocklist"
	}
}

func displayProtocol(proto string) string {
	proto = strings.TrimSpace(proto)
	if proto == "" || proto == "-" {
		return "DNS"
	}
	return strings.ToUpper(proto)
}

func displayReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "dns-flood-watchlist":
		return "DNS-Flood-Watchlist"
	case "rate-limit":
		return "Rate-Limit"
	case "subdomain-flood":
		return "Subdomain-Flood"
	case "external-blocklist":
		return "Externe Blocklist"
	case "geoip":
		return "GeoIP"
	default:
		parts := strings.FieldsFunc(reason, func(r rune) bool { return r == '-' || r == '_' })
		for i, p := range parts {
			if p == "" {
				continue
			}
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
		if len(parts) == 0 {
			return "Unbekannt"
		}
		return strings.Join(parts, "-")
	}
}

func formatNotificationDuration(sec int64, perm bool) string {
	if perm || sec == 0 {
		return "PERMANENT"
	}
	if sec < 60 {
		return strconv.FormatInt(sec, 10) + "s"
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if s > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%dm", m)
}

func (d *Daemon) sendNotification(ctx context.Context, title, msg string, b db.Ban) {
	action := notificationAction(b)
	req, err := d.notificationRequest(ctx, title, msg, b)
	if err != nil {
		d.warn("Benachrichtigung nicht vorbereitet (%s/%s): %v", d.Config.NotifyType, action, err)
		return
	}
	if req == nil {
		d.warn("Benachrichtigung übersprungen (%s/%s): Ziel nicht konfiguriert oder Typ unbekannt", d.Config.NotifyType, action)
		return
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		d.warn("Benachrichtigung fehlgeschlagen (%s/%s): %v", d.Config.NotifyType, action, err)
		return
	}
	if resp == nil {
		d.warn("Benachrichtigung fehlgeschlagen (%s/%s): keine HTTP-Antwort", d.Config.NotifyType, action)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		d.warn("Benachrichtigung fehlgeschlagen (%s/%s): HTTP %d", d.Config.NotifyType, action, resp.StatusCode)
		return
	}
	d.debug("Benachrichtigung gesendet (%s/%s): HTTP %d", d.Config.NotifyType, action, resp.StatusCode)
}

func (d *Daemon) reportAbuseIPDB(ctx context.Context, b db.Ban) {
	if d.Config.AbuseIPDBAPIKey == "" {
		d.warn("AbuseIPDB: API-Key nicht konfiguriert")
		return
	}
	form := url.Values{}
	form.Set("ip", b.IP)
	form.Set("categories", d.Config.AbuseIPDBCategories)
	form.Set("comment", d.abuseIPDBComment(b))
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.abuseipdb.com/api/v2/report", strings.NewReader(form.Encode()))
		if err != nil {
			return
		}
		req.Header.Set("Key", d.Config.AbuseIPDBAPIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := d.Client.Do(req)
		if err != nil {
			d.error("AbuseIPDB Fehler: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			d.info("AbuseIPDB: %s erfolgreich gemeldet", b.IP)
		} else {
			d.warn("AbuseIPDB: HTTP %d für %s", resp.StatusCode, b.IP)
		}
	}()
}

func (d *Daemon) abuseIPDBComment(b db.Ban) string {
	return fmt.Sprintf("DNS flooding on our DNS server: %dx %s in %ds. Banned by Adguard Shield 🔗 %s", b.Count, b.Domain, d.notificationWindow(b), appinfo.ProjectURL)
}

func (d *Daemon) notificationRequest(ctx context.Context, title, msg string, b db.Ban) (*http.Request, error) {
	action := notificationAction(b)
	switch d.Config.NotifyType {
	case "ntfy":
		if d.Config.NTFYTopic == "" {
			return nil, nil
		}
		url := strings.TrimRight(d.Config.NTFYServerURL, "/") + "/" + d.Config.NTFYTopic
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(msg))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Title", title)
		req.Header.Set("Priority", d.Config.NTFYPriority)
		if d.Config.NTFYToken != "" {
			req.Header.Set("Authorization", "Bearer "+d.Config.NTFYToken)
		}
		return req, nil
	case "discord":
		return jsonPost(ctx, d.Config.NotifyWebhook, map[string]string{"content": title + "\n\n" + msg})
	case "slack":
		return jsonPost(ctx, d.Config.NotifyWebhook, map[string]string{"text": title + "\n\n" + msg})
	case "generic":
		return jsonPost(ctx, d.Config.NotifyWebhook, map[string]string{"title": title, "message": msg, "client": b.IP, "action": action})
	case "gotify":
		form := url.Values{}
		form.Set("title", title)
		form.Set("message", msg)
		form.Set("priority", "5")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Config.NotifyWebhook, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	default:
		return nil, nil
	}
}

func notificationAction(b db.Ban) string {
	if strings.HasPrefix(b.Reason, "service_") {
		return b.Reason
	}
	if strings.HasSuffix(b.Reason, "-flush") {
		return b.Reason
	}
	if b.Source == "" && b.Domain == "" {
		return "unban"
	}
	return "ban"
}

func jsonPost(ctx context.Context, url string, payload any) (*http.Request, error) {
	if url == "" {
		return nil, nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (d *Daemon) fetchLines(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

func (d *Daemon) fetchCachedLines(ctx context.Context, sourceURL, cacheDir, prefix string, index int) ([]string, error) {
	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.txt", prefix, index))
	etagFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.etag", prefix, index))
	tmpFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.tmp", prefix, index))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	if etag, err := os.ReadFile(etagFile); err == nil {
		if value := strings.TrimSpace(string(etag)); value != "" {
			req.Header.Set("If-None-Match", value)
		}
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		if b, readErr := os.ReadFile(cacheFile); readErr == nil {
			d.warn("%s Download fehlgeschlagen, nutze Cache: %v", prefix, err)
			return strings.Split(string(b), "\n"), nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		d.debug("%s Liste unverändert: %s", prefix, sourceURL)
		b, err := os.ReadFile(cacheFile)
		if err != nil {
			return nil, err
		}
		return strings.Split(string(b), "\n"), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if b, readErr := os.ReadFile(cacheFile); readErr == nil {
			d.warn("%s Download HTTP %d, nutze Cache: %s", prefix, resp.StatusCode, sourceURL)
			return strings.Split(string(b), "\n"), nil
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpFile, b, 0644); err != nil {
		return nil, err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.WriteFile(etagFile, []byte(etag+"\n"), 0644)
	}
	if err := os.Rename(tmpFile, cacheFile); err != nil {
		return nil, err
	}
	d.debug("%s Liste aktualisiert: %s (%d Bytes)", prefix, sourceURL, len(b))
	return strings.Split(string(b), "\n"), nil
}

func parseListEntry(line string) []string {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 && (parts[0] == "0.0.0.0" || strings.HasPrefix(parts[0], "127.") || parts[0] == "::" || parts[0] == "::1") {
		line = parts[1]
	} else if len(parts) > 1 {
		return nil
	}
	if strings.Contains(line, "://") {
		return nil
	}
	if _, err := netip.ParseAddr(line); err == nil {
		return []string{line}
	}
	if _, err := netip.ParsePrefix(line); err == nil {
		return []string{line}
	}
	if isHostname(line) {
		return []string{line}
	}
	return nil
}

func resolveEntry(entry string) []string {
	if _, err := netip.ParseAddr(entry); err == nil {
		return []string{entry}
	}
	if _, err := netip.ParsePrefix(entry); err == nil {
		return []string{entry}
	}
	addrs, err := net.LookupHost(entry)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil && !ip.IsUnspecified() {
			out = append(out, ip.String())
		}
	}
	return out
}

func isHostname(s string) bool {
	if len(s) > 253 || strings.ContainsAny(s, "/:") {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if p == "" || len(p) > 63 {
			return false
		}
	}
	return true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func baseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) >= 3 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if isMultipartPublicSuffix(lastTwo) {
			return parts[len(parts)-3] + "." + lastTwo
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func isMultipartPublicSuffix(s string) bool {
	first, rest, ok := strings.Cut(s, ".")
	if !ok || len(rest) < 2 || len(rest) > 3 {
		return false
	}
	switch first {
	case "co", "com", "net", "org", "gov", "edu", "ac", "gv", "ne", "or", "go":
		return true
	default:
		return false
	}
}

func (d *Daemon) SaveFirewallRules(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.StateDir, 0755); err != nil {
		return err
	}
	if err := saveCommand(ctx, filepath.Join(d.Config.StateDir, "iptables-rules.v4"), "iptables-save"); err != nil {
		return err
	}
	return saveCommand(ctx, filepath.Join(d.Config.StateDir, "iptables-rules.v6"), "ip6tables-save")
}

func saveCommand(ctx context.Context, path, name string) error {
	out, err := exec.CommandContext(ctx, name).Output()
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0644)
}
func durationForLevel(base int64, level, mult int) int64 {
	if level <= 1 {
		return base
	}
	if mult < 1 {
		mult = 1
	}
	d := base
	for i := 1; i < level; i++ {
		d *= int64(mult)
	}
	return d
}
func formatDuration(sec int64, perm bool) string {
	if perm || sec == 0 {
		return "permanent"
	}
	return strconv.FormatInt(sec, 10) + "s"
}
func (d *Daemon) log(format string, args ...any) {
	d.info(format, args...)
}

func (d *Daemon) debug(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Debugf(format, args...)
	}
}
func (d *Daemon) info(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Infof(format, args...)
	}
}
func (d *Daemon) warn(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Warnf(format, args...)
	}
}
func (d *Daemon) error(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Errorf(format, args...)
	}
}
