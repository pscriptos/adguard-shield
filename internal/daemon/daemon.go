package daemon

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"adguard-shield/internal/config"
	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
	"adguard-shield/internal/geoip"
	"adguard-shield/internal/syslog"
)

const (
	notifyTitle            = "🛡️ AdGuard Shield"
	geoIPWorkers           = 4
	geoIPPendingMax        = 10000
	blocklistNotifyMax     = 5
	blocklistSummaryIPsMax = 5
	hostLookupTimeout      = 5 * time.Second
	httpClientTimeout      = 20 * time.Second
	dailyInterval          = 24 * time.Hour
	whitelistReloadEvery   = 5 * time.Minute
	firewallDelTimeout     = 10 * time.Second
	queryLogLimitWarnEvery = 5 * time.Minute
)

type Daemon struct {
	Config *config.Config
	Store  *db.Store
	FW     *firewall.Firewall
	Geo    *geoip.Resolver
	// Client prüft TLS-Zertifikate (AbuseIPDB, externe Listen).
	Client *http.Client
	// NotifyClient wird für Benachrichtigungen genutzt (NOTIFY_TLS_INSECURE);
	// ohne NotifyClient wird Client verwendet.
	NotifyClient *http.Client
	// AdGuardClient wird nur für die AdGuard-Home-API genutzt (ADGUARD_TLS_INSECURE).
	AdGuardClient *http.Client
	Logger        *syslog.Logger
	LogFile       *syslog.RotatingFile

	mu         sync.Mutex
	seen       map[string]time.Time
	events     []queryEvent
	geoSeen    map[string]time.Time
	lastNewest time.Time

	// Für die Web-Statusseite, geschützt durch mu.
	startedAt       time.Time
	lastPollAt      time.Time
	lastPollEntries int
	lastPollErr     string
	lastPollErrAt   time.Time

	jobMu sync.Mutex
	jobs  map[string]jobRun

	wlMu      sync.RWMutex
	wl        *whitelist
	wlOnce    sync.Once
	wlSkipped string

	queryLogLimitWarned time.Time

	// insecureListWarned merkt sich bereits gemeldete http://-Listen.
	insecureListWarned sync.Map

	banMu sync.Mutex

	geoMu      sync.Mutex
	geoPending map[string]struct{}
	geoRunning bool

	notify          notifier
	notifyQueueSize int

	serviceMu            sync.Mutex
	serviceStartNotified bool
	serviceStopNotified  bool
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
	logFile, err := syslog.OpenFile(c.LogFile)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	logger := syslog.New(io.MultiWriter(os.Stderr, logFile), c.LogLevel)
	fw := firewall.New(firewall.OSExecutor{}, c.Chain, c.BlockedPorts, c.FirewallMode, c.DryRun)
	d := &Daemon{
		Config: c, Store: st, FW: fw, Logger: logger, LogFile: logFile,
		Client:        &http.Client{Timeout: httpClientTimeout, Transport: newTransport(false)},
		NotifyClient:  &http.Client{Timeout: httpClientTimeout, Transport: newTransport(c.NotifyTLSInsecure)},
		AdGuardClient: &http.Client{Timeout: httpClientTimeout, Transport: newTransport(c.AdGuardTLSInsecure)},
		seen:          map[string]time.Time{}, geoSeen: map[string]time.Time{},
	}
	d.Geo = geoip.New(c.GeoIPMMDBPath, c.GeoIPLicenseKey, filepath.Join(filepath.Dir(c.Path), "geoip"), c.GeoIPCacheTTL, st)
	return d, nil
}

func newTransport(insecure bool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return tr
}

func (d *Daemon) Close() {
	if d.Geo != nil {
		_ = d.Geo.Close()
	}
	if d.Store != nil {
		_ = d.Store.Close()
	}
	if d.LogFile != nil {
		_ = d.LogFile.Close()
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	if d.LogFile != nil && d.Config.LogMaxSizeMB > 0 {
		d.LogFile.SetMaxBytes(int64(d.Config.LogMaxSizeMB) << 20)
	}
	d.mu.Lock()
	d.startedAt = time.Now()
	d.mu.Unlock()
	d.info("AdGuard Shield Go-Daemon gestartet")
	for _, w := range d.Config.Warnings {
		d.warn("Konfiguration: %s", w)
	}
	d.info("Konfiguration: Limit %d Anfragen/%ds, Polling alle %ds, Dry-Run: %v", d.Config.RateLimitMaxRequests, d.Config.RateLimitWindow, d.Config.CheckInterval, d.Config.DryRun)
	d.info("Module: GeoIP=%v, externe Blocklist=%v, externe Whitelist=%v, Progressive-Ban=%v", d.Config.GeoIPEnabled, d.Config.ExternalBlocklistEnabled, d.Config.ExternalWhitelistEnabled, d.Config.ProgressiveBanEnabled)
	d.NotifyServiceStart(context.Background())
	d.startNotifier()
	defer func() {
		d.stopNotifier(notifyDrainTimeout)
		d.NotifyServiceStop(context.Background())
	}()
	stopWeb := d.startWeb(ctx)
	defer stopWeb()
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
	d.runJob(ctx, "external-whitelist", d.Config.ExternalWhitelistEnabled, time.Duration(d.Config.ExternalWhitelistInterval)*time.Second, true, d.SyncWhitelist)
	// Ohne eigenen Whitelist-Worker übernimmt der Daemon so Änderungen von
	// "adguard-shield whitelist-sync" bzw. "whitelist-flush" aus der CLI.
	d.runJob(ctx, "whitelist-reload", !d.Config.ExternalWhitelistEnabled, whitelistReloadEvery, false, func(context.Context) error {
		return d.loadCaches()
	})
	d.runJob(ctx, "external-blocklist", d.Config.ExternalBlocklistEnabled, time.Duration(d.Config.ExternalBlocklistInterval)*time.Second, true, d.SyncBlocklist)
	d.runJob(ctx, "geoip-refresh", d.Config.GeoIPEnabled, dailyInterval, false, d.refreshGeoIP)
	d.runJob(ctx, "db-retention", d.Config.HistoryRetentionDays > 0 || d.Config.GeoIPCacheTTL > 0, dailyInterval, true, func(context.Context) error {
		return d.runRetention(time.Now())
	})
	d.runJob(ctx, "ban-expiry", true, 60*time.Second, true, func(ctx context.Context) error {
		expired, err := d.Store.ExpiredBans(time.Now().Unix())
		if err != nil {
			return err
		}
		for _, ip := range expired {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_ = d.Unban(ctx, ip, "expired")
		}
		return nil
	})
	d.runJob(ctx, "offense-cleanup", d.Config.ProgressiveBanEnabled, time.Hour, true, func(ctx context.Context) error {
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

func (d *Daemon) runJob(ctx context.Context, name string, enabled bool, interval time.Duration, runNow bool, fn func(context.Context) error) {
	if !enabled || interval <= 0 {
		d.debug("Worker %s deaktiviert", name)
		return
	}
	go func() {
		d.info("Worker %s gestartet (Intervall: %s)", name, interval)
		if runNow {
			err := fn(ctx)
			d.recordJob(name, err)
			if err != nil {
				d.error("%s Fehler: %v", name, err)
			} else {
				d.debug("%s Lauf abgeschlossen", name)
			}
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				d.info("Worker %s gestoppt", name)
				return
			case <-t.C:
				err := fn(ctx)
				d.recordJob(name, err)
				if err != nil {
					d.error("%s Fehler: %v", name, err)
				} else {
					d.debug("%s Lauf abgeschlossen", name)
				}
			}
		}
	}()
}

func (d *Daemon) loadCaches() error {
	var external []string
	if d.Store != nil {
		wl, err := d.Store.AllWhitelist()
		if err != nil {
			return err
		}
		external = make([]string, 0, len(wl))
		for ip := range wl {
			external = append(external, ip)
		}
	}
	w, skipped := newWhitelist(d.Config.Whitelist, external)
	d.setWhitelist(w, skipped)
	return nil
}

// setWhitelist tauscht den Snapshot aus und warnt über zu breite Einträge nur,
// wenn sie sich seit dem letzten Laden geändert haben.
func (d *Daemon) setWhitelist(w *whitelist, skipped []string) {
	key := strings.Join(skipped, ",")
	d.wlMu.Lock()
	d.wl = w
	changed := key != d.wlSkipped
	d.wlSkipped = key
	d.wlMu.Unlock()
	if changed && len(skipped) > 0 {
		d.warn("Whitelist: %d zu breite Netze werden ignoriert (IPv4 mindestens /%d, IPv6 mindestens /%d): %s", len(skipped), whitelistMinBits4, whitelistMinBits6, previewList(skipped, 10))
	}
}

func (d *Daemon) currentWhitelist() *whitelist {
	d.wlMu.RLock()
	w := d.wl
	d.wlMu.RUnlock()
	if w != nil {
		return w
	}
	d.wlOnce.Do(func() {
		if err := d.loadCaches(); err != nil {
			d.warn("Whitelist-Cache nicht geladen, nutze nur statische Whitelist: %v", err)
			d.setWhitelist(newWhitelist(d.Config.Whitelist))
		}
	})
	d.wlMu.RLock()
	defer d.wlMu.RUnlock()
	return d.wl
}

func (d *Daemon) reconcileFirewall(ctx context.Context) error {
	now := time.Now().Unix()
	expired, err := d.Store.ExpiredBans(now)
	if err != nil {
		return err
	}
	for _, ip := range expired {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = d.Unban(ctx, ip, "expired")
	}
	bans, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	entries := make([]firewall.Entry, 0, len(bans))
	for _, b := range bans {
		timeout := int64(0)
		if !b.Permanent && b.BanUntil > now {
			timeout = b.BanUntil - now
		}
		entries = append(entries, firewall.Entry{IP: b.IP, Timeout: timeout})
	}
	err = d.FW.AddBatch(ctx, entries)
	d.info("Firewall abgeglichen: %d aktive Sperren", len(entries))
	return err
}

func (d *Daemon) runRetention(now time.Time) error {
	if days := d.Config.HistoryRetentionDays; days > 0 {
		n, err := d.Store.PruneHistory(now.Unix() - int64(days)*86400)
		if err != nil {
			return err
		}
		if n > 0 {
			d.info("Retention: %d History-Einträge älter als %d Tage entfernt", n, days)
		}
	}
	if ttl := d.Config.GeoIPCacheTTL; ttl > 0 {
		n, err := d.Store.PruneGeoIPCache(now.Unix() - ttl)
		if err != nil {
			return err
		}
		if n > 0 {
			d.info("Retention: %d abgelaufene GeoIP-Cache-Einträge entfernt", n)
		}
	}
	return nil
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
