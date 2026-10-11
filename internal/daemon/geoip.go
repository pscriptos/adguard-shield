package daemon

import (
	"context"
	"sync"
	"time"

	"adguard-shield/internal/geoip"
)

func (d *Daemon) CheckGeoIPForCommand(ctx context.Context, ip string) {
	d.checkGeoIP(ctx, ip)
}

// scheduleGeoIP merkt Clients für die GeoIP-Prüfung vor. Ein einzelner
// Hintergrundlauf arbeitet die (begrenzte) Warteschlange mit geoIPWorkers ab.
func (d *Daemon) scheduleGeoIP(ctx context.Context, ips []string) {
	if len(ips) == 0 {
		return
	}
	d.geoMu.Lock()
	if d.geoPending == nil {
		d.geoPending = map[string]struct{}{}
	}
	dropped := 0
	for _, ip := range ips {
		if _, ok := d.geoPending[ip]; ok {
			continue
		}
		if len(d.geoPending) >= geoIPPendingMax {
			dropped++
			continue
		}
		d.geoPending[ip] = struct{}{}
	}
	start := !d.geoRunning && len(d.geoPending) > 0
	if start {
		d.geoRunning = true
	}
	d.geoMu.Unlock()
	if dropped > 0 {
		d.warn("GeoIP-Warteschlange voll, %d Clients übersprungen", dropped)
	}
	if start {
		go d.runGeoIPChecks(ctx)
	}
}

func (d *Daemon) runGeoIPChecks(ctx context.Context) {
	for {
		d.geoMu.Lock()
		if len(d.geoPending) == 0 || ctx.Err() != nil {
			d.geoPending = nil
			d.geoRunning = false
			d.geoMu.Unlock()
			return
		}
		batch := make([]string, 0, len(d.geoPending))
		for ip := range d.geoPending {
			batch = append(batch, ip)
		}
		d.geoPending = map[string]struct{}{}
		d.geoMu.Unlock()
		d.debug("GeoIP-Prüfung: %d Clients", len(batch))

		ch := make(chan string)
		var wg sync.WaitGroup
		for i := 0; i < min(geoIPWorkers, len(batch)); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ch {
					d.checkGeoIP(ctx, ip)
				}
			}()
		}
	feed:
		for _, ip := range batch {
			select {
			case ch <- ip:
			case <-ctx.Done():
				break feed
			}
		}
		close(ch)
		wg.Wait()
	}
}

func (d *Daemon) checkGeoIP(ctx context.Context, ip string) {
	if d.Geo == nil {
		return
	}
	if d.Config.GeoIPSkipPrivate && geoip.IsPrivateIP(ip) {
		return
	}
	if d.isWhitelisted(ip) {
		return
	}
	if !d.shouldCheckGeoIP(ip, time.Now()) {
		return
	}
	if exists, _ := d.Store.BanExists(ip); exists {
		return
	}
	cc, err := d.Geo.Lookup(ip)
	if err != nil || cc == "" {
		return
	}
	if geoip.ShouldBlock(cc, d.Config.GeoIPMode, d.Config.GeoIPCountries) {
		if err := d.Ban(ctx, BanRequest{IP: ip, Domain: "GeoIP:" + cc, Protocol: "-", Reason: "geoip", Source: "geoip", Country: cc, Permanent: true}); err != nil {
			d.error("GeoIP Ban Fehler: %v", err)
		}
	}
}

func (d *Daemon) refreshGeoIP(ctx context.Context) error {
	swapped, err := d.Geo.Refresh(ctx)
	if swapped {
		d.info("GeoIP-Datenbank aktualisiert")
	}
	return err
}

func (d *Daemon) shouldCheckGeoIP(ip string, now time.Time) bool {
	interval := d.geoIPCheckInterval()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.geoSeen[ip]; ok && now.Sub(last) < interval {
		return false
	}
	d.geoSeen[ip] = now
	d.pruneGeoSeenLocked(now, interval)
	return true
}

func (d *Daemon) geoIPCheckInterval() time.Duration {
	seconds := 0
	if d.Config != nil {
		seconds = d.Config.GeoIPCheckInterval
		if seconds <= 0 {
			seconds = d.Config.CheckInterval
		}
	}
	if seconds <= 0 {
		seconds = 1
	}
	return time.Duration(seconds) * time.Second
}

func (d *Daemon) pruneGeoSeenLocked(now time.Time, interval time.Duration) {
	cutoff := now.Add(-2 * interval)
	for ip, last := range d.geoSeen {
		if last.Before(cutoff) {
			delete(d.geoSeen, ip)
		}
	}
}
