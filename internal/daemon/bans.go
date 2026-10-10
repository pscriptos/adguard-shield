package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"adguard-shield/internal/db"
	"adguard-shield/internal/geoip"
)

// BanRequest beschreibt eine Sperre; Domain, Count usw. dienen Historie und Benachrichtigung.
type BanRequest struct {
	IP        string
	Domain    string
	Count     int
	Protocol  string
	Reason    string
	Source    string
	Country   string
	Permanent bool
}

// Ban sperrt eine IP oder ein Netz. Die Entscheidung (Whitelist, bestehende
// Sperre, Offense-Stufe, Eintrag) ist serialisiert; Benachrichtigung und
// AbuseIPDB-Meldung erfolgen nur für tatsächlich neu eingetragene Sperren.
func (d *Daemon) Ban(ctx context.Context, r BanRequest) error {
	ip, ok := normalizeTarget(r.IP)
	if !ok || strings.HasSuffix(ip, "/0") {
		return fmt.Errorf("ungültige IP-Adresse oder ungültiges Netz: %q", r.IP)
	}
	r.IP = ip
	d.banMu.Lock()
	b, inserted, err := d.banLocked(ctx, r)
	d.banMu.Unlock()
	if err != nil || !inserted {
		return err
	}
	abuseReported := d.shouldReportAbuseIPDB(b)
	d.notifyBan(b, abuseReported)
	if abuseReported {
		d.reportAbuseIPDB(context.Background(), b)
	}
	return nil
}

func (d *Daemon) banLocked(ctx context.Context, r BanRequest) (db.Ban, bool, error) {
	if d.isWhitelistedForBan(r.IP) {
		if r.Source == "manual" {
			return db.Ban{}, false, fmt.Errorf("%s steht auf der Whitelist und wird nicht gesperrt", r.IP)
		}
		return db.Ban{}, false, nil
	}
	exists, err := d.Store.BanExists(r.IP)
	if err != nil || exists {
		return db.Ban{}, false, err
	}
	if d.Config.DryRun {
		_ = d.Store.History("DRY", r.IP, r.Domain, strconv.Itoa(r.Count), "dry-run", r.Protocol, "dry-run ("+r.Reason+")")
		d.warn("[DRY-RUN] Würde sperren: %s (%s, %s)", r.IP, r.Reason, r.Domain)
		return db.Ban{}, false, nil
	}
	permanent := r.Permanent
	duration := d.Config.BanDuration
	level := 0
	if r.Source == "monitor" && d.Config.ProgressiveBanEnabled && !permanent {
		level, err = d.Store.IncrementOffense(r.IP, d.Config.ProgressiveBanResetAfter)
		if err != nil {
			return db.Ban{}, false, err
		}
		duration = durationForLevel(d.Config.BanDuration, level, d.Config.ProgressiveBanMultiplier)
		if d.Config.ProgressiveBanMaxLevel > 0 && level >= d.Config.ProgressiveBanMaxLevel {
			permanent = true
		}
	}
	if permanent {
		duration = 0
	}
	banUntil := int64(0)
	if !permanent && duration > 0 {
		banUntil = time.Now().Unix() + duration
	}
	b := db.Ban{IP: r.IP, Domain: r.Domain, Count: r.Count, BanUntil: banUntil, Duration: duration, OffenseLevel: level, Permanent: permanent, Reason: r.Reason, Protocol: r.Protocol, Source: r.Source, GeoIPCountry: r.Country, GeoIPMode: d.Config.GeoIPMode}
	inserted, err := d.Store.InsertBanIfAbsent(b)
	if err != nil || !inserted {
		return db.Ban{}, false, err
	}
	if err := d.FW.Add(ctx, r.IP, duration); err != nil {
		d.warn("Firewall Add Warnung: %v", err)
	}
	_ = d.Store.History("BAN", r.IP, r.Domain, strconv.Itoa(r.Count), formatDuration(duration, permanent), r.Protocol, r.Reason)
	d.warn("BAN %s (%s, %s)", r.IP, r.Reason, r.Domain)
	return b, true, nil
}

func (d *Daemon) Unban(ctx context.Context, ip, reason string) error {
	return d.unban(ctx, ip, reason, true)
}

func (d *Daemon) UnbanQuiet(ctx context.Context, ip, reason string) error {
	return d.unban(ctx, ip, reason, false)
}

// unban hebt eine Sperre auf. Firewall, Datenbank und Historie werden unter
// banMu geändert (Aufrufer dürfen banMu nicht halten), die Benachrichtigung
// erfolgt außerhalb. FW.Del läuft auch bei abgebrochenem ctx (SIGTERM), damit
// kein ipset-Eintrag ohne Datenbankzeile zurückbleibt.
func (d *Daemon) unban(ctx context.Context, ip, reason string, notify bool) error {
	delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), firewallDelTimeout)
	defer cancel()
	d.banMu.Lock()
	_ = d.FW.Del(delCtx, ip)
	err := d.Store.DeleteBan(ip)
	if err == nil {
		_ = d.Store.History("UNBAN", ip, "-", "-", "-", "-", reason)
	}
	d.banMu.Unlock()
	if err != nil {
		return err
	}
	if notify {
		d.notifyUnban(ip, reason)
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
		if ctx.Err() != nil {
			return ctx.Err()
		}
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

// isWhitelisted prüft nur den Whitelist-Snapshot im Speicher (für Massenprüfungen).
func (d *Daemon) isWhitelisted(ip string) bool {
	return d.currentWhitelist().contains(ip)
}

// isWhitelistedForBan ergänzt den Snapshot für einzelne IPs um eine
// Datenbankabfrage, damit z.B. per CLI ("whitelist-sync") eingetragene
// Adressen sofort wirken. Netze werden über den periodischen Reload erfasst.
func (d *Daemon) isWhitelistedForBan(ip string) bool {
	if d.isWhitelisted(ip) {
		return true
	}
	a, p, ok := parseTarget(ip)
	if !ok || p.IsValid() || d.Store == nil {
		return false
	}
	found, err := d.Store.WhitelistContains(a.String())
	if err != nil {
		d.warn("Whitelist-Abfrage für %s fehlgeschlagen: %v", ip, err)
	}
	return found
}

// IsWhitelisted prüft eine IP oder ein Netz gegen statische und externe Whitelist (inkl. CIDR).
func (d *Daemon) IsWhitelisted(ip string) bool {
	return d.isWhitelistedForBan(ip)
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
