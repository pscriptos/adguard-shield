package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adguard-shield/internal/db"
	"adguard-shield/internal/firewall"
)

// collectListEntries lädt alle Listen und liefert die normalisierten IPs/Netze,
// die Zahl der Quellen, die weder geladen noch aus dem Cache gelesen werden
// konnten, und die Zahl der Quellen, für die nur der Cache genutzt wurde.
func (d *Daemon) collectListEntries(ctx context.Context, urls []string, cacheDir, prefix string) (map[string]bool, int, int) {
	out := map[string]bool{}
	failed, stale := 0, 0
	for i, u := range urls {
		lines, fromCache, err := d.fetchCachedLines(ctx, u, cacheDir, prefix, i)
		if err != nil {
			d.warn("%s Download Warnung %s: %v", prefix, listSource(i, u), err)
			failed++
			continue
		}
		if fromCache {
			stale++
		}
		for _, line := range lines {
			for _, entry := range parseListEntry(line) {
				for _, resolved := range resolveEntry(ctx, entry) {
					out[resolved] = true
				}
			}
		}
	}
	return out, failed, stale
}

// listSource beschreibt eine Listen-URL für Logs ohne Pfad, Query und
// Zugangsdaten, da diese Tokens enthalten können.
func listSource(i int, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Sprintf("Quelle #%d", i+1)
	}
	return fmt.Sprintf("Quelle #%d (%s://%s)", i+1, u.Scheme, u.Host)
}

// listErr entfernt die vollständige URL aus Fehlern von net/http.
func listErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

func (d *Daemon) SyncWhitelist(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.ExternalWhitelistCacheDir, 0755); err != nil {
		return err
	}
	ips, failed, _ := d.collectListEntries(ctx, d.Config.ExternalWhitelistURLs, d.Config.ExternalWhitelistCacheDir, "whitelist")
	if failed > 0 {
		d.warn("Externe Whitelist: %d von %d Quellen nicht verfügbar, bisherige Einträge bleiben erhalten", failed, len(d.Config.ExternalWhitelistURLs))
		return fmt.Errorf("externe Whitelist: %d Quelle(n) nicht verfügbar", failed)
	}
	var list, broad []string
	for _, ip := range sortedKeys(ips) {
		if whitelistEntryOK(ip) {
			list = append(list, ip)
		} else {
			broad = append(broad, ip)
		}
	}
	if len(broad) > 0 {
		d.warn("Externe Whitelist: %d zu breite Netze werden ignoriert (IPv4 mindestens /%d, IPv6 mindestens /%d): %s", len(broad), whitelistMinBits4, whitelistMinBits6, previewList(broad, 10))
	}
	if err := d.Store.ReplaceWhitelist(list, "external"); err != nil {
		return err
	}
	if err := d.loadCaches(); err != nil {
		return err
	}
	bans, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	var lift []string
	for _, b := range bans {
		if d.isWhitelisted(b.IP) {
			lift = append(lift, b.IP)
		}
	}
	if whitelistSweepTooLarge(len(lift), len(bans)) {
		d.error("Externe Whitelist: Freigabe von %d der %d aktiven Sperren abgebrochen (Sicherheitsbremse, mehr als %d%%); Whitelist ist aktiv, bitte Listen prüfen", len(lift), len(bans), whitelistSweepMaxPercent)
		lift = nil
	}
	for _, ip := range lift {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = d.Unban(ctx, ip, "external-whitelist")
	}
	d.info("Externe Whitelist synchronisiert: %d IPs/Netze", len(list))
	return nil
}

// Sicherheitsbremse: Eine fehlerhafte Whitelist darf nicht schlagartig den
// Großteil aller Sperren aufheben.
const (
	whitelistSweepMaxPercent = 50
	whitelistSweepMinCount   = 100
)

func whitelistSweepTooLarge(lift, active int) bool {
	return lift > whitelistSweepMinCount && lift*100 > active*whitelistSweepMaxPercent
}

func (d *Daemon) SyncBlocklist(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.ExternalBlocklistCacheDir, 0755); err != nil {
		return err
	}
	desired, failed, stale := d.collectListEntries(ctx, d.Config.ExternalBlocklistURLs, d.Config.ExternalBlocklistCacheDir, "blocklist")
	for entry := range desired {
		if !blockableTarget(entry) {
			d.warn("Externe Blocklist: Eintrag %s wird ignoriert", entry)
			delete(desired, entry)
		}
	}
	active, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	existing := make(map[string]bool, len(active))
	for _, b := range active {
		existing[canonicalOrRaw(b.IP)] = true
	}

	dur := d.Config.ExternalBlocklistDuration
	perm := dur == 0
	banUntil := int64(0)
	if !perm {
		banUntil = time.Now().Unix() + dur
	}
	var skippedWL []string
	var candidates []db.Ban
	for _, ip := range sortedKeys(desired) {
		if d.isWhitelisted(ip) {
			if strings.Contains(ip, "/") {
				skippedWL = append(skippedWL, ip)
			}
			continue
		}
		if existing[ip] {
			continue
		}
		if d.Config.DryRun {
			_ = d.Store.History("DRY", ip, "-", "-", "dry-run", "-", "dry-run (external-blocklist)")
			d.warn("[DRY-RUN] Würde externe Blocklist-IP sperren: %s", ip)
			continue
		}
		candidates = append(candidates, db.Ban{IP: ip, Domain: "-", BanUntil: banUntil, Duration: dur, Permanent: perm, Reason: "external-blocklist", Protocol: "-", Source: "external-blocklist"})
	}
	if len(skippedWL) > 0 {
		d.warn("Externe Blocklist: %d Netze überschneiden die Whitelist und werden nicht gesperrt: %s", len(skippedWL), previewList(skippedWL, 10))
	}

	var added []db.Ban
	var entries []firewall.Entry
	for _, b := range candidates {
		inserted, err := d.Store.InsertBanIfAbsent(b)
		if err != nil {
			d.warn("Externe Blocklist: Sperre %s nicht gespeichert: %v", b.IP, err)
			continue
		}
		if inserted {
			added = append(added, b)
			entries = append(entries, firewall.Entry{IP: b.IP, Timeout: dur})
		}
	}
	if len(entries) > 0 {
		if err := d.FW.AddBatch(ctx, entries); err != nil {
			d.warn("Firewall Add Warnung (externe Blocklist): %v", err)
		}
	}
	for _, b := range added {
		_ = d.Store.History("BAN", b.IP, "-", "-", formatDuration(dur, perm), "-", "external-blocklist")
	}
	d.notifyBlocklistBans(added)

	if d.Config.ExternalBlocklistAutoUnban {
		if failed > 0 {
			d.warn("Externe Blocklist: %d Quelle(n) nicht verfügbar, Auto-Unban wird übersprungen", failed)
		} else {
			current, err := d.Store.BansBySource("external-blocklist")
			if err != nil {
				return err
			}
			for _, b := range current {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !desired[canonicalOrRaw(b.IP)] {
					_ = d.Unban(ctx, b.IP, "external-blocklist-removed")
				}
			}
		}
	}
	d.info("Externe Blocklist synchronisiert: %d IPs/Netze, %d neu gesperrt", len(desired), len(added))
	if n := failed + stale; n > 0 {
		return fmt.Errorf("%d von %d Quellen fehlgeschlagen (Cache genutzt bzw. übersprungen)", n, len(d.Config.ExternalBlocklistURLs))
	}
	return nil
}

// blockableTarget verhindert, dass fehlerhafte Listen 0.0.0.0, Loopback oder
// eine komplette Adressfamilie (/0) sperren.
func blockableTarget(s string) bool {
	a, p, ok := parseTarget(s)
	if !ok {
		return false
	}
	if p.IsValid() {
		return p.Bits() > 0 && !p.Addr().IsLoopback()
	}
	return !a.IsUnspecified() && !a.IsLoopback()
}

func canonicalOrRaw(s string) string {
	if n, ok := normalizeTarget(s); ok {
		return n
	}
	return s
}

func previewList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + ", ..."
}

// fetchCachedLines lädt eine Liste; fromCache meldet, dass der Download
// fehlschlug und stattdessen der Cache genutzt wurde.
func (d *Daemon) fetchCachedLines(ctx context.Context, sourceURL, cacheDir, prefix string, index int) (lines []string, fromCache bool, err error) {
	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.txt", prefix, index))
	etagFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.etag", prefix, index))
	tmpFile := filepath.Join(cacheDir, fmt.Sprintf("%s_%d.tmp", prefix, index))
	src := listSource(index, sourceURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, false, listErr(err)
	}
	if etag, err := os.ReadFile(etagFile); err == nil {
		if value := strings.TrimSpace(string(etag)); value != "" {
			req.Header.Set("If-None-Match", value)
		}
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		err = listErr(err)
		if b, readErr := os.ReadFile(cacheFile); readErr == nil {
			d.warn("%s Download fehlgeschlagen, nutze Cache: %s: %v", prefix, src, err)
			return strings.Split(string(b), "\n"), true, nil
		}
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		d.debug("%s Liste unverändert: %s", prefix, src)
		b, err := os.ReadFile(cacheFile)
		if err != nil {
			return nil, false, err
		}
		return strings.Split(string(b), "\n"), false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if b, readErr := os.ReadFile(cacheFile); readErr == nil {
			d.warn("%s Download HTTP %d, nutze Cache: %s", prefix, resp.StatusCode, src)
			return strings.Split(string(b), "\n"), true, nil
		}
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, false, listErr(err)
	}
	if err := os.WriteFile(tmpFile, b, 0644); err != nil {
		return nil, false, err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.WriteFile(etagFile, []byte(etag+"\n"), 0644)
	}
	if err := os.Rename(tmpFile, cacheFile); err != nil {
		return nil, false, err
	}
	d.debug("%s Liste aktualisiert: %s (%d Bytes)", prefix, src, len(b))
	return strings.Split(string(b), "\n"), false, nil
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

// resolveEntry normalisiert IPs/Netze und löst Hostnamen mit Timeout auf.
func resolveEntry(ctx context.Context, entry string) []string {
	if n, ok := normalizeTarget(entry); ok {
		return []string{n}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, hostLookupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, entry)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil && !ip.IsUnspecified() {
			out = append(out, ip.WithZone("").Unmap().String())
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
