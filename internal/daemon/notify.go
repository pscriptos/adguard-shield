package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/db"
)

func (d *Daemon) notifyBlocklistBans(added []db.Ban) {
	if len(added) == 0 || !d.Config.NotifyEnabled || !d.Config.ExternalBlocklistNotify {
		return
	}
	if len(added) <= blocklistNotifyMax {
		for _, b := range added {
			d.notifyBan(b, false)
		}
		return
	}
	ips := make([]string, 0, blocklistSummaryIPsMax)
	for _, b := range added[:blocklistSummaryIPsMax] {
		ips = append(ips, b.IP)
	}
	first, count := added[0], len(added)
	d.enqueueNotification("Blocklist-Zusammenfassung", func(ctx context.Context) {
		msg := fmt.Sprintf("🚫 AdGuard Shield Externe Blocklist auf %s\n---\nNeue Sperren: %d\nDauer: %s\nBeispiele: %s, ...",
			d.serverHostname(), count, formatNotificationDuration(first.Duration, first.Permanent), strings.Join(ips, ", "))
		d.sendNotification(ctx, notifyTitle, msg, db.Ban{Domain: "-", Reason: "external-blocklist", Source: "external-blocklist"})
	})
}

func (d *Daemon) notifyBan(b db.Ban, abuseReported bool) {
	if !d.Config.NotifyEnabled {
		return
	}
	if b.Source == "geoip" && !d.Config.GeoIPNotify {
		return
	}
	if b.Source == "external-blocklist" && !d.Config.ExternalBlocklistNotify {
		return
	}
	d.enqueueNotification("Ban "+b.IP, func(ctx context.Context) {
		d.sendNotification(ctx, notifyTitle, d.banNotificationMessage(ctx, b, abuseReported), b)
	})
}

func (d *Daemon) notifyUnban(ip, reason string) {
	if !d.Config.NotifyEnabled {
		return
	}
	d.enqueueNotification("Unban "+ip, func(ctx context.Context) {
		msg := fmt.Sprintf("✅ AdGuard Shield Freigabe auf %s\n---\nIP: %s\nHostname: %s\n\nAbuseIPDB: %s", d.serverHostname(), ip, lookupPTR(ctx, ip), abuseIPDBCheckURL(ip))
		d.sendNotification(ctx, notifyTitle, msg, db.Ban{IP: ip, Reason: reason})
	})
}

// NotifyBulkUnban meldet eine Sammel-Freigabe (ctx bleibt aus Kompatibilitätsgründen).
func (d *Daemon) NotifyBulkUnban(_ context.Context, reason string, count int) {
	if !d.Config.NotifyEnabled || count <= 0 {
		return
	}
	d.enqueueNotification("Bulk-Freigabe", func(ctx context.Context) {
		msg := fmt.Sprintf("✅ AdGuard Shield Bulk-Freigabe auf %s\n---\nFreigegebene IPs: %d\nAktion: %s", d.serverHostname(), count, displayReason(reason))
		d.sendNotification(ctx, notifyTitle, msg, db.Ban{Reason: reason})
	})
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
	d.sendNotification(ctx, notifyTitle, msg, db.Ban{Reason: action, Source: "service"})
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

func (d *Daemon) serverHostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unbekannt"
	}
	return strings.TrimSpace(name)
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
	client := d.NotifyClient
	if client == nil {
		client = d.Client
	}
	resp, err := client.Do(req)
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
