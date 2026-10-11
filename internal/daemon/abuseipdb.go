package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/db"
)

func (d *Daemon) shouldReportAbuseIPDB(b db.Ban) bool {
	return b.Source == "monitor" && b.Permanent && d.Config.AbuseIPDBEnabled && d.Config.AbuseIPDBAPIKey != ""
}

func abuseIPDBCheckURL(ip string) string {
	return "https://www.abuseipdb.com/check/" + ip
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
			if err := d.Store.RecordAbuseIPDBReport(b.IP); err != nil {
				d.warn("AbuseIPDB: Meldung für %s nicht gespeichert: %v", b.IP, err)
			}
		} else {
			d.warn("AbuseIPDB: HTTP %d für %s", resp.StatusCode, b.IP)
		}
	}()
}

func (d *Daemon) abuseIPDBComment(b db.Ban) string {
	return fmt.Sprintf("DNS flooding on our DNS server: %dx %s in %ds. Banned by Adguard Shield 🔗 %s", b.Count, b.Domain, d.notificationWindow(b), appinfo.ProjectURL)
}
