package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const queryLogMaxPages = 20

type queryLogResponse struct {
	Data   []queryItem `json:"data"`
	Oldest string      `json:"oldest"`
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

// FetchQueryLog liest die neueste Seite des AdGuard-Querylogs.
func (d *Daemon) FetchQueryLog(ctx context.Context) ([]queryItem, error) {
	page, err := d.fetchQueryLogPage(ctx, "")
	if err != nil {
		return nil, err
	}
	return page.Data, nil
}

func (d *Daemon) fetchQueryLogPage(ctx context.Context, olderThan string) (queryLogResponse, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(d.Config.APIQueryLimit))
	q.Set("response_status", "all")
	if olderThan != "" {
		q.Set("older_than", olderThan)
	}
	u := strings.TrimRight(d.Config.AdGuardURL, "/") + "/control/querylog?" + q.Encode()
	var out queryLogResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out, err
	}
	if d.Config.AdGuardUser != "" || d.Config.AdGuardPass != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Config.AdGuardUser+":"+d.Config.AdGuardPass)))
	}
	client := d.AdGuardClient
	if client == nil {
		client = d.Client
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("AdGuard API HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// fetchQueryLogSince blättert rückwärts durch das Querylog, bis die Seite
// unvollständig ist, cutoff unterschritten wird, bereits im letzten Poll
// verarbeitete Einträge erreicht sind (seenUntil) oder queryLogMaxPages erreicht ist.
func (d *Daemon) fetchQueryLogSince(ctx context.Context, cutoff, seenUntil time.Time) ([]queryItem, error) {
	var all []queryItem
	olderThan := ""
	pages := 0
	defer func() {
		if pages > 1 {
			d.debug("Querylog: %d Seiten mit %d Einträgen geladen", pages, len(all))
		}
	}()
	for page := 0; ; page++ {
		if page >= queryLogMaxPages {
			if d.shouldWarnQueryLogLimit(time.Now()) {
				d.warn("Querylog: Limit von %d Seiten erreicht, ältere Einträge werden nicht ausgewertet (Hinweis höchstens alle %s)", queryLogMaxPages, queryLogLimitWarnEvery)
			} else {
				d.debug("Querylog: Limit von %d Seiten erreicht", queryLogMaxPages)
			}
			break
		}
		res, err := d.fetchQueryLogPage(ctx, olderThan)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			d.warn("Querylog: Seite %d nicht geladen: %v", page+1, err)
			break
		}
		pages++
		all = append(all, res.Data...)
		if len(res.Data) == 0 || len(res.Data) < d.Config.APIQueryLimit {
			break
		}
		oldest := res.Oldest
		if oldest == "" {
			oldest = res.Data[len(res.Data)-1].Time
		}
		t, err := parseAGHTime(oldest)
		if err != nil || oldest == olderThan {
			break
		}
		if t.Before(cutoff) {
			break
		}
		if !seenUntil.IsZero() && !t.After(seenUntil) {
			break
		}
		olderThan = oldest
	}
	return all, nil
}

// shouldWarnQueryLogLimit begrenzt die Warnung bei Dauerlast (Flood) auf eine
// pro queryLogLimitWarnEvery.
func (d *Daemon) shouldWarnQueryLogLimit(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.queryLogLimitWarned.IsZero() && now.Sub(d.queryLogLimitWarned) < queryLogLimitWarnEvery {
		return false
	}
	d.queryLogLimitWarned = now
	return true
}
