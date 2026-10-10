package web

import (
	"context"
	"time"
)

// Provider liefert den aktuellen Status. Der Server ruft Status höchstens
// alle cacheTTL auf.
type Provider interface {
	Status(ctx context.Context) (*Status, error)
}

type ProviderFunc func(ctx context.Context) (*Status, error)

func (f ProviderFunc) Status(ctx context.Context) (*Status, error) { return f(ctx) }

// Status ist das JSON-Dokument von api/status. Es darf keine Geheimnisse
// (Passwörter, Tokens, API-Keys, Webhook-URLs) enthalten.
type Status struct {
	GeneratedAt   time.Time      `json:"generated_at"`
	Version       string         `json:"version"`
	Hostname      string         `json:"hostname"`
	StartedAt     time.Time      `json:"started_at"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	DryRun        bool           `json:"dry_run"`
	Tiles         Tiles          `json:"tiles"`
	Poll          Poll           `json:"poll"`
	Modules       []Module       `json:"modules"`
	Live          Live           `json:"live"`
	Bans          []Ban          `json:"bans"`
	History       []HistoryEntry `json:"history"`
	Logs          []string       `json:"logs"`
}

type Tiles struct {
	ActiveBans       int `json:"active_bans"`
	PermanentBans    int `json:"permanent_bans"`
	BansToday        int `json:"bans_today"`
	Bans7Days        int `json:"bans_7_days"`
	Offenses         int `json:"offenses"`
	WhitelistEntries int `json:"whitelist_entries"`
}

type Poll struct {
	IntervalSeconds int        `json:"interval_seconds"`
	LastSuccess     *time.Time `json:"last_success,omitempty"`
	Entries         int        `json:"entries"`
	LastError       string     `json:"last_error,omitempty"`
	LastErrorAt     *time.Time `json:"last_error_at,omitempty"`
}

type Module struct {
	Name    string     `json:"name"`
	Active  bool       `json:"active"`
	Detail  string     `json:"detail,omitempty"`
	LastRun *time.Time `json:"last_run,omitempty"`
	// LastResult ist "ok" oder eine (bereinigte) Fehlermeldung.
	LastResult string `json:"last_result,omitempty"`
}

type Live struct {
	WindowSeconds          int     `json:"window_seconds"`
	Limit                  int     `json:"limit"`
	SubdomainEnabled       bool    `json:"subdomain_enabled"`
	SubdomainWindowSeconds int     `json:"subdomain_window_seconds"`
	SubdomainLimit         int     `json:"subdomain_limit"`
	EventsInMemory         int     `json:"events_in_memory"`
	Top                    []Count `json:"top"`
	Subdomains             []Count `json:"subdomains"`
	Recent                 []Query `json:"recent"`
}

type Count struct {
	Client   string `json:"client"`
	Domain   string `json:"domain"`
	Count    int    `json:"count"`
	Protocol string `json:"protocol"`
}

type Query struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Protocol string    `json:"protocol"`
	Domain   string    `json:"domain"`
}

type Ban struct {
	IP        string     `json:"ip"`
	Source    string     `json:"source"`
	Reason    string     `json:"reason"`
	Domain    string     `json:"domain"`
	Country   string     `json:"country,omitempty"`
	Permanent bool       `json:"permanent"`
	Until     *time.Time `json:"until,omitempty"`
}

type HistoryEntry struct {
	Time     string `json:"time"`
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Domain   string `json:"domain"`
	Count    string `json:"count"`
	Duration string `json:"duration"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
}
