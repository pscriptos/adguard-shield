package db

import (
	"database/sql"
	"fmt"
	"math"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

type Ban struct {
	IP           string
	Domain       string
	Count        int
	BanUntil     int64
	Duration     int64
	OffenseLevel int
	Permanent    bool
	Reason       string
	Protocol     string
	Source       string
	GeoIPCountry string
	GeoIPMode    string
}

type Offense struct {
	IP        string
	Level     int
	LastEpoch int64
	Last      string
	First     string
}

type WhitelistEntry struct {
	IP         string
	Source     string
	ResolvedAt string
}

type GeoIPCacheEntry struct {
	IP              string
	CountryCode     string
	LookedUpAtEpoch int64
	DBMtime         int64
}

type ReportStats struct {
	Since                 int64
	Until                 int64
	TotalBans             int
	TotalUnbans           int
	UniqueIPs             int
	PermanentBans         int
	ActiveBans            int
	AbuseIPDBReports      int
	RateLimitBans         int
	SubdomainFloodBans    int
	WatchlistBans         int
	ExternalBlocklistBans int
	GeoIPBans             int
	ManualBans            int
	OtherBans             int
	BusiestDay            string
	BusiestDayCount       int
	TopClients            []ReportCount
	TopDomains            []ReportCount
	Protocols             []ReportCount
	Reasons               []ReportCount
	Sources               []ReportCount
	RecentBans            []ReportEvent
	RecentEvents          []string
}

type ReportCount struct {
	Name  string
	Count int
}

type ReportEvent struct {
	Timestamp string
	Action    string
	IP        string
	Domain    string
	Count     string
	Duration  string
	Protocol  string
	Reason    string
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db}
	if err := s.Init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) Init() error {
	schema := `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now', 'localtime')));
CREATE TABLE IF NOT EXISTS active_bans (
 client_ip TEXT PRIMARY KEY, domain TEXT, count INTEGER, ban_time TEXT,
 ban_until_epoch INTEGER DEFAULT 0, ban_duration INTEGER DEFAULT 0, offense_level INTEGER DEFAULT 0,
 is_permanent INTEGER DEFAULT 0, reason TEXT DEFAULT 'rate-limit', protocol TEXT DEFAULT 'DNS',
 source TEXT DEFAULT 'monitor', geoip_country TEXT, geoip_mode TEXT, created_at TEXT DEFAULT (datetime('now', 'localtime')));
CREATE TABLE IF NOT EXISTS offense_tracking (
 client_ip TEXT PRIMARY KEY, offense_level INTEGER DEFAULT 0, last_offense_epoch INTEGER,
 last_offense TEXT, first_offense TEXT, created_at TEXT DEFAULT (datetime('now', 'localtime')),
 updated_at TEXT DEFAULT (datetime('now', 'localtime')));
CREATE TABLE IF NOT EXISTS ban_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_epoch INTEGER NOT NULL, timestamp_text TEXT NOT NULL,
 action TEXT NOT NULL, client_ip TEXT NOT NULL, domain TEXT, count TEXT, duration TEXT, protocol TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS whitelist_cache (ip_address TEXT PRIMARY KEY, source TEXT, resolved_at TEXT DEFAULT (datetime('now', 'localtime')));
CREATE TABLE IF NOT EXISTS geoip_cache (ip TEXT PRIMARY KEY, country_code TEXT NOT NULL, looked_up_at_epoch INTEGER NOT NULL, db_mtime INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS abuseipdb_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_epoch INTEGER NOT NULL, timestamp_text TEXT NOT NULL, client_ip TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_bans_until ON active_bans(ban_until_epoch);
CREATE INDEX IF NOT EXISTS idx_bans_source ON active_bans(source);
CREATE INDEX IF NOT EXISTS idx_bans_reason ON active_bans(reason);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON ban_history(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_history_action ON ban_history(action);
CREATE INDEX IF NOT EXISTS idx_history_ip ON ban_history(client_ip);
CREATE INDEX IF NOT EXISTS idx_offenses_last ON offense_tracking(last_offense_epoch);
CREATE INDEX IF NOT EXISTS idx_geoip_cache_age ON geoip_cache(looked_up_at_epoch);
CREATE INDEX IF NOT EXISTS idx_abuseipdb_timestamp ON abuseipdb_reports(timestamp_epoch);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);`
	if _, err := s.DB.Exec(schema); err != nil {
		return err
	}
	return s.migrate()
}

type migration struct {
	version int
	sql     string
}

// migrations werden aufsteigend nach Version angewendet; Version 1 ist das
// Basisschema aus Init. Einträge dürfen nachträglich nicht geändert werden.
var migrations = []migration{
	{2, `CREATE INDEX IF NOT EXISTS idx_bans_created ON active_bans(created_at);
CREATE INDEX IF NOT EXISTS idx_history_action_timestamp ON ban_history(action, timestamp_epoch);`},
}

func (s *Store) migrate() error {
	current, err := s.SchemaVersion()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return fmt.Errorf("Migration %d: %w", m.version, err)
		}
	}
	return nil
}

func (s *Store) applyMigration(m migration) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Version zuerst eintragen: Das sichert die Schreibsperre, und ein
	// parallel startender Prozess überspringt die bereits angewendete Migration.
	res, err := tx.Exec(`INSERT OR IGNORE INTO schema_version (version) VALUES (?)`, m.version)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return err
	}
	if _, err := tx.Exec(m.sql); err != nil {
		return err
	}
	return tx.Commit()
}

// SchemaVersion liefert die höchste angewendete Schema-Version.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.DB.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	return v, err
}

func (s *Store) BanExists(ip string) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM active_bans WHERE client_ip=? LIMIT 1`, ip).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

const banColumns = `client_ip, COALESCE(domain,''), COALESCE(count,0), COALESCE(ban_until_epoch,0),
COALESCE(ban_duration,0), COALESCE(offense_level,0), COALESCE(is_permanent,0), COALESCE(reason,''), COALESCE(protocol,''),
COALESCE(source,''), COALESCE(geoip_country,''), COALESCE(geoip_mode,'')`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBan(r rowScanner) (Ban, error) {
	var b Ban
	var perm int
	if err := r.Scan(&b.IP, &b.Domain, &b.Count, &b.BanUntil, &b.Duration, &b.OffenseLevel, &perm, &b.Reason, &b.Protocol, &b.Source, &b.GeoIPCountry, &b.GeoIPMode); err != nil {
		return Ban{}, err
	}
	b.Permanent = perm == 1
	return b, nil
}

// queryBans liest Sperren aus active_bans; tail enthält WHERE/ORDER BY.
func (s *Store) queryBans(tail string, args ...any) ([]Ban, error) {
	rows, err := s.DB.Query(`SELECT `+banColumns+` FROM active_bans `+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) BanByIP(ip string) (Ban, bool, error) {
	b, err := scanBan(s.DB.QueryRow(`SELECT `+banColumns+` FROM active_bans WHERE client_ip=? LIMIT 1`, ip))
	if err == sql.ErrNoRows {
		return Ban{}, false, nil
	}
	if err != nil {
		return Ban{}, false, err
	}
	return b, true, nil
}

func (s *Store) InsertBan(b Ban) error {
	_, err := s.insertBan(`INSERT OR REPLACE INTO`, ``, b)
	return err
}

// InsertBanIfAbsent legt die Sperre nur an, wenn für die IP noch keine aktive
// Sperre existiert. true bedeutet, dass diese Sperre neu eingetragen wurde.
func (s *Store) InsertBanIfAbsent(b Ban) (bool, error) {
	res, err := s.insertBan(`INSERT INTO`, ` ON CONFLICT(client_ip) DO NOTHING`, b)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) insertBan(verb, conflict string, b Ban) (sql.Result, error) {
	perm := 0
	if b.Permanent {
		perm = 1
	}
	return s.DB.Exec(verb+` active_bans
(client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`+conflict,
		b.IP, b.Domain, b.Count, time.Now().Format("2006-01-02 15:04:05"), b.BanUntil, b.Duration, b.OffenseLevel, perm,
		b.Reason, b.Protocol, b.Source, b.GeoIPCountry, b.GeoIPMode)
}

func (s *Store) DeleteBan(ip string) error {
	_, err := s.DB.Exec(`DELETE FROM active_bans WHERE client_ip=?`, ip)
	return err
}

func (s *Store) ActiveBans() ([]Ban, error) {
	return s.queryBans(`ORDER BY created_at DESC`)
}

// RecentActiveBans liefert die neuesten aktiven Sperren (wie ActiveBans sortiert).
func (s *Store) RecentActiveBans(limit int) ([]Ban, error) {
	return s.queryBans(`ORDER BY created_at DESC LIMIT ?`, limit)
}

func (s *Store) CountActiveBans() (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM active_bans`).Scan(&count)
	return count, err
}

// CountPermanentActiveBans zählt Sperren ohne Ablauf (wie banUntil in der Anzeige).
func (s *Store) CountPermanentActiveBans() (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM active_bans WHERE COALESCE(is_permanent,0) <> 0 OR COALESCE(ban_until_epoch,0) <= 0`).Scan(&count)
	return count, err
}

func (s *Store) CountWhitelist() (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM whitelist_cache`).Scan(&count)
	return count, err
}

func (s *Store) BansBySource(source string) ([]Ban, error) {
	return s.queryBans(`WHERE source=?`, source)
}

func (s *Store) BansByReason(reason string) ([]Ban, error) {
	return s.queryBans(`WHERE reason=?`, reason)
}

func (s *Store) CountBySource(source string) (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM active_bans WHERE source=?`, source).Scan(&count)
	return count, err
}

func (s *Store) ExpiredBans(now int64) ([]string, error) {
	rows, err := s.DB.Query(`SELECT client_ip FROM active_bans WHERE ban_until_epoch > 0 AND is_permanent = 0 AND ban_until_epoch <= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (s *Store) History(action, ip, domain, count, duration, protocol, reason string) error {
	now := time.Now()
	_, err := s.DB.Exec(`INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, now.Unix(), now.Format("2006-01-02 15:04:05"), action, ip, domain, count, duration, protocol, reason)
	return err
}

func (s *Store) RecentHistory(limit int) ([]string, error) {
	rows, err := s.DB.Query(`SELECT timestamp_text, action, client_ip, COALESCE(domain,''), COALESCE(count,''), COALESCE(duration,''), COALESCE(protocol,''), COALESCE(reason,'')
FROM ban_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ts, action, ip, domain, count, duration, proto, reason string
		if err := rows.Scan(&ts, &action, &ip, &domain, &count, &duration, &proto, &reason); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s | %s", ts, action, ip, domain, count, duration, proto, reason))
	}
	return out, rows.Err()
}

func (s *Store) WhitelistContains(ip string) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM whitelist_cache WHERE ip_address=? LIMIT 1`, ip).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) WhitelistByIP(ip string) (WhitelistEntry, bool, error) {
	var e WhitelistEntry
	err := s.DB.QueryRow(`SELECT ip_address, COALESCE(source,''), COALESCE(resolved_at,'') FROM whitelist_cache WHERE ip_address=? LIMIT 1`, ip).Scan(&e.IP, &e.Source, &e.ResolvedAt)
	if err == sql.ErrNoRows {
		return WhitelistEntry{}, false, nil
	}
	if err != nil {
		return WhitelistEntry{}, false, err
	}
	return e, true, nil
}

func (s *Store) ReplaceWhitelist(ips []string, source string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM whitelist_cache WHERE source=? OR source IS NULL`, source); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO whitelist_cache (ip_address, source) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ip := range ips {
		if _, err := stmt.Exec(ip, source); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AllWhitelist() (map[string]bool, error) {
	rows, err := s.DB.Query(`SELECT ip_address FROM whitelist_cache`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

func (s *Store) IncrementOffense(ip string, resetAfter int64) (int, error) {
	return s.incrementOffenseAt(ip, resetAfter, time.Now())
}

// incrementOffenseAt erhöht die Stufe in einer einzigen Anweisung, damit
// parallele Aufrufe keine Erhöhung verlieren. Im SET beziehen sich alle
// Spaltennamen auf die Werte vor dem Update.
func (s *Store) incrementOffenseAt(ip string, resetAfter int64, now time.Time) (int, error) {
	ts := now.Format("2006-01-02 15:04:05")
	var level int
	err := s.DB.QueryRow(`INSERT INTO offense_tracking (client_ip, offense_level, last_offense_epoch, last_offense, first_offense, updated_at)
VALUES (?1, 1, ?2, ?3, ?3, ?3)
ON CONFLICT(client_ip) DO UPDATE SET
 offense_level = CASE WHEN COALESCE(last_offense_epoch,0) > 0 AND ?2 - last_offense_epoch > ?4 THEN 1 ELSE COALESCE(offense_level,0) + 1 END,
 first_offense = CASE WHEN COALESCE(last_offense_epoch,0) > 0 AND ?2 - last_offense_epoch > ?4 THEN ?3 ELSE COALESCE(first_offense,'') END,
 last_offense_epoch = ?2, last_offense = ?3, updated_at = ?3
RETURNING offense_level`, ip, now.Unix(), ts, resetAfter).Scan(&level)
	return level, err
}

func (s *Store) ResetOffense(ip string) error {
	if ip == "" {
		_, err := s.DB.Exec(`DELETE FROM offense_tracking`)
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM offense_tracking WHERE client_ip=?`, ip)
	return err
}

func (s *Store) CleanupOffenses(resetAfter int64) (int64, error) {
	cutoff := time.Now().Unix() - resetAfter
	res, err := s.DB.Exec(`DELETE FROM offense_tracking WHERE last_offense_epoch <= ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountOffenses() (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM offense_tracking`).Scan(&count)
	return count, err
}

func (s *Store) CountExpiredOffenses(resetAfter int64) (int, error) {
	var count int
	cutoff := time.Now().Unix() - resetAfter
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM offense_tracking WHERE last_offense_epoch <= ?`, cutoff).Scan(&count)
	return count, err
}

func (s *Store) OffenseByIP(ip string) (Offense, bool, error) {
	var o Offense
	err := s.DB.QueryRow(`SELECT client_ip, COALESCE(offense_level,0), COALESCE(last_offense_epoch,0), COALESCE(last_offense,''), COALESCE(first_offense,'')
FROM offense_tracking WHERE client_ip=? LIMIT 1`, ip).Scan(&o.IP, &o.Level, &o.LastEpoch, &o.Last, &o.First)
	if err == sql.ErrNoRows {
		return Offense{}, false, nil
	}
	if err != nil {
		return Offense{}, false, err
	}
	return o, true, nil
}

// LoadGeoIPCache liefert die Cache-Einträge der letzten ttl Sekunden (ttl <= 0: alle).
func (s *Store) LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error) {
	since := int64(math.MinInt64)
	if ttl > 0 {
		since = time.Now().Unix() - ttl
	}
	rows, err := s.DB.Query(`SELECT ip, country_code FROM geoip_cache WHERE looked_up_at_epoch >= ? AND (db_mtime=? OR db_mtime=0)`, since, dbMtime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ip, cc string
		if err := rows.Scan(&ip, &cc); err != nil {
			return nil, err
		}
		out[ip] = cc
	}
	return out, rows.Err()
}

func (s *Store) GeoIPCacheByIP(ip string) (GeoIPCacheEntry, bool, error) {
	var e GeoIPCacheEntry
	err := s.DB.QueryRow(`SELECT ip, country_code, COALESCE(looked_up_at_epoch,0), COALESCE(db_mtime,0) FROM geoip_cache WHERE ip=? LIMIT 1`, ip).Scan(&e.IP, &e.CountryCode, &e.LookedUpAtEpoch, &e.DBMtime)
	if err == sql.ErrNoRows {
		return GeoIPCacheEntry{}, false, nil
	}
	if err != nil {
		return GeoIPCacheEntry{}, false, err
	}
	return e, true, nil
}

func (s *Store) UpsertGeoIP(ip, country string, dbMtime int64) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO geoip_cache (ip, country_code, looked_up_at_epoch, db_mtime) VALUES (?, ?, ?, ?)`, ip, country, time.Now().Unix(), dbMtime)
	return err
}

func (s *Store) ClearGeoIPCache() (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM geoip_cache`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneHistory löscht ban_history- und abuseipdb_reports-Einträge, die älter als
// before (Unix-Zeit) sind, und liefert die Gesamtzahl gelöschter Zeilen.
func (s *Store) PruneHistory(before int64) (int64, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var total int64
	for _, q := range []string{
		`DELETE FROM ban_history WHERE timestamp_epoch < ?`,
		`DELETE FROM abuseipdb_reports WHERE timestamp_epoch < ?`,
	} {
		res, err := tx.Exec(q, before)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, tx.Commit()
}

// PruneGeoIPCache löscht GeoIP-Cache-Einträge, die vor before nachgeschlagen wurden.
func (s *Store) PruneGeoIPCache(before int64) (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM geoip_cache WHERE looked_up_at_epoch < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PeriodSummary liefert nur TotalBans, TotalUnbans, UniqueIPs und PermanentBans
// (Werte identisch zu ReportStats) mit einer einzigen Abfrage.
func (s *Store) PeriodSummary(since, until int64) (ReportStats, error) {
	st := ReportStats{Since: since, Until: until}
	err := s.DB.QueryRow(`SELECT COALESCE(SUM(action='BAN'),0), COALESCE(SUM(action='UNBAN'),0),
COUNT(DISTINCT CASE WHEN action='BAN' THEN client_ip END),
COALESCE(SUM(action='BAN' AND LOWER(COALESCE(duration,'')) LIKE '%permanent%'),0)
FROM ban_history WHERE action IN ('BAN','UNBAN') AND timestamp_epoch BETWEEN ? AND ?`, since, until).
		Scan(&st.TotalBans, &st.TotalUnbans, &st.UniqueIPs, &st.PermanentBans)
	return st, err
}

func (s *Store) ReportStats(since, until, busiestSince int64, limit int) (ReportStats, error) {
	st := ReportStats{Since: since, Until: until}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&st.TotalBans); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE action='UNBAN' AND timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&st.TotalUnbans); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(DISTINCT client_ip) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&st.UniqueIPs); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? AND LOWER(COALESCE(duration,'')) LIKE '%permanent%'`, since, until).Scan(&st.PermanentBans); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM active_bans`).Scan(&st.ActiveBans); err != nil {
		return st, err
	}
	if err := s.reportAttackTypes(&st, since, until); err != nil {
		return st, err
	}
	if busiestSince <= 0 {
		busiestSince = since
	}
	if err := s.DB.QueryRow(`SELECT SUBSTR(timestamp_text, 1, 10), COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? GROUP BY SUBSTR(timestamp_text, 1, 10) ORDER BY COUNT(*) DESC, SUBSTR(timestamp_text, 1, 10) DESC LIMIT 1`, busiestSince, until).Scan(&st.BusiestDay, &st.BusiestDayCount); err != nil && err != sql.ErrNoRows {
		return st, err
	}
	var err error
	st.TopClients, err = s.reportCounts(`SELECT client_ip, COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? GROUP BY client_ip ORDER BY COUNT(*) DESC, client_ip LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	// GeoIP-, Blocklist- und manuelle Sperren tragen Platzhalter statt echter Domains.
	st.TopDomains, err = s.reportCounts(`SELECT domain, COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?
AND COALESCE(domain,'') NOT IN ('', '-') AND domain NOT LIKE 'GeoIP:%'
AND LOWER(COALESCE(reason,'')) NOT IN ('geoip', 'manual', 'external-blocklist')
GROUP BY domain ORDER BY COUNT(*) DESC, domain LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	st.Protocols, err = s.reportCounts(`SELECT p, COUNT(*) FROM (SELECT CASE WHEN TRIM(COALESCE(protocol,'')) IN ('', '-') THEN 'n/a' ELSE LOWER(TRIM(protocol)) END AS p
FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?) GROUP BY p ORDER BY COUNT(*) DESC, p LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	st.Reasons, err = s.reportCounts(`SELECT COALESCE(NULLIF(reason,''), 'unknown'), COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? GROUP BY COALESCE(NULLIF(reason,''), 'unknown') ORDER BY COUNT(*) DESC LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	st.Sources, err = s.reportCounts(`SELECT COALESCE(NULLIF(source,''), 'unknown'), COUNT(*) FROM active_bans GROUP BY COALESCE(NULLIF(source,''), 'unknown') ORDER BY COUNT(*) DESC LIMIT ?`, limit)
	if err != nil {
		return st, err
	}
	st.RecentBans, err = s.reportRecentBans(since, until, 10)
	if err != nil {
		return st, err
	}
	st.RecentEvents, err = s.RecentHistory(limit)
	return st, err
}

// reportAttackTypes ordnet jede Sperre genau einer Kategorie zu, damit die
// Summe der Angriffsarten immer der Gesamtzahl der Sperren entspricht.
func (s *Store) reportAttackTypes(st *ReportStats, since, until int64) error {
	rows, err := s.DB.Query(`SELECT CASE
 WHEN r LIKE '%watchlist%' THEN 'watchlist'
 WHEN r LIKE '%subdomain%flood%' THEN 'subdomain-flood'
 WHEN r LIKE '%rate%limit%' THEN 'rate-limit'
 WHEN r LIKE '%external%blocklist%' THEN 'external-blocklist'
 WHEN r LIKE 'geoip%' THEN 'geoip'
 WHEN r = 'manual' THEN 'manual'
 ELSE 'other' END AS kind, COUNT(*)
FROM (SELECT LOWER(COALESCE(reason,'')) AS r FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?)
GROUP BY kind`, since, until)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			return err
		}
		switch kind {
		case "rate-limit":
			st.RateLimitBans = count
		case "subdomain-flood":
			st.SubdomainFloodBans = count
		case "watchlist":
			st.WatchlistBans = count
		case "external-blocklist":
			st.ExternalBlocklistBans = count
		case "geoip":
			st.GeoIPBans = count
		case "manual":
			st.ManualBans = count
		default:
			st.OtherBans = count
		}
	}
	return rows.Err()
}

func (s *Store) RecordAbuseIPDBReport(ip string) error {
	now := time.Now()
	_, err := s.DB.Exec(`INSERT INTO abuseipdb_reports (timestamp_epoch, timestamp_text, client_ip) VALUES (?, ?, ?)`, now.Unix(), now.Format("2006-01-02 15:04:05"), ip)
	return err
}

// AbuseIPDBReportStats liefert die Anzahl gespeicherter Meldungen im Zeitraum und
// den Zeitpunkt der ältesten gespeicherten Meldung (0, wenn keine existiert).
func (s *Store) AbuseIPDBReportStats(since, until int64) (int, int64, error) {
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM abuseipdb_reports WHERE timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&count); err != nil {
		return 0, 0, err
	}
	var first int64
	if err := s.DB.QueryRow(`SELECT COALESCE(MIN(timestamp_epoch), 0) FROM abuseipdb_reports`).Scan(&first); err != nil {
		return 0, 0, err
	}
	return count, first, nil
}

// reportCounts führt eine Abfrage mit den Spalten (Name, Anzahl) aus; die
// Argumente werden unverändert an die Abfrage übergeben.
func (s *Store) reportCounts(query string, args ...any) ([]ReportCount, error) {
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportCount
	for rows.Next() {
		var item ReportCount
		if err := rows.Scan(&item.Name, &item.Count); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) reportRecentBans(since, until int64, limit int) ([]ReportEvent, error) {
	rows, err := s.DB.Query(`SELECT timestamp_text, action, client_ip, COALESCE(domain,''), COALESCE(count,''), COALESCE(duration,''), COALESCE(protocol,''), COALESCE(reason,'')
FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? ORDER BY id DESC LIMIT ?`, since, until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportEvent
	for rows.Next() {
		var e ReportEvent
		if err := rows.Scan(&e.Timestamp, &e.Action, &e.IP, &e.Domain, &e.Count, &e.Duration, &e.Protocol, &e.Reason); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) RecentHistoryByIP(ip string, limit int) ([]string, error) {
	rows, err := s.DB.Query(`SELECT timestamp_text, action, client_ip, COALESCE(domain,''), COALESCE(count,''), COALESCE(duration,''), COALESCE(protocol,''), COALESCE(reason,'')
FROM ban_history WHERE client_ip=? ORDER BY id DESC LIMIT ?`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ts, action, clientIP, domain, count, duration, proto, reason string
		if err := rows.Scan(&ts, &action, &clientIP, &domain, &count, &duration, &proto, &reason); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s | %s", ts, action, clientIP, domain, count, duration, proto, reason))
	}
	return out, rows.Err()
}
