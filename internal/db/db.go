package db

import (
	"database/sql"
	"fmt"
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

type ReportStats struct {
	Since        int64
	Until        int64
	TotalBans    int
	TotalUnbans  int
	ActiveBans   int
	TopClients   []ReportCount
	Reasons      []ReportCount
	Sources      []ReportCount
	RecentEvents []string
}

type ReportCount struct {
	Name  string
	Count int
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
CREATE INDEX IF NOT EXISTS idx_bans_until ON active_bans(ban_until_epoch);
CREATE INDEX IF NOT EXISTS idx_bans_source ON active_bans(source);
CREATE INDEX IF NOT EXISTS idx_bans_reason ON active_bans(reason);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON ban_history(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_history_action ON ban_history(action);
CREATE INDEX IF NOT EXISTS idx_history_ip ON ban_history(client_ip);
CREATE INDEX IF NOT EXISTS idx_offenses_last ON offense_tracking(last_offense_epoch);
CREATE INDEX IF NOT EXISTS idx_geoip_cache_age ON geoip_cache(looked_up_at_epoch);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);`
	_, err := s.DB.Exec(schema)
	return err
}

func (s *Store) BanExists(ip string) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM active_bans WHERE client_ip=? LIMIT 1`, ip).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) InsertBan(b Ban) error {
	now := time.Now()
	perm := 0
	if b.Permanent {
		perm = 1
	}
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO active_bans
(client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.IP, b.Domain, b.Count, now.Format("2006-01-02 15:04:05"), b.BanUntil, b.Duration, b.OffenseLevel, perm,
		b.Reason, b.Protocol, b.Source, b.GeoIPCountry, b.GeoIPMode)
	return err
}

func (s *Store) DeleteBan(ip string) error {
	_, err := s.DB.Exec(`DELETE FROM active_bans WHERE client_ip=?`, ip)
	return err
}

func (s *Store) ActiveBans() ([]Ban, error) {
	rows, err := s.DB.Query(`SELECT client_ip, COALESCE(domain,''), COALESCE(count,0), COALESCE(ban_until_epoch,0),
COALESCE(ban_duration,0), COALESCE(offense_level,0), COALESCE(is_permanent,0), COALESCE(reason,''), COALESCE(protocol,''),
COALESCE(source,''), COALESCE(geoip_country,''), COALESCE(geoip_mode,'') FROM active_bans ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var perm int
		if err := rows.Scan(&b.IP, &b.Domain, &b.Count, &b.BanUntil, &b.Duration, &b.OffenseLevel, &perm, &b.Reason, &b.Protocol, &b.Source, &b.GeoIPCountry, &b.GeoIPMode); err != nil {
			return nil, err
		}
		b.Permanent = perm == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) BansBySource(source string) ([]Ban, error) {
	rows, err := s.DB.Query(`SELECT client_ip, COALESCE(domain,''), COALESCE(count,0), COALESCE(ban_until_epoch,0),
COALESCE(ban_duration,0), COALESCE(offense_level,0), COALESCE(is_permanent,0), COALESCE(reason,''), COALESCE(protocol,''),
COALESCE(source,''), COALESCE(geoip_country,''), COALESCE(geoip_mode,'') FROM active_bans WHERE source=?`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var perm int
		if err := rows.Scan(&b.IP, &b.Domain, &b.Count, &b.BanUntil, &b.Duration, &b.OffenseLevel, &perm, &b.Reason, &b.Protocol, &b.Source, &b.GeoIPCountry, &b.GeoIPMode); err != nil {
			return nil, err
		}
		b.Permanent = perm == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) BansByReason(reason string) ([]Ban, error) {
	rows, err := s.DB.Query(`SELECT client_ip, COALESCE(domain,''), COALESCE(count,0), COALESCE(ban_until_epoch,0),
COALESCE(ban_duration,0), COALESCE(offense_level,0), COALESCE(is_permanent,0), COALESCE(reason,''), COALESCE(protocol,''),
COALESCE(source,''), COALESCE(geoip_country,''), COALESCE(geoip_mode,'') FROM active_bans WHERE reason=?`, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var perm int
		if err := rows.Scan(&b.IP, &b.Domain, &b.Count, &b.BanUntil, &b.Duration, &b.OffenseLevel, &perm, &b.Reason, &b.Protocol, &b.Source, &b.GeoIPCountry, &b.GeoIPMode); err != nil {
			return nil, err
		}
		b.Permanent = perm == 1
		out = append(out, b)
	}
	return out, rows.Err()
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
	now := time.Now()
	var level int
	var last int64
	var first string
	err := s.DB.QueryRow(`SELECT offense_level, COALESCE(last_offense_epoch,0), COALESCE(first_offense,'') FROM offense_tracking WHERE client_ip=?`, ip).Scan(&level, &last, &first)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if err == sql.ErrNoRows || (last > 0 && now.Unix()-last > resetAfter) {
		level = 0
		first = now.Format("2006-01-02 15:04:05")
	}
	level++
	_, err = s.DB.Exec(`INSERT OR REPLACE INTO offense_tracking (client_ip, offense_level, last_offense_epoch, last_offense, first_offense, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`, ip, level, now.Unix(), now.Format("2006-01-02 15:04:05"), first, now.Format("2006-01-02 15:04:05"))
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

func (s *Store) LoadGeoIPCache(ttl, dbMtime int64) (map[string]string, error) {
	rows, err := s.DB.Query(`SELECT ip, country_code FROM geoip_cache WHERE looked_up_at_epoch >= ? AND (db_mtime=? OR db_mtime=0)`, time.Now().Unix()-ttl, dbMtime)
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

func (s *Store) ReportStats(since, until int64, limit int) (ReportStats, error) {
	st := ReportStats{Since: since, Until: until}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&st.TotalBans); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ban_history WHERE action='UNBAN' AND timestamp_epoch BETWEEN ? AND ?`, since, until).Scan(&st.TotalUnbans); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM active_bans`).Scan(&st.ActiveBans); err != nil {
		return st, err
	}
	var err error
	st.TopClients, err = s.reportCounts(`SELECT client_ip, COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? GROUP BY client_ip ORDER BY COUNT(*) DESC, client_ip LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	st.Reasons, err = s.reportCounts(`SELECT COALESCE(NULLIF(reason,''), 'unknown'), COUNT(*) FROM ban_history WHERE action='BAN' AND timestamp_epoch BETWEEN ? AND ? GROUP BY COALESCE(NULLIF(reason,''), 'unknown') ORDER BY COUNT(*) DESC LIMIT ?`, since, until, limit)
	if err != nil {
		return st, err
	}
	st.Sources, err = s.reportCounts(`SELECT COALESCE(NULLIF(source,''), 'unknown'), COUNT(*) FROM active_bans GROUP BY COALESCE(NULLIF(source,''), 'unknown') ORDER BY COUNT(*) DESC LIMIT ?`, 0, 0, limit)
	if err != nil {
		return st, err
	}
	st.RecentEvents, err = s.RecentHistory(limit)
	return st, err
}

func (s *Store) reportCounts(query string, since, until int64, limit int) ([]ReportCount, error) {
	var rows *sql.Rows
	var err error
	if since == 0 && until == 0 {
		rows, err = s.DB.Query(query, limit)
	} else {
		rows, err = s.DB.Query(query, since, until, limit)
	}
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
