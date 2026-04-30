#!/bin/bash
###############################################################################
# AdGuard Shield - SQLite Datenbank-Bibliothek
# Zentrale Datenbankfunktionen fuer alle Scripte.
# Wird per "source db.sh" eingebunden.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

DB_FILE="${STATE_DIR}/adguard-shield.db"
DB_SCHEMA_VERSION=1
_DB_MIGRATION_MARKER="${STATE_DIR}/.migration_v1_complete"

# ─── SQL-Wert escapen (Single Quotes verdoppeln) ────────────────────────────
_db_escape() {
    echo "${1//\'/\'\'}"
}

# ─── SQL ausfuehren (INSERT/UPDATE/DELETE) ───────────────────────────────────
db_exec() {
    sqlite3 "$DB_FILE" <<EOF
.timeout 5000
$1
EOF
}

# ─── SQL-Abfrage mit Pipe-Separator ─────────────────────────────────────────
db_query() {
    sqlite3 -separator '|' "$DB_FILE" <<EOF
.timeout 5000
$1
EOF
}

# ─── Datenbank initialisieren ────────────────────────────────────────────────
db_init() {
    mkdir -p "$(dirname "$DB_FILE")"

    sqlite3 "$DB_FILE" <<'SCHEMA'
.timeout 5000
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS active_bans (
    client_ip TEXT PRIMARY KEY,
    domain TEXT,
    count INTEGER,
    ban_time TEXT,
    ban_until_epoch INTEGER DEFAULT 0,
    ban_duration INTEGER DEFAULT 0,
    offense_level INTEGER DEFAULT 0,
    is_permanent INTEGER DEFAULT 0,
    reason TEXT DEFAULT 'rate-limit',
    protocol TEXT DEFAULT 'DNS',
    source TEXT DEFAULT 'monitor',
    geoip_country TEXT,
    geoip_mode TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS offense_tracking (
    client_ip TEXT PRIMARY KEY,
    offense_level INTEGER DEFAULT 0,
    last_offense_epoch INTEGER,
    last_offense TEXT,
    first_offense TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS ban_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_epoch INTEGER NOT NULL,
    timestamp_text TEXT NOT NULL,
    action TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    domain TEXT,
    count TEXT,
    duration TEXT,
    protocol TEXT,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS whitelist_cache (
    ip_address TEXT PRIMARY KEY,
    source TEXT,
    resolved_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- Indexes fuer Performance
CREATE INDEX IF NOT EXISTS idx_bans_until ON active_bans(ban_until_epoch);
CREATE INDEX IF NOT EXISTS idx_bans_source ON active_bans(source);
CREATE INDEX IF NOT EXISTS idx_bans_reason ON active_bans(reason);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON ban_history(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_history_action ON ban_history(action);
CREATE INDEX IF NOT EXISTS idx_history_ip ON ban_history(client_ip);
CREATE INDEX IF NOT EXISTS idx_offenses_last ON offense_tracking(last_offense_epoch);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);
SCHEMA
}

# ─── Ban-Funktionen ─────────────────────────────────────────────────────────

db_ban_exists() {
    local ip=$(_db_escape "$1")
    local result
    result=$(db_query "SELECT 1 FROM active_bans WHERE client_ip='$ip' LIMIT 1;")
    [[ -n "$result" ]]
}

db_ban_get() {
    local ip=$(_db_escape "$1")
    db_query "SELECT client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode FROM active_bans WHERE client_ip='$ip' LIMIT 1;"
}

db_ban_insert() {
    local ip=$(_db_escape "$1")
    local domain=$(_db_escape "$2")
    local count="${3:-0}"
    local ban_time=$(_db_escape "$4")
    local ban_until_epoch="${5:-0}"
    local ban_duration="${6:-0}"
    local offense_level="${7:-0}"
    local is_permanent="${8:-0}"
    local reason=$(_db_escape "${9:-rate-limit}")
    local protocol=$(_db_escape "${10:-DNS}")
    local source=$(_db_escape "${11:-monitor}")
    local geoip_country=$(_db_escape "${12:-}")
    local geoip_mode=$(_db_escape "${13:-}")

    db_exec "INSERT OR REPLACE INTO active_bans (client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode) VALUES ('$ip', '$domain', $count, '$ban_time', $ban_until_epoch, $ban_duration, $offense_level, $is_permanent, '$reason', '$protocol', '$source', '$geoip_country', '$geoip_mode');"
}

db_ban_delete() {
    local ip=$(_db_escape "$1")
    db_exec "DELETE FROM active_bans WHERE client_ip='$ip';"
}

db_ban_get_field() {
    local ip=$(_db_escape "$1")
    local field=$(_db_escape "$2")
    db_query "SELECT $field FROM active_bans WHERE client_ip='$ip' LIMIT 1;"
}

db_ban_get_expired() {
    local now
    now=$(date '+%s')
    db_query "SELECT client_ip FROM active_bans WHERE ban_until_epoch > 0 AND is_permanent = 0 AND ban_until_epoch <= $now;"
}

db_ban_get_expired_by_source() {
    local source=$(_db_escape "$1")
    local now
    now=$(date '+%s')
    db_query "SELECT client_ip FROM active_bans WHERE source='$source' AND ban_until_epoch > 0 AND is_permanent = 0 AND ban_until_epoch <= $now;"
}

db_ban_get_by_source() {
    local source=$(_db_escape "$1")
    db_query "SELECT client_ip FROM active_bans WHERE source='$source';"
}

db_ban_count() {
    db_query "SELECT COUNT(*) FROM active_bans;"
}

db_ban_count_by_source() {
    local source=$(_db_escape "$1")
    db_query "SELECT COUNT(*) FROM active_bans WHERE source='$source';"
}

db_ban_get_all() {
    db_query "SELECT client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode FROM active_bans ORDER BY created_at DESC;"
}

db_ban_get_by_reason() {
    local reason=$(_db_escape "$1")
    db_query "SELECT client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode FROM active_bans WHERE reason='$reason';"
}

# ─── Offense-Funktionen ─────────────────────────────────────────────────────

db_offense_get_level() {
    local ip=$(_db_escape "$1")
    local reset_after="${2:-86400}"
    local now
    now=$(date '+%s')

    local row
    row=$(db_query "SELECT offense_level, last_offense_epoch FROM offense_tracking WHERE client_ip='$ip' LIMIT 1;")

    if [[ -z "$row" ]]; then
        echo "0"
        return
    fi

    local level last_epoch
    IFS='|' read -r level last_epoch <<< "$row"

    if [[ -n "$last_epoch" && $((now - last_epoch)) -gt "$reset_after" ]]; then
        db_exec "DELETE FROM offense_tracking WHERE client_ip='$ip';"
        echo "0"
        return
    fi

    echo "${level:-0}"
}

db_offense_increment() {
    local ip=$(_db_escape "$1")
    local current_level
    current_level=$(db_offense_get_level "$1" "${PROGRESSIVE_BAN_RESET_AFTER:-86400}")
    local new_level=$((current_level + 1))
    local now
    now=$(date '+%s')
    local now_readable
    now_readable=$(date '+%Y-%m-%d %H:%M:%S')

    local first_offense
    first_offense=$(db_query "SELECT first_offense FROM offense_tracking WHERE client_ip='$ip' LIMIT 1;")
    [[ -z "$first_offense" ]] && first_offense="$now_readable"

    db_exec "INSERT OR REPLACE INTO offense_tracking (client_ip, offense_level, last_offense_epoch, last_offense, first_offense, updated_at) VALUES ('$ip', $new_level, $now, '$now_readable', '$first_offense', '$now_readable');"

    echo "$new_level"
}

db_offense_delete() {
    local ip=$(_db_escape "$1")
    db_exec "DELETE FROM offense_tracking WHERE client_ip='$ip';"
}

db_offense_delete_all() {
    local count
    count=$(db_query "SELECT COUNT(*) FROM offense_tracking;")
    db_exec "DELETE FROM offense_tracking;"
    echo "${count:-0}"
}

db_offense_delete_expired() {
    local reset_after="${1:-86400}"
    local now
    now=$(date '+%s')
    local cutoff=$((now - reset_after))

    local expired
    expired=$(db_query "SELECT client_ip, offense_level, last_offense_epoch FROM offense_tracking WHERE last_offense_epoch <= $cutoff;")
    local count=0
    if [[ -n "$expired" ]]; then
        count=$(echo "$expired" | wc -l)
        db_exec "DELETE FROM offense_tracking WHERE last_offense_epoch <= $cutoff;"
    fi
    echo "$count"
}

db_offense_get_all() {
    db_query "SELECT client_ip, offense_level, last_offense_epoch, last_offense, first_offense FROM offense_tracking ORDER BY last_offense_epoch DESC;"
}

db_offense_count() {
    db_query "SELECT COUNT(*) FROM offense_tracking;"
}

db_offense_count_expired() {
    local reset_after="${1:-86400}"
    local now
    now=$(date '+%s')
    local cutoff=$((now - reset_after))
    db_query "SELECT COUNT(*) FROM offense_tracking WHERE last_offense_epoch <= $cutoff;"
}

# ─── Ban-History-Funktionen ─────────────────────────────────────────────────

db_history_add() {
    local action=$(_db_escape "$1")
    local client_ip=$(_db_escape "$2")
    local domain=$(_db_escape "${3:--}")
    local count=$(_db_escape "${4:--}")
    local reason=$(_db_escape "${5:--}")
    local duration=$(_db_escape "${6:--}")
    local protocol=$(_db_escape "${7:--}")
    local now_epoch
    now_epoch=$(date '+%s')
    local now_text
    now_text=$(date '+%Y-%m-%d %H:%M:%S')

    db_exec "INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES ($now_epoch, '$now_text', '$action', '$client_ip', '$domain', '$count', '$duration', '$protocol', '$reason');"
}

db_history_cleanup() {
    local retention_days="${1:-0}"
    [[ "$retention_days" == "0" || -z "$retention_days" ]] && return

    local cutoff_epoch
    cutoff_epoch=$(date -d "-${retention_days} days" '+%s' 2>/dev/null)
    [[ -z "$cutoff_epoch" ]] && return

    local before after removed
    before=$(db_query "SELECT COUNT(*) FROM ban_history;")
    db_exec "DELETE FROM ban_history WHERE timestamp_epoch < $cutoff_epoch;"
    after=$(db_query "SELECT COUNT(*) FROM ban_history;")
    removed=$((before - after))
    echo "$removed"
}

db_history_get_recent() {
    local limit="${1:-50}"
    db_query "SELECT timestamp_text, action, client_ip, domain, count, duration, protocol, reason FROM ban_history ORDER BY id DESC LIMIT $limit;"
}

db_history_count() {
    db_query "SELECT COUNT(*) FROM ban_history;"
}

db_history_count_by_action() {
    local action=$(_db_escape "$1")
    db_query "SELECT COUNT(*) FROM ban_history WHERE action='$action';"
}

db_history_stats_for_range() {
    local start_epoch="$1"
    local end_epoch="$2"

    db_query "SELECT
        COALESCE(SUM(CASE WHEN action='BAN' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN action='UNBAN' THEN 1 ELSE 0 END), 0),
        COALESCE(COUNT(DISTINCT CASE WHEN action='BAN' THEN client_ip END), 0),
        COALESCE(SUM(CASE WHEN action='BAN' AND (duration LIKE '%PERMANENT%' OR duration LIKE '%permanent%') THEN 1 ELSE 0 END), 0)
    FROM ban_history
    WHERE timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch;"
}

db_history_report_stats() {
    local start_epoch="$1"
    local end_epoch="$2"
    local busiest_start="$3"

    db_query "SELECT
        COALESCE(SUM(CASE WHEN action='BAN' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN action='UNBAN' THEN 1 ELSE 0 END), 0),
        COALESCE(COUNT(DISTINCT CASE WHEN action='BAN' THEN client_ip END), 0),
        COALESCE(SUM(CASE WHEN action='BAN' AND (duration LIKE '%PERMANENT%' OR duration LIKE '%permanent%') THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN action='BAN' AND reason LIKE '%rate%limit%' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN action='BAN' AND reason LIKE '%subdomain%flood%' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN action='BAN' AND reason LIKE '%external%blocklist%' THEN 1 ELSE 0 END), 0)
    FROM ban_history
    WHERE timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch;"
}

db_history_busiest_day() {
    local start_epoch="$1"
    local end_epoch="$2"

    db_query "SELECT substr(timestamp_text, 1, 10), COUNT(*)
    FROM ban_history
    WHERE action='BAN' AND timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch
    GROUP BY substr(timestamp_text, 1, 10)
    ORDER BY COUNT(*) DESC
    LIMIT 1;"
}

db_history_top_ips() {
    local start_epoch="$1"
    local end_epoch="$2"
    local limit="${3:-10}"

    db_query "SELECT COUNT(*), client_ip
    FROM ban_history
    WHERE action='BAN' AND timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch
    GROUP BY client_ip
    ORDER BY COUNT(*) DESC
    LIMIT $limit;"
}

db_history_top_domains() {
    local start_epoch="$1"
    local end_epoch="$2"
    local limit="${3:-10}"

    db_query "SELECT COUNT(*), domain
    FROM ban_history
    WHERE action='BAN' AND domain != '-' AND domain != '' AND timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch
    GROUP BY domain
    ORDER BY COUNT(*) DESC
    LIMIT $limit;"
}

db_history_protocol_stats() {
    local start_epoch="$1"
    local end_epoch="$2"

    db_query "SELECT COUNT(*), COALESCE(NULLIF(protocol, ''), 'unbekannt')
    FROM ban_history
    WHERE action='BAN' AND timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch
    GROUP BY COALESCE(NULLIF(protocol, ''), 'unbekannt')
    ORDER BY COUNT(*) DESC;"
}

db_history_recent_bans() {
    local start_epoch="$1"
    local end_epoch="$2"
    local limit="${3:-10}"

    db_query "SELECT timestamp_text, action, client_ip, domain, count, duration, protocol, reason
    FROM ban_history
    WHERE action='BAN' AND timestamp_epoch >= $start_epoch AND timestamp_epoch <= $end_epoch
    ORDER BY id DESC
    LIMIT $limit;"
}

# ─── Whitelist-Funktionen ───────────────────────────────────────────────────

db_whitelist_contains() {
    local ip=$(_db_escape "$1")
    local result
    result=$(db_query "SELECT 1 FROM whitelist_cache WHERE ip_address='$ip' LIMIT 1;")
    [[ -n "$result" ]]
}

db_whitelist_sync() {
    local source=$(_db_escape "${1:-external}")
    local tmp_sql=""
    tmp_sql="BEGIN TRANSACTION; DELETE FROM whitelist_cache;"
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        local safe_ip=$(_db_escape "$ip")
        tmp_sql+=" INSERT OR IGNORE INTO whitelist_cache (ip_address, source) VALUES ('$safe_ip', '$source');"
    done
    tmp_sql+=" COMMIT;"
    db_exec "$tmp_sql"
}

db_whitelist_count() {
    db_query "SELECT COUNT(*) FROM whitelist_cache;"
}

db_whitelist_get_all() {
    db_query "SELECT ip_address FROM whitelist_cache;"
}

db_whitelist_clear() {
    db_exec "DELETE FROM whitelist_cache;"
}

# ─── Migration von Flat-Files ───────────────────────────────────────────────

db_migrate_from_files() {
    # Bereits migriert?
    if [[ -f "$_DB_MIGRATION_MARKER" ]]; then
        return 0
    fi

    local migrated=0
    local backup_dir="${STATE_DIR}/.backup_pre_sqlite"

    # ─── .ban-Dateien migrieren ──────────────────────────────────────────
    local ban_sql="BEGIN TRANSACTION;"
    local ban_count=0

    for state_file in "${STATE_DIR}"/*.ban "${STATE_DIR}"/ext_*.ban; do
        [[ -f "$state_file" ]] || continue
        local basename_f
        basename_f=$(basename "$state_file")

        local s_ip s_domain s_count s_ban_time s_ban_until_epoch s_ban_duration
        local s_offense_level s_is_permanent s_reason s_protocol s_source
        local s_geoip_country s_geoip_mode

        s_ip=$(grep '^CLIENT_IP=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        [[ -z "$s_ip" ]] && continue

        s_domain=$(grep '^DOMAIN=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_count=$(grep '^COUNT=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_ban_time=$(grep '^BAN_TIME=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_ban_until_epoch=$(grep '^BAN_UNTIL_EPOCH=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_ban_duration=$(grep '^BAN_DURATION=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_offense_level=$(grep '^OFFENSE_LEVEL=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_is_permanent=$(grep '^IS_PERMANENT=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_reason=$(grep '^REASON=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_protocol=$(grep '^PROTOCOL=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_geoip_country=$(grep '^GEOIP_COUNTRY=' "$state_file" 2>/dev/null | cut -d= -f2 || true)
        s_geoip_mode=$(grep '^GEOIP_MODE=' "$state_file" 2>/dev/null | cut -d= -f2 || true)

        # Source bestimmen
        if [[ "$basename_f" == ext_* ]]; then
            s_source="external-blocklist"
        elif [[ "$s_reason" == "geoip" ]]; then
            s_source="geoip"
        else
            s_source="monitor"
        fi

        # Boolean zu Integer
        local perm_int=0
        [[ "$s_is_permanent" == "true" ]] && perm_int=1

        s_ip=$(_db_escape "$s_ip")
        s_domain=$(_db_escape "${s_domain:--}")
        s_ban_time=$(_db_escape "${s_ban_time:-}")
        s_reason=$(_db_escape "${s_reason:-rate-limit}")
        s_protocol=$(_db_escape "${s_protocol:-DNS}")
        s_geoip_country=$(_db_escape "${s_geoip_country:-}")
        s_geoip_mode=$(_db_escape "${s_geoip_mode:-}")

        ban_sql+=" INSERT OR IGNORE INTO active_bans (client_ip, domain, count, ban_time, ban_until_epoch, ban_duration, offense_level, is_permanent, reason, protocol, source, geoip_country, geoip_mode) VALUES ('$s_ip', '$s_domain', ${s_count:-0}, '$s_ban_time', ${s_ban_until_epoch:-0}, ${s_ban_duration:-0}, ${s_offense_level:-0}, $perm_int, '$s_reason', '$s_protocol', '$s_source', '$s_geoip_country', '$s_geoip_mode');"
        ban_count=$((ban_count + 1))
    done
    ban_sql+=" COMMIT;"

    if [[ $ban_count -gt 0 ]]; then
        db_exec "$ban_sql"
        migrated=$((migrated + ban_count))
    fi

    # ─── .offenses-Dateien migrieren ─────────────────────────────────────
    local offense_sql="BEGIN TRANSACTION;"
    local offense_count=0

    for offense_file in "${STATE_DIR}"/*.offenses; do
        [[ -f "$offense_file" ]] || continue

        local o_ip o_level o_last_epoch o_last o_first
        o_ip=$(grep '^CLIENT_IP=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)
        [[ -z "$o_ip" ]] && continue

        o_level=$(grep '^OFFENSE_LEVEL=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)
        o_last_epoch=$(grep '^LAST_OFFENSE_EPOCH=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)
        o_last=$(grep '^LAST_OFFENSE=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)
        o_first=$(grep '^FIRST_OFFENSE=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)

        o_ip=$(_db_escape "$o_ip")
        o_last=$(_db_escape "${o_last:-}")
        o_first=$(_db_escape "${o_first:-}")

        offense_sql+=" INSERT OR IGNORE INTO offense_tracking (client_ip, offense_level, last_offense_epoch, last_offense, first_offense) VALUES ('$o_ip', ${o_level:-0}, ${o_last_epoch:-0}, '$o_last', '$o_first');"
        offense_count=$((offense_count + 1))
    done
    offense_sql+=" COMMIT;"

    if [[ $offense_count -gt 0 ]]; then
        db_exec "$offense_sql"
        migrated=$((migrated + offense_count))
    fi

    # ─── Ban-History-Log migrieren ───────────────────────────────────────
    local history_count=0
    if [[ -f "$BAN_HISTORY_FILE" ]]; then
        local history_sql
        history_sql=$(awk '
            /^#/ || /^[[:space:]]*$/ { next }
            {
                n = split($0, f, "|")
                if (n < 2) next
                ts = f[1]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", ts)
                if (length(ts) < 19) next
                ep = mktime(substr(ts,1,4) " " substr(ts,6,2) " " substr(ts,9,2) " " \
                            substr(ts,12,2) " " substr(ts,15,2) " " substr(ts,18,2))
                if (ep < 0) next
                for (i = 1; i <= n; i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", f[i])
                # Single quotes escapen
                gsub(/'\''/, "'\'''\''", f[1])
                gsub(/'\''/, "'\'''\''", f[2])
                gsub(/'\''/, "'\'''\''", f[3])
                gsub(/'\''/, "'\'''\''", f[4])
                gsub(/'\''/, "'\'''\''", f[5])
                gsub(/'\''/, "'\'''\''", f[6])
                gsub(/'\''/, "'\'''\''", f[7])
                gsub(/'\''/, "'\'''\''", f[8])
                printf "INSERT INTO ban_history (timestamp_epoch, timestamp_text, action, client_ip, domain, count, duration, protocol, reason) VALUES (%d, '\''%s'\'', '\''%s'\'', '\''%s'\'', '\''%s'\'', '\''%s'\'', '\''%s'\'', '\''%s'\'', '\''%s'\'');\n", \
                    ep, f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]
                count++
            }
            END { print "-- migrated " count+0 " history entries" }
        ' "$BAN_HISTORY_FILE")

        if [[ -n "$history_sql" ]]; then
            echo "BEGIN TRANSACTION; $history_sql COMMIT;" | sqlite3 "$DB_FILE" 2>/dev/null
            history_count=$(echo "$history_sql" | grep -c '^INSERT' || true)
            migrated=$((migrated + history_count))
        fi
    fi

    # ─── Whitelist-Cache migrieren ───────────────────────────────────────
    local wl_file="${EXTERNAL_WHITELIST_CACHE_DIR:-/var/lib/adguard-shield/external-whitelist}/resolved_ips.txt"
    local wl_count=0
    if [[ -f "$wl_file" ]]; then
        local wl_sql="BEGIN TRANSACTION;"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            local safe_ip=$(_db_escape "$ip")
            wl_sql+=" INSERT OR IGNORE INTO whitelist_cache (ip_address, source) VALUES ('$safe_ip', 'external');"
            wl_count=$((wl_count + 1))
        done < "$wl_file"
        wl_sql+=" COMMIT;"

        if [[ $wl_count -gt 0 ]]; then
            db_exec "$wl_sql"
            migrated=$((migrated + wl_count))
        fi
    fi

    # ─── Alte Dateien in Backup verschieben ──────────────────────────────
    if [[ $migrated -gt 0 ]]; then
        mkdir -p "$backup_dir"

        for f in "${STATE_DIR}"/*.ban "${STATE_DIR}"/ext_*.ban; do
            [[ -f "$f" ]] || continue
            mv "$f" "$backup_dir/" 2>/dev/null || true
        done

        for f in "${STATE_DIR}"/*.offenses; do
            [[ -f "$f" ]] || continue
            mv "$f" "$backup_dir/" 2>/dev/null || true
        done

        if [[ -f "$BAN_HISTORY_FILE" ]]; then
            cp "$BAN_HISTORY_FILE" "${backup_dir}/adguard-shield-bans.log.bak" 2>/dev/null || true
        fi

        if [[ -f "$wl_file" ]]; then
            cp "$wl_file" "${backup_dir}/resolved_ips.txt.bak" 2>/dev/null || true
        fi
    fi

    # Migrations-Marker setzen
    echo "migrated_at=$(date '+%Y-%m-%d %H:%M:%S')" > "$_DB_MIGRATION_MARKER"
    echo "bans=$ban_count" >> "$_DB_MIGRATION_MARKER"
    echo "offenses=$offense_count" >> "$_DB_MIGRATION_MARKER"
    echo "history=$history_count" >> "$_DB_MIGRATION_MARKER"
    echo "whitelist=$wl_count" >> "$_DB_MIGRATION_MARKER"

    echo "$migrated"
}
