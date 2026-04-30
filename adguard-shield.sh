#!/bin/bash
###############################################################################
# AdGuard Shield
# Überwacht DNS-Anfragen und sperrt Clients bei Überschreitung des Limits
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

VERSION="v1.0.0"

set -euo pipefail

# Fehler-Trap: Bei unerwartetem Abbruch Fehlerdetails ausgeben
trap 'echo "[$(date "+%Y-%m-%d %H:%M:%S")] [ERROR] Unerwarteter Fehler in Zeile $LINENO (Exit-Code: $?)" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-shield.conf"

# ─── Konfiguration laden ───────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "FEHLER: Konfigurationsdatei nicht gefunden: $CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=adguard-shield.conf
source "$CONFIG_FILE"

# ─── Datenbank-Bibliothek laden ───────────────────────────────────────────────
# shellcheck source=db.sh
source "${SCRIPT_DIR}/db.sh"

# ─── Abhängigkeiten prüfen ────────────────────────────────────────────────────
check_dependencies() {
    local missing=()
    for cmd in curl jq iptables ip6tables date sqlite3; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "ERROR" "Fehlende Abhängigkeiten: ${missing[*]}"
        echo "Bitte installieren: sudo apt install ${missing[*]}" >&2
        exit 1
    fi
}

# ─── Logging ──────────────────────────────────────────────────────────────────
declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)

log() {
    local level="$1"
    shift
    local message="$*"
    local configured_level="${LOG_LEVEL:-INFO}"

    if [[ ${LOG_LEVELS[$level]:-1} -ge ${LOG_LEVELS[$configured_level]:-1} ]]; then
        local timestamp
        timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
        local log_entry="[$timestamp] [$level] $message"

        echo "$log_entry" | tee -a "$LOG_FILE"

        # Log-Rotation prüfen
        if [[ -f "$LOG_FILE" ]]; then
            local size_kb
            size_kb=$(du -k "$LOG_FILE" 2>/dev/null | cut -f1)
            local max_kb=$((LOG_MAX_SIZE_MB * 1024))
            if [[ ${size_kb:-0} -gt $max_kb ]]; then
                mv "$LOG_FILE" "${LOG_FILE}.old"
                log "INFO" "Log-Datei rotiert"
            fi
        fi
    fi
}

# ─── Ban-History ─────────────────────────────────────────────────────────────
log_ban_history() {
    local action="$1"
    local client_ip="$2"
    local domain="${3:-}"
    local count="${4:-}"
    local reason="${5:-}"
    local duration="${6:-}"
    local protocol="${7:-}"

    if [[ -z "$duration" && "$action" == "BAN" ]]; then
        duration="${BAN_DURATION}s"
    fi
    [[ -z "$duration" ]] && duration="-"
    [[ -z "$protocol" ]] && protocol="-"

    db_history_add "$action" "$client_ip" "${domain:--}" "${count:--}" "${reason:-rate-limit}" "$duration" "$protocol"
}

# ─── Progressive Ban (Recidive) ─────────────────────────────────────────────
get_offense_level() {
    local client_ip="$1"
    local level
    level=$(db_offense_get_level "$client_ip" "${PROGRESSIVE_BAN_RESET_AFTER:-86400}")
    echo "$level"
}

increment_offense_level() {
    local client_ip="$1"
    db_offense_increment "$client_ip"
}

# Berechnet die Sperrdauer basierend auf der Offense-Stufe
calculate_ban_duration() {
    local offense_level="$1"
    local base_duration="${BAN_DURATION:-3600}"
    local multiplier="${PROGRESSIVE_BAN_MULTIPLIER:-2}"
    local max_level="${PROGRESSIVE_BAN_MAX_LEVEL:-5}"

    # Progressive Bans deaktiviert? → Standard-Dauer
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" != "true" ]]; then
        echo "$base_duration"
        return
    fi

    # Permanente Sperre ab max_level (0 = nie permanent)
    if [[ "$max_level" -gt 0 && "$offense_level" -ge "$max_level" ]]; then
        echo "0"  # 0 = permanent
        return
    fi

    # Exponentielle Steigerung: base × multiplier^(level-1)
    # Stufe 1: base × 1, Stufe 2: base × mult, Stufe 3: base × mult², ...
    if [[ "$offense_level" -le 1 ]]; then
        echo "$base_duration"
    else
        local power=$((offense_level - 1))
        local factor=1
        for ((i=0; i<power; i++)); do
            factor=$((factor * multiplier))
        done
        echo $((base_duration * factor))
    fi
}

# Formatiert Sekunden in eine lesbare Dauer-Angabe
format_duration() {
    local seconds="$1"
    if [[ "$seconds" -eq 0 ]]; then
        echo "PERMANENT"
        return
    fi
    if [[ "$seconds" -ge 86400 ]]; then
        echo "$((seconds / 86400))d $((seconds % 86400 / 3600))h"
    elif [[ "$seconds" -ge 3600 ]]; then
        echo "$((seconds / 3600))h $((seconds % 3600 / 60))m"
    elif [[ "$seconds" -ge 60 ]]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    else
        echo "${seconds}s"
    fi
}

reset_offense_level() {
    local client_ip="$1"
    db_offense_delete "$client_ip"
}

# ─── Protokoll-Erkennung ─────────────────────────────────────────────────────
# Wandelt AdGuard Home client_proto Werte in lesbare Protokoll-Namen um
# API-Werte: "" = Plain DNS, "doh" = DNS-over-HTTPS, "dot" = DNS-over-TLS,
#            "doq" = DNS-over-QUIC, "dnscrypt" = DNSCrypt
format_protocol() {
    local proto="$1"
    case "${proto,,}" in
        doh)      echo "DoH"      ;;
        dot)      echo "DoT"      ;;
        doq)      echo "DoQ"      ;;
        dnscrypt) echo "DNSCrypt" ;;
        ""|dns)   echo "DNS"      ;;
        *)        echo "${proto:-DNS}" ;;
    esac
}

# ─── Hostname-Auflösung ──────────────────────────────────────────────────────
# Versucht den Hostnamen einer IP per Reverse-DNS aufzulösen
resolve_hostname() {
    local ip="$1"
    local hostname=""

    # Versuche Reverse-DNS-Auflösung via dig
    if command -v dig &>/dev/null; then
        hostname=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
    fi

    # Fallback via host
    if [[ -z "$hostname" ]] && command -v host &>/dev/null; then
        hostname=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF}' | sed 's/\.$//' | head -1)
    fi

    # Fallback via getent
    if [[ -z "$hostname" ]] && command -v getent &>/dev/null; then
        hostname=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -1)
    fi

    echo "${hostname:-(unbekannt)}"
}

# ─── AbuseIPDB Reporting ─────────────────────────────────────────────────────
# Meldet eine IP an AbuseIPDB (nur bei permanenten Sperren)
report_to_abuseipdb() {
    local client_ip="$1"
    local domain="$2"
    local count="$3"
    local reason="${4:-rate-limit}"
    local window="${5:-$RATE_LIMIT_WINDOW}"

    if [[ "${ABUSEIPDB_ENABLED:-false}" != "true" ]]; then
        return 0
    fi

    if [[ -z "${ABUSEIPDB_API_KEY:-}" ]]; then
        log "WARN" "AbuseIPDB: API-Key nicht konfiguriert (ABUSEIPDB_API_KEY ist leer)"
        return 1
    fi

    # Kommentar für AbuseIPDB erstellen (englisch)
    local comment
    if [[ "$reason" == "subdomain-flood" ]]; then
        comment="DNS flooding on our DNS server: ${count}x ${domain} in ${window}s (random subdomain attack). Banned by Adguard Shield 🔗 https://tnvs.de/as"
    else
        comment="DNS flooding on our DNS server: ${count}x ${domain} in ${window}s. Banned by Adguard Shield 🔗 https://tnvs.de/as"
    fi

    local categories="${ABUSEIPDB_CATEGORIES:-4}"

    log "INFO" "AbuseIPDB: Melde IP $client_ip (${comment})"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 15 \
        -X POST "https://api.abuseipdb.com/api/v2/report" \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: application/json" \
        --data-urlencode "ip=${client_ip}" \
        --data-urlencode "categories=${categories}" \
        --data-urlencode "comment=${comment}" \
        2>/dev/null) || true

    if [[ "$http_code" == "200" || "$http_code" == "429" ]]; then
        if [[ "$http_code" == "429" ]]; then
            log "WARN" "AbuseIPDB: Rate-Limit erreicht für $client_ip (HTTP 429) – Report wird später erneut versucht"
        else
            log "INFO" "AbuseIPDB: IP $client_ip erfolgreich gemeldet (HTTP $http_code)"
        fi
    else
        log "ERROR" "AbuseIPDB: Meldung fehlgeschlagen für $client_ip (HTTP ${http_code:-timeout})"
    fi
}

# ─── Verzeichnisse und Datenbank erstellen ───────────────────────────────────
init_directories() {
    mkdir -p "$STATE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$PID_FILE")"

    db_init

    # Migration von Flat-Files (einmalig beim ersten Start nach Update)
    if [[ ! -f "$_DB_MIGRATION_MARKER" ]]; then
        local migrated
        migrated=$(db_migrate_from_files)
        if [[ "${migrated:-0}" -gt 0 ]]; then
            log "INFO" "SQLite-Migration abgeschlossen: $migrated Eintraege migriert"
            log "INFO" "Backup der alten Dateien: ${STATE_DIR}/.backup_pre_sqlite/"
        fi
    fi
}

# ─── PID-Management ──────────────────────────────────────────────────────────
write_pid() {
    echo $$ > "$PID_FILE"
}

cleanup() {
    log "INFO" "AdGuard Shield wird beendet..."
    # Service-Stop-Benachrichtigung senden
    if [[ "${NOTIFY_ENABLED:-false}" == "true" ]]; then
        send_notification "service_stop" "" "" ""
        # Kurz warten damit die Benachrichtigung gesendet wird (curl läuft im Hintergrund)
        sleep 1
    fi
    stop_blocklist_worker
    stop_whitelist_worker
    stop_geoip_worker
    stop_offense_cleanup_worker
    rm -f "$PID_FILE"
    exit 0
}

check_already_running() {
    if [[ -f "$PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "Monitor läuft bereits (PID: $old_pid). Beende." >&2
            exit 1
        else
            rm -f "$PID_FILE"
        fi
    fi
}

# ─── Whitelist Prüfung ───────────────────────────────────────────────────────
is_whitelisted() {
    local ip="$1"
    IFS=',' read -ra wl_entries <<< "$WHITELIST"
    for entry in "${wl_entries[@]}"; do
        entry=$(echo "$entry" | xargs)
        if [[ "$ip" == "$entry" ]]; then
            return 0
        fi
    done

    # Externe Whitelist prüfen (SQLite)
    if db_whitelist_contains "$ip"; then
        return 0
    fi

    return 1
}

# ─── DNS-Flood-Watchlist Prüfung ────────────────────────────────────────────
is_dns_flood_watchlist_match() {
    local domain="$1"

    if [[ "${DNS_FLOOD_WATCHLIST_ENABLED:-false}" != "true" ]]; then
        return 1
    fi

    if [[ -z "${DNS_FLOOD_WATCHLIST:-}" ]]; then
        return 1
    fi

    local entry
    IFS=',' read -ra watchlist_entries <<< "$DNS_FLOOD_WATCHLIST"
    for entry in "${watchlist_entries[@]}"; do
        entry=$(echo "$entry" | xargs)
        [[ -z "$entry" ]] && continue

        if [[ "$domain" == "$entry" || "$domain" == *".$entry" ]]; then
            return 0
        fi
    done

    return 1
}

# ─── iptables Chain Setup ────────────────────────────────────────────────────
setup_iptables_chain() {
    # IPv4 Chain erstellen falls nicht vorhanden
    if ! iptables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        log "INFO" "Erstelle iptables Chain: $IPTABLES_CHAIN (IPv4)"
        iptables -N "$IPTABLES_CHAIN"

        # Chain in INPUT einhängen für alle relevanten Ports
        for port in $BLOCKED_PORTS; do
            iptables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            iptables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
    fi

    # IPv6 Chain erstellen falls nicht vorhanden
    if ! ip6tables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        log "INFO" "Erstelle ip6tables Chain: $IPTABLES_CHAIN (IPv6)"
        ip6tables -N "$IPTABLES_CHAIN"

        for port in $BLOCKED_PORTS; do
            ip6tables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            ip6tables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
    fi
}

# ─── Client sperren ─────────────────────────────────────────────────────────
ban_client() {
    local client_ip="$1"
    local domain="$2"
    local count="$3"
    local reason="${4:-rate-limit}"
    local window="${5:-$RATE_LIMIT_WINDOW}"
    local protocol="${6:-DNS}"

    # Prüfen ob bereits gesperrt
    if db_ban_exists "$client_ip"; then
        log "DEBUG" "Client $client_ip ist bereits gesperrt"
        return 0
    fi

    # Progressive Ban: Offense-Level ermitteln und Sperrdauer berechnen
    local offense_level=0
    local effective_duration="$BAN_DURATION"
    local is_permanent=false

    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
        offense_level=$(increment_offense_level "$client_ip")
        effective_duration=$(calculate_ban_duration "$offense_level")

        if [[ "$effective_duration" -eq 0 ]]; then
            is_permanent=true
        fi
    fi

    # DNS-Flood-Watchlist: Sofort permanent sperren
    if [[ "$reason" == "dns-flood-watchlist" ]]; then
        is_permanent=true
        effective_duration=0
        log "WARN" "DNS-Flood-Watchlist: Erzwinge permanente Sperre für $client_ip ($domain)"
    fi

    local ban_until
    local ban_until_display
    if [[ "$is_permanent" == "true" ]]; then
        ban_until=0  # 0 = permanent
        ban_until_display="PERMANENT"
    else
        ban_until=$(date -d "+${effective_duration} seconds" '+%s' 2>/dev/null || date -v "+${effective_duration}S" '+%s')
        ban_until_display=$(date -d "@$ban_until" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$ban_until" '+%Y-%m-%d %H:%M:%S')
    fi

    local duration_display
    duration_display=$(format_duration "$effective_duration")

    if [[ "$DRY_RUN" == "true" ]]; then
        if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && "$reason" != "dns-flood-watchlist" ]]; then
            log "WARN" "[DRY-RUN] WÜRDE sperren: $client_ip (${count}x $domain in ${window}s via $protocol) für ${duration_display} [Stufe $offense_level] [${reason}]"
        else
            log "WARN" "[DRY-RUN] WÜRDE sperren: $client_ip (${count}x $domain in ${window}s via $protocol) für ${duration_display} [${reason}]"
        fi
        log_ban_history "DRY" "$client_ip" "$domain" "$count" "dry-run (${reason})" "${duration_display}" "$protocol"
        return 0
    fi

    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && "$reason" != "dns-flood-watchlist" ]]; then
        log "WARN" "SPERRE Client: $client_ip (${count}x $domain in ${window}s via $protocol) für ${duration_display} [Stufe ${offense_level}/${PROGRESSIVE_BAN_MAX_LEVEL:-0}] [${reason}]"
    else
        log "WARN" "SPERRE Client: $client_ip (${count}x $domain in ${window}s via $protocol) für ${duration_display} [${reason}]"
    fi

    # IPv4 oder IPv6 erkennen
    if [[ "$client_ip" == *:* ]]; then
        # IPv6
        ip6tables -I "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    else
        # IPv4
        iptables -I "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    fi

    # State in Datenbank speichern
    local perm_int=0
    [[ "$is_permanent" == "true" ]] && perm_int=1
    db_ban_insert "$client_ip" "$domain" "$count" "$(date '+%Y-%m-%d %H:%M:%S')" "$ban_until" "$effective_duration" "$offense_level" "$perm_int" "$reason" "$protocol" "monitor"

    # Ban-History Eintrag
    local history_duration="${duration_display}"
    [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && "$reason" != "dns-flood-watchlist" ]] && history_duration="${duration_display} (Stufe ${offense_level})"
    log_ban_history "BAN" "$client_ip" "$domain" "$count" "$reason" "$history_duration" "$protocol"

    # Benachrichtigung senden
    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "ban" "$client_ip" "$domain" "$count" "$offense_level" "$duration_display" "$reason" "$window" "$protocol" "$is_permanent"
    fi

    # AbuseIPDB Report (nur bei permanenter Sperre)
    if [[ "$is_permanent" == "true" ]]; then
        report_to_abuseipdb "$client_ip" "$domain" "$count" "$reason" "$window" &
    fi
}

# ─── Client entsperren ──────────────────────────────────────────────────────
unban_client() {
    local client_ip="$1"
    local reason="${2:-expired}"

    # Domain und Protokoll aus DB lesen bevor wir loeschen
    local ban_data
    ban_data=$(db_ban_get "$client_ip")
    local domain="-"
    local protocol="-"
    if [[ -n "$ban_data" ]]; then
        IFS='|' read -r _ b_domain _ _ _ _ _ _ _ b_protocol _ _ _ <<< "$ban_data"
        domain="${b_domain:--}"
        protocol="${b_protocol:--}"
    fi

    log "INFO" "ENTSPERRE Client: $client_ip ($reason)"

    if [[ "$client_ip" == *:* ]]; then
        ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    else
        iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    fi

    db_ban_delete "$client_ip"

    log_ban_history "UNBAN" "$client_ip" "$domain" "-" "$reason" "-" "$protocol"

    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "unban" "$client_ip" "$domain" ""
    fi
}

# ─── Abgelaufene Sperren aufheben ───────────────────────────────────────────
check_expired_bans() {
    local expired_ips
    expired_ips=$(db_ban_get_expired)
    [[ -z "$expired_ips" ]] && return

    while IFS= read -r client_ip; do
        [[ -z "$client_ip" ]] && continue
        unban_client "$client_ip" "expired"
    done <<< "$expired_ips"
}

# ─── Benachrichtigungen ─────────────────────────────────────────────────────
send_notification() {
    local action="$1"
    local client_ip="$2"
    local domain="$3"
    local count="$4"
    local offense_level="${5:-}"
    local duration_display="${6:-}"
    local reason="${7:-rate-limit}"
    local window="${8:-$RATE_LIMIT_WINDOW}"
    local protocol="${9:-DNS}"
    local is_permanent="${10:-false}"

    # Ntfy benötigt keine Webhook-URL (nutzt NTFY_SERVER_URL + NTFY_TOPIC)
    if [[ "$NOTIFY_TYPE" != "ntfy" && -z "$NOTIFY_WEBHOOK_URL" ]]; then
        return
    fi

    local reason_label="Rate-Limit"
    [[ "$reason" == "subdomain-flood" ]] && reason_label="Subdomain-Flood"
    [[ "$reason" == "dns-flood-watchlist" ]] && reason_label="DNS-Flood-Watchlist"

    local title
    local message
    local my_hostname
    my_hostname=$(hostname)

    if [[ "$action" == "ban" ]]; then
        title="🚨 🛡️ AdGuard Shield"
        local client_hostname
        client_hostname=$(resolve_hostname "$client_ip")

        # AbuseIPDB-Hinweis bei permanenter Sperre
        local abuseipdb_hint=""
        if [[ "$is_permanent" == "true" && "${ABUSEIPDB_ENABLED:-false}" == "true" ]]; then
            abuseipdb_hint=$'\n⚠️ IP wurde an AbuseIPDB gemeldet'
        fi

        # Dauer-Anzeige mit Stufe (nicht bei Watchlist – dort ist es immer permanent)
        local dur_line
        if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && -n "$offense_level" && "$reason" != "dns-flood-watchlist" ]]; then
            dur_line="**${duration_display}** [Stufe ${offense_level}/${PROGRESSIVE_BAN_MAX_LEVEL:-0}]"
        else
            dur_line="**${duration_display}**"
        fi

        message="🚫 AdGuard Shield Ban auf ${my_hostname}${abuseipdb_hint}
---
IP: ${client_ip}
Hostname: ${client_hostname}
Grund: ${count}x ${domain} in ${window}s via ${protocol}, ${reason_label}
Dauer: ${dur_line}

Whois: https://www.whois.com/whois/${client_ip}
AbuseIPDB: https://www.abuseipdb.com/check/${client_ip}"

    elif [[ "$action" == "unban" ]]; then
        title="✅ AdGuard Shield"
        local client_hostname
        client_hostname=$(resolve_hostname "$client_ip")

        message="✅ AdGuard Shield Freigabe auf ${my_hostname}
---
IP: ${client_ip}
Hostname: ${client_hostname}

AbuseIPDB: https://www.abuseipdb.com/check/${client_ip}"

    elif [[ "$action" == "service_start" ]]; then
        title="✅ AdGuard Shield"
        message="🟢 AdGuard Shield ${VERSION} wurde auf ${my_hostname} gestartet."
    elif [[ "$action" == "service_stop" ]]; then
        title="🚨 🛡️ AdGuard Shield"
        message="🔴 AdGuard Shield ${VERSION} wurde auf ${my_hostname} gestoppt."
    fi

    case "$NOTIFY_TYPE" in
        discord)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" '{content: $msg}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
        slack)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" '{text: $msg}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
        gotify)
            local clean_message
            clean_message=$(echo "$message" | sed 's/\*\*//g')
            curl -s -X POST "$NOTIFY_WEBHOOK_URL" \
                -F "title=${title}" \
                -F "message=${clean_message}" \
                -F "priority=5" &>/dev/null &
            ;;
        ntfy)
            send_ntfy_notification "$action" "$title" "$message"
            ;;
        generic)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" --arg act "$action" --arg cl "${client_ip:-}" --arg dom "${domain:-}" \
                '{message: $msg, action: $act, client: $cl, domain: $dom}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
    esac
}

# ─── Ntfy Benachrichtigung ───────────────────────────────────────────────────
send_ntfy_notification() {
    local action="$1"
    local title="$2"
    local message="$3"

    if [[ -z "${NTFY_TOPIC:-}" ]]; then
        log "WARN" "Ntfy: Kein Topic konfiguriert (NTFY_TOPIC ist leer)"
        return 1
    fi

    local ntfy_url="${NTFY_SERVER_URL:-https://ntfy.sh}"
    local priority="${NTFY_PRIORITY:-4}"
    local tags

    if [[ "$action" == "ban" ]]; then
        tags="rotating_light,ban"
    elif [[ "$action" == "service_start" ]]; then
        tags="green_circle,start"
    elif [[ "$action" == "service_stop" ]]; then
        tags="red_circle,stop"
    else
        tags="white_check_mark,unban"
    fi

    # Markdown-Formatierung entfernen für Ntfy
    local clean_message
    clean_message=$(echo "$message" | sed 's/\*\*//g')

    # Ntfy fügt Emojis über Tags hinzu → Titel ohne führende Emojis setzen
    local ntfy_title
    case "$action" in
        ban)           ntfy_title="🛡️ AdGuard Shield" ;;
        *)             ntfy_title="AdGuard Shield" ;;
    esac

    local -a curl_args=(
        -s
        -X POST
        "${ntfy_url}/${NTFY_TOPIC}"
        -H "Title: ${ntfy_title}"
        -H "Priority: ${priority}"
        -H "Tags: ${tags}"
        -d "${clean_message}"
    )

    # Token hinzufügen falls konfiguriert
    if [[ -n "${NTFY_TOKEN:-}" ]]; then
        curl_args+=(-H "Authorization: Bearer ${NTFY_TOKEN}")
    fi

    curl "${curl_args[@]}" &>/dev/null &
}

# ─── AdGuard Home API abfragen ──────────────────────────────────────────────
query_adguard_log() {
    # Hinweis: Zeitfilterung erfolgt client-seitig in analyze_queries(),
    # da die AdGuard API keinen "newer_than" Parameter unterstützt.

    local response
    response=$(curl -s -u "${ADGUARD_USER}:${ADGUARD_PASS}" \
        --connect-timeout 5 \
        --max-time 10 \
        "${ADGUARD_URL}/control/querylog?limit=${API_QUERY_LIMIT}&response_status=all" 2>/dev/null)

    if [[ -z "$response" || "$response" == "null" ]]; then
        log "ERROR" "Keine Antwort von AdGuard Home API"
        return 1
    fi

    # Prüfen ob die Antwort gültiges JSON ist
    if ! echo "$response" | jq . &>/dev/null; then
        log "ERROR" "Ungültige API-Antwort (kein JSON)"
        return 1
    fi

    echo "$response"
}

# ─── Anfragen analysieren ───────────────────────────────────────────────────
analyze_queries() {
    local api_response="$1"
    local now_epoch
    now_epoch=$(date '+%s')
    local window_start=$((now_epoch - RATE_LIMIT_WINDOW))

    # Anzahl der API-Einträge loggen
    local entry_count
    entry_count=$(echo "$api_response" | jq '.data // [] | length' 2>/dev/null || echo "0")
    log "INFO" "API-Abfrage: ${entry_count} Einträge erhalten, prüfe Zeitfenster ${RATE_LIMIT_WINDOW}s..."

    # Extrahiere Client-IP + Domain + Protokoll Paare aus dem Zeitfenster
    # und zähle die Häufigkeit pro (client, domain) Kombination
    # Unterstützt .question.name (alte API) und .question.host (neue API)
    # Unterstützt Timestamps mit UTC ("Z") und Zeitzonen-Offset ("+01:00")
    # Protokoll: client_proto aus der API → ""/dns = Plain DNS, doh, dot, doq, dnscrypt
    local violations=""
    violations=$(echo "$api_response" | jq -r --argjson window_start "$window_start" '
        # ISO 8601 Timestamp zu Unix-Epoch konvertieren
        # Unterstützt: "2026-03-03T20:01:48Z", "2026-03-03T20:01:48.123Z",
        #              "2026-03-03T20:01:48+01:00", "2026-03-03T20:01:48.123+01:00"
        def to_epoch:
            sub("\\.[0-9]+(?=[+-Z])"; "") |
            if endswith("Z") then
                fromdateiso8601
            elif test("[+-][0-9]{2}:[0-9]{2}$") then
                # Zeitzonen-Offset per String-Slicing extrahieren (zuverlässiger als Regex)
                # Letzten 6 Zeichen = "+01:00" bzw. "-05:00"
                (.[:-6]) as $base |
                (.[-6:-5]) as $sign |
                (.[-5:-3] | tonumber) as $h |
                (.[-2:] | tonumber) as $m |
                ($base + "Z" | fromdateiso8601) +
                (if $sign == "+" then -1 else 1 end * ($h * 3600 + $m * 60))
            else
                fromdateiso8601
            end;

        .data // [] | 
        [.[] | 
            select(.time != null) |
            select((.time | to_epoch) >= $window_start) |
            {
                client: (.client // .client_info.ip // "unknown"),
                domain: ((.question.name // .question.host // "unknown") | rtrimstr(".")),
                proto: (.client_proto // "")
            }
        ] |
        group_by(.client + "|" + .domain) |
        map({
            client: .[0].client,
            domain: .[0].domain,
            count: length,
            protocols: ([.[].proto | if . == "" then "dns" else . end] | unique | join(","))
        }) |
        .[] |
        select(.count > 0) |
        "\(.client)|\(.domain)|\(.count)|\(.protocols)"
    ') || {
        log "ERROR" "jq Analyse fehlgeschlagen - API-Antwort-Format prüfen (ist AdGuard Home erreichbar?)"
        return
    }

    if [[ -z "$violations" ]]; then
        log "INFO" "Keine Anfragen im Zeitfenster gefunden"
        return
    fi

    # Prüfe jede Kombination gegen das Limit
    while IFS='|' read -r client domain count protocols; do
        [[ -z "$client" || -z "$domain" || -z "$count" ]] && continue

        # Protokoll-Namen formatieren für die Anzeige
        local proto_display=""
        if [[ -n "$protocols" ]]; then
            local -a proto_parts=()
            IFS=',' read -ra raw_protos <<< "$protocols"
            for p in "${raw_protos[@]}"; do
                proto_parts+=("$(format_protocol "$p")")
            done
            proto_display=$(IFS=','; echo "${proto_parts[*]}")
        else
            proto_display="DNS"
        fi

        log "INFO" "Client: $client, Domain: $domain, Anfragen: $count/$RATE_LIMIT_MAX_REQUESTS, Protokoll: $proto_display"

        if [[ "$count" -gt "$RATE_LIMIT_MAX_REQUESTS" ]]; then
            if is_whitelisted "$client"; then
                log "INFO" "Client $client ist auf der Whitelist - keine Sperre (${count}x $domain via $proto_display)"
                continue
            fi

            local ban_reason="rate-limit"
            if is_dns_flood_watchlist_match "$domain"; then
                ban_reason="dns-flood-watchlist"
                log "WARN" "DNS-Flood-Watchlist Treffer: $client → $domain (${count}x in ${RATE_LIMIT_WINDOW}s) → permanenter Ban + AbuseIPDB"
            fi

            ban_client "$client" "$domain" "$count" "$ban_reason" "$RATE_LIMIT_WINDOW" "$proto_display"
        fi
    done <<< "$violations"
}

# ─── Subdomain-Flood-Erkennung ──────────────────────────────────────────────
# Erkennt Random-Subdomain-Attacken: Bots die massenhaft zufällige Subdomains
# einer Domain abfragen (z.B. abc123.microsoft.com, xyz456.microsoft.com, ...)
# Zählt eindeutige Subdomains pro Basisdomain und Client im Zeitfenster
analyze_subdomain_flood() {
    local api_response="$1"

    if [[ "${SUBDOMAIN_FLOOD_ENABLED:-false}" != "true" ]]; then
        return
    fi

    local now_epoch
    now_epoch=$(date '+%s')
    local window="${SUBDOMAIN_FLOOD_WINDOW:-60}"
    local window_start=$((now_epoch - window))
    local max_unique="${SUBDOMAIN_FLOOD_MAX_UNIQUE:-50}"

    log "DEBUG" "Subdomain-Flood-Prüfung: max ${max_unique} eindeutige Subdomains pro Basisdomain in ${window}s"

    # jq-Analyse: Gruppiere nach Client + Basisdomain, zähle eindeutige Subdomains
    local violations=""
    violations=$(echo "$api_response" | jq -r --argjson window_start "$window_start" --argjson max_unique "$max_unique" '
        # Basisdomain extrahieren (eTLD+1)
        # Behandelt gängige Multi-Part-TLDs wie .co.uk, .com.au, .co.jp etc.
        def base_domain:
            split(".") |
            if length <= 2 then join(".")
            elif ((.[-2:] | join(".")) | test("^(co|com|net|org|gov|edu|ac|gv|ne|or|go)\\.[a-z]{2,3}$")) then
                if length >= 3 then .[-3:] | join(".") else join(".") end
            else
                .[-2:] | join(".")
            end;

        # ISO 8601 Timestamp zu Unix-Epoch konvertieren
        def to_epoch:
            sub("\\.[0-9]+(?=[+-Z])"; "") |
            if endswith("Z") then
                fromdateiso8601
            elif test("[+-][0-9]{2}:[0-9]{2}$") then
                (.[:-6]) as $base |
                (.[-6:-5]) as $sign |
                (.[-5:-3] | tonumber) as $h |
                (.[-2:] | tonumber) as $m |
                ($base + "Z" | fromdateiso8601) +
                (if $sign == "+" then -1 else 1 end * ($h * 3600 + $m * 60))
            else
                fromdateiso8601
            end;

        .data // [] |
        [.[] |
            select(.time != null) |
            select((.time | to_epoch) >= $window_start) |
            ((.question.name // .question.host // "unknown") | rtrimstr(".")) as $domain |
            ($domain | base_domain) as $base |
            {
                client: (.client // .client_info.ip // "unknown"),
                domain: $domain,
                base_domain: $base,
                proto: (.client_proto // "")
            }
        ] |
        # Nur Einträge mit echten Subdomains (domain != base_domain)
        [.[] | select(.domain != .base_domain)] |
        group_by(.client + "|" + .base_domain) |
        map({
            client: .[0].client,
            base_domain: .[0].base_domain,
            unique_subdomains: ([.[].domain] | unique | length),
            total_queries: length,
            example_domains: ([.[].domain] | unique | .[0:3] | join(", ")),
            protocols: ([.[].proto | if . == "" then "dns" else . end] | unique | join(","))
        }) |
        .[] |
        select(.unique_subdomains > $max_unique) |
        "\(.client)|\(.base_domain)|\(.unique_subdomains)|\(.total_queries)|\(.example_domains)|\(.protocols)"
    ') || {
        log "ERROR" "jq Subdomain-Flood-Analyse fehlgeschlagen"
        return
    }

    if [[ -z "$violations" ]]; then
        log "DEBUG" "Keine Subdomain-Flood-Verstöße erkannt"
        return
    fi

    # Gefundene Verstöße verarbeiten
    while IFS='|' read -r client base_domain unique_count total_count examples protocols; do
        [[ -z "$client" || -z "$base_domain" || -z "$unique_count" ]] && continue

        # Protokoll-Namen formatieren
        local proto_display=""
        if [[ -n "$protocols" ]]; then
            local -a proto_parts=()
            IFS=',' read -ra raw_protos <<< "$protocols"
            for p in "${raw_protos[@]}"; do
                proto_parts+=("$(format_protocol "$p")")
            done
            proto_display=$(IFS=','; echo "${proto_parts[*]}")
        else
            proto_display="DNS"
        fi

        log "WARN" "Subdomain-Flood erkannt: $client → ${unique_count} eindeutige Subdomains von $base_domain (${total_count} Anfragen via $proto_display, z.B. $examples)"

        if is_whitelisted "$client"; then
            log "INFO" "Client $client ist auf der Whitelist - keine Sperre (Subdomain-Flood: ${unique_count}x $base_domain via $proto_display)"
            continue
        fi

        # Prüfen ob bereits gesperrt
        if db_ban_exists "$client"; then
            log "DEBUG" "Client $client ist bereits gesperrt (Subdomain-Flood übersprungen)"
            continue
        fi

        local ban_reason="subdomain-flood"
        if is_dns_flood_watchlist_match "$base_domain"; then
            ban_reason="dns-flood-watchlist"
            log "WARN" "DNS-Flood-Watchlist Treffer (Subdomain-Flood): $client → *.${base_domain} → permanenter Ban + AbuseIPDB"
        fi

        ban_client "$client" "*.${base_domain}" "$unique_count" "$ban_reason" "$window" "$proto_display"
    done <<< "$violations"
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
show_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield - Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Progressive Ban Info
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
        echo "  📈 Progressive Sperren: AKTIV"
        echo "     Multiplikator: ×${PROGRESSIVE_BAN_MULTIPLIER:-2}"
        echo "     Max-Stufe: ${PROGRESSIVE_BAN_MAX_LEVEL:-0} (0=kein Limit)"
        echo "     Zähler-Reset: $(format_duration "${PROGRESSIVE_BAN_RESET_AFTER:-86400}") ohne Vergehen"
        echo ""
    fi

    # Subdomain-Flood-Schutz Info
    if [[ "${SUBDOMAIN_FLOOD_ENABLED:-false}" == "true" ]]; then
        echo "  🌐 Subdomain-Flood-Schutz: AKTIV"
        echo "     Max eindeutige Subdomains: ${SUBDOMAIN_FLOOD_MAX_UNIQUE:-50} pro Basisdomain"
        echo "     Zeitfenster: ${SUBDOMAIN_FLOOD_WINDOW:-60}s"
        echo ""
    fi

    # DNS-Flood-Watchlist Info
    if [[ "${DNS_FLOOD_WATCHLIST_ENABLED:-false}" == "true" ]]; then
        echo "  🎯 DNS-Flood-Watchlist: AKTIV"
        echo "     Domains: ${DNS_FLOOD_WATCHLIST:-<keine>}"
        echo "     Aktion: Sofort permanenter Ban + AbuseIPDB-Meldung"
        echo ""
    fi

    # GeoIP-Filter Info
    if [[ "${GEOIP_ENABLED:-false}" == "true" ]]; then
        local geoip_mode_label
        [[ "${GEOIP_MODE:-blocklist}" == "blocklist" ]] && geoip_mode_label="Blocklist" || geoip_mode_label="Allowlist"
        echo "  🌍 GeoIP-Filter: AKTIV"
        echo "     Modus: ${geoip_mode_label}"
        echo "     Länder: ${GEOIP_COUNTRIES:-<keine>}"
        echo "     Sperrdauer: PERMANENT (Auto-Unban bei Änderung der Länderliste)"
        echo ""
    fi

    # Aktive Sperren aus Datenbank
    local ban_count=0
    local all_bans
    all_bans=$(db_ban_get_all)

    if [[ -n "$all_bans" ]]; then
        while IFS='|' read -r s_ip s_domain s_count s_ban_time s_ban_until_epoch s_dur s_level s_perm_int s_reason s_proto s_source s_geoip_country s_geoip_mode; do
            [[ -z "$s_ip" ]] && continue
            ban_count=$((ban_count + 1))
            s_reason="${s_reason:-rate-limit}"
            s_proto="${s_proto:-?}"

            local reason_tag=""
            [[ "$s_reason" == "subdomain-flood" ]] && reason_tag=" (Subdomain-Flood)"
            [[ "$s_reason" == "dns-flood-watchlist" ]] && reason_tag=" (DNS-Flood-Watchlist)"

            local count_info=""
            if [[ -n "$s_count" && "$s_count" != "0" && "$s_count" != "-" ]]; then
                if [[ "$s_reason" == "subdomain-flood" ]]; then
                    count_info=", ${s_count} Subdomains"
                else
                    count_info=", ${s_count} Anfragen"
                fi
            fi

            local proto_tag=" via ${s_proto}"

            local s_until_display
            if [[ "$s_ban_until_epoch" == "0" || "$s_perm_int" == "1" ]]; then
                s_until_display="PERMANENT"
            else
                s_until_display=$(date -d "@$s_ban_until_epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$s_ban_until_epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "?")
            fi

            if [[ "$s_perm_int" == "1" && "$s_reason" == "dns-flood-watchlist" ]]; then
                echo "  🚫 Gesperrt: $s_ip → $s_domain [PERMANENT${count_info}${proto_tag}]${reason_tag}"
            elif [[ "$s_perm_int" == "1" ]]; then
                echo "  🚫 Gesperrt: $s_ip → $s_domain [PERMANENT, Stufe ${s_level:-?}${count_info}${proto_tag}]${reason_tag}"
            elif [[ -n "$s_level" && "$s_level" -gt 0 ]]; then
                echo "  🚫 Gesperrt: $s_ip → $s_domain [Stufe ${s_level}, $(format_duration "${s_dur:-$BAN_DURATION}"), bis $s_until_display${count_info}${proto_tag}]${reason_tag}"
            else
                echo "  🚫 Gesperrt: $s_ip → $s_domain [bis $s_until_display${count_info}${proto_tag}]${reason_tag}"
            fi
        done <<< "$all_bans"
    fi

    echo ""
    if [[ $ban_count -eq 0 ]]; then
        echo "  ✅ Keine aktiven Sperren"
    else
        echo "  Gesamt: $ban_count aktive Sperren"
    fi

    # Offense-Informationen anzeigen (Wiederholungstäter)
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
        local offense_data
        offense_data=$(db_offense_get_all)
        local offense_count=0
        local offense_output=""

        if [[ -n "$offense_data" ]]; then
            while IFS='|' read -r o_ip o_level o_last_epoch o_last o_first; do
                [[ -z "$o_ip" ]] && continue
                offense_count=$((offense_count + 1))
                local next_dur
                next_dur=$(calculate_ban_duration "$((o_level + 1))")
                if [[ "$next_dur" -eq 0 ]]; then
                    offense_output+="     ⚠ $o_ip: Stufe $o_level (letztes Vergehen: $o_last) → nächste Sperre: PERMANENT\n"
                else
                    offense_output+="     ⚠ $o_ip: Stufe $o_level (letztes Vergehen: $o_last) → nächste Sperre: $(format_duration "$next_dur")\n"
                fi
            done <<< "$offense_data"
        fi

        if [[ $offense_count -gt 0 ]]; then
            echo ""
            echo "  📋 Wiederholungstäter ($offense_count IPs mit Vorgeschichte):"
            echo -e "$offense_output"
        fi
    fi

    echo ""

    # iptables Regeln anzeigen
    echo "  iptables Regeln ($IPTABLES_CHAIN):"
    if iptables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        iptables -n -L "$IPTABLES_CHAIN" --line-numbers 2>/dev/null | sed 's/^/    /'
    else
        echo "    Chain existiert noch nicht"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Ban-History anzeigen ────────────────────────────────────────────────────
show_history() {
    local lines="${1:-50}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield - Ban History (letzte $lines Einträge)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    local total
    total=$(db_history_count)

    if [[ "${total:-0}" -eq 0 ]]; then
        echo "  Noch keine History vorhanden."
        echo ""
        return
    fi

    echo "  # Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | PROTOKOLL | GRUND"
    echo "  #──────────────────────────────────────────────────────────────────────────────────────────────────"
    echo ""

    local recent
    recent=$(db_history_get_recent "$lines")
    if [[ -n "$recent" ]]; then
        while IFS='|' read -r ts action ip domain count duration protocol reason; do
            printf "  %-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %-10s | %s\n" \
                "$ts" "$action" "$ip" "$domain" "$count" "$duration" "$protocol" "$reason"
        done <<< "$recent"
    fi

    echo ""
    local bans unbans
    bans=$(db_history_count_by_action "BAN")
    unbans=$(db_history_count_by_action "UNBAN")
    echo "  Gesamt: $total Einträge ($bans Sperren, $unbans Entsperrungen)"
    echo "  Datenbank: $DB_FILE"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Alle Sperren aufheben ──────────────────────────────────────────────────
flush_all_bans() {
    log "INFO" "Alle Sperren werden aufgehoben..."

    local all_ips
    all_ips=$(db_query "SELECT client_ip FROM active_bans;")
    if [[ -n "$all_ips" ]]; then
        while IFS= read -r client_ip; do
            [[ -z "$client_ip" ]] && continue
            unban_client "$client_ip" "manual-flush"
        done <<< "$all_ips"
    fi

    # Chain leeren
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null || true

    log "INFO" "Alle Sperren aufgehoben"
}

# ─── Alle Offense-Zähler zurücksetzen ────────────────────────────────────────
flush_all_offenses() {
    local count
    count=$(db_offense_delete_all)
    log "INFO" "$count Offense-Zähler zurückgesetzt"
    echo "$count Offense-Zähler zurückgesetzt"
}

# ─── Externer Blocklist-Worker starten ───────────────────────────────────────
start_blocklist_worker() {
    if [[ "${EXTERNAL_BLOCKLIST_ENABLED:-false}" != "true" ]]; then
        log "DEBUG" "Externer Blocklist-Worker ist deaktiviert"
        return
    fi

    local worker_script="${SCRIPT_DIR}/external-blocklist-worker.sh"
    if [[ ! -f "$worker_script" ]]; then
        log "WARN" "Blocklist-Worker Script nicht gefunden: $worker_script"
        return
    fi

    log "INFO" "Starte externen Blocklist-Worker im Hintergrund..."
    bash "$worker_script" start &
    BLOCKLIST_WORKER_PID=$!
    log "INFO" "Blocklist-Worker gestartet (PID: $BLOCKLIST_WORKER_PID)"
}

# ─── Externer Blocklist-Worker stoppen ───────────────────────────────────────
stop_blocklist_worker() {
    local worker_pid_file="/var/run/adguard-blocklist-worker.pid"
    if [[ -f "$worker_pid_file" ]]; then
        local wpid
        wpid=$(cat "$worker_pid_file")
        if kill -0 "$wpid" 2>/dev/null; then
            log "INFO" "Stoppe Blocklist-Worker (PID: $wpid)..."
            kill "$wpid" 2>/dev/null || true
            rm -f "$worker_pid_file"
        fi
    fi
}

# ─── Externer Whitelist-Worker starten ───────────────────────────────────────
start_whitelist_worker() {
    if [[ "${EXTERNAL_WHITELIST_ENABLED:-false}" != "true" ]]; then
        log "DEBUG" "Externer Whitelist-Worker ist deaktiviert"
        return
    fi

    local worker_script="${SCRIPT_DIR}/external-whitelist-worker.sh"
    if [[ ! -f "$worker_script" ]]; then
        log "WARN" "Whitelist-Worker Script nicht gefunden: $worker_script"
        return
    fi

    log "INFO" "Starte externen Whitelist-Worker im Hintergrund..."
    bash "$worker_script" start &
    WHITELIST_WORKER_PID=$!
    log "INFO" "Whitelist-Worker gestartet (PID: $WHITELIST_WORKER_PID)"
}

# ─── Externer Whitelist-Worker stoppen ───────────────────────────────────────
stop_whitelist_worker() {
    local worker_pid_file="/var/run/adguard-whitelist-worker.pid"
    if [[ -f "$worker_pid_file" ]]; then
        local wpid
        wpid=$(cat "$worker_pid_file")
        if kill -0 "$wpid" 2>/dev/null; then
            log "INFO" "Stoppe Whitelist-Worker (PID: $wpid)..."
            kill "$wpid" 2>/dev/null || true
            rm -f "$worker_pid_file"
        fi
    fi
}

# ─── GeoIP-Worker starten ────────────────────────────────────────────────────
start_geoip_worker() {
    if [[ "${GEOIP_ENABLED:-false}" != "true" ]]; then
        log "DEBUG" "GeoIP-Worker ist deaktiviert"
        return
    fi

    local worker_script="${SCRIPT_DIR}/geoip-worker.sh"
    if [[ ! -f "$worker_script" ]]; then
        log "WARN" "GeoIP-Worker Script nicht gefunden: $worker_script"
        return
    fi

    log "INFO" "Starte GeoIP-Worker im Hintergrund..."
    bash "$worker_script" start &
    GEOIP_WORKER_PID=$!
    log "INFO" "GeoIP-Worker gestartet (PID: $GEOIP_WORKER_PID)"
}

# ─── GeoIP-Worker stoppen ────────────────────────────────────────────────────
stop_geoip_worker() {
    local worker_pid_file="/var/run/adguard-geoip-worker.pid"
    if [[ -f "$worker_pid_file" ]]; then
        local wpid
        wpid=$(cat "$worker_pid_file")
        if kill -0 "$wpid" 2>/dev/null; then
            log "INFO" "Stoppe GeoIP-Worker (PID: $wpid)..."
            kill "$wpid" 2>/dev/null || true
            rm -f "$worker_pid_file"
        fi
    fi
}

# ─── Offense-Cleanup-Worker starten ──────────────────────────────────────────
start_offense_cleanup_worker() {
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" != "true" ]]; then
        log "DEBUG" "Offense-Cleanup-Worker ist deaktiviert (Progressive Sperren inaktiv)"
        return
    fi

    local worker_script="${SCRIPT_DIR}/offense-cleanup-worker.sh"
    if [[ ! -f "$worker_script" ]]; then
        log "WARN" "Offense-Cleanup-Worker Script nicht gefunden: $worker_script"
        return
    fi

    log "INFO" "Starte Offense-Cleanup-Worker im Hintergrund (nice 19, idle I/O)..."
    nice -n 19 ionice -c 3 bash "$worker_script" start &
    OFFENSE_CLEANUP_WORKER_PID=$!
    log "INFO" "Offense-Cleanup-Worker gestartet (PID: $OFFENSE_CLEANUP_WORKER_PID)"
}

# ─── Offense-Cleanup-Worker stoppen ──────────────────────────────────────────
stop_offense_cleanup_worker() {
    local worker_pid_file="/var/run/adguard-offense-cleanup-worker.pid"
    if [[ -f "$worker_pid_file" ]]; then
        local wpid
        wpid=$(cat "$worker_pid_file")
        if kill -0 "$wpid" 2>/dev/null; then
            log "INFO" "Stoppe Offense-Cleanup-Worker (PID: $wpid)..."
            kill "$wpid" 2>/dev/null || true
            rm -f "$worker_pid_file"
        fi
    fi
}

# ─── Hauptschleife ──────────────────────────────────────────────────────────
main_loop() {
    log "INFO" "═══════════════════════════════════════════════════════════"
    log "INFO" "AdGuard Shield ${VERSION} gestartet"
    log "INFO" "  Limit: ${RATE_LIMIT_MAX_REQUESTS} Anfragen pro ${RATE_LIMIT_WINDOW}s"
    log "INFO" "  Sperrdauer: $(format_duration "${BAN_DURATION}")"
    log "INFO" "  Prüfintervall: ${CHECK_INTERVAL}s"
    log "INFO" "  Dry-Run: ${DRY_RUN}"
    log "INFO" "  Whitelist: ${WHITELIST}"
    log "INFO" "  Externe Blocklist: ${EXTERNAL_BLOCKLIST_ENABLED:-false}"
    log "INFO" "  Externe Whitelist: ${EXTERNAL_WHITELIST_ENABLED:-false}"
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  Progressive Sperren: AKTIV (×${PROGRESSIVE_BAN_MULTIPLIER:-2}, Max-Stufe: ${PROGRESSIVE_BAN_MAX_LEVEL:-0}, Reset: $(format_duration "${PROGRESSIVE_BAN_RESET_AFTER:-86400}"))"
    else
        log "INFO" "  Progressive Sperren: deaktiviert"
    fi
    if [[ "${SUBDOMAIN_FLOOD_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  Subdomain-Flood-Schutz: AKTIV (max ${SUBDOMAIN_FLOOD_MAX_UNIQUE:-50} Subdomains/${SUBDOMAIN_FLOOD_WINDOW:-60}s)"
    else
        log "INFO" "  Subdomain-Flood-Schutz: deaktiviert"
    fi
    if [[ "${DNS_FLOOD_WATCHLIST_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  DNS-Flood-Watchlist: AKTIV (Domains: ${DNS_FLOOD_WATCHLIST:-<keine>})"
    else
        log "INFO" "  DNS-Flood-Watchlist: deaktiviert"
    fi
    if [[ "${ABUSEIPDB_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  AbuseIPDB Reporting: AKTIV (Kategorien: ${ABUSEIPDB_CATEGORIES:-4})"
    else
        log "INFO" "  AbuseIPDB Reporting: deaktiviert"
    fi
    if [[ "${GEOIP_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  GeoIP-Filter: AKTIV (Modus: ${GEOIP_MODE:-blocklist}, Länder: ${GEOIP_COUNTRIES:-<keine>})"
    else
        log "INFO" "  GeoIP-Filter: deaktiviert"
    fi
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  Offense-Cleanup: AKTIV (Reset: $(format_duration "${PROGRESSIVE_BAN_RESET_AFTER:-86400}"), Prüfintervall: 1h)"
    fi
    log "INFO" "═══════════════════════════════════════════════════════════"

    # Service-Start-Benachrichtigung senden
    if [[ "${NOTIFY_ENABLED:-false}" == "true" ]]; then
        send_notification "service_start" "" "" ""
    fi

    # Blocklist-Worker als Hintergrundprozess starten
    start_blocklist_worker

    # Whitelist-Worker als Hintergrundprozess starten
    start_whitelist_worker

    # GeoIP-Worker als Hintergrundprozess starten
    start_geoip_worker

    # Offense-Cleanup-Worker als Hintergrundprozess starten
    start_offense_cleanup_worker

    while true; do
        # Abgelaufene Sperren prüfen
        check_expired_bans

        # API abfragen
        local api_response
        if api_response=$(query_adguard_log); then
            analyze_queries "$api_response"
            analyze_subdomain_flood "$api_response"
        fi

        sleep "$CHECK_INTERVAL"
    done
}

# ─── Signal-Handler ──────────────────────────────────────────────────────────
trap cleanup SIGTERM SIGINT SIGHUP

# ─── Kommandozeilen-Argumente ────────────────────────────────────────────────
case "${1:-start}" in
    start)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] AdGuard Shield ${VERSION} wird gestartet..."
        check_dependencies
        check_already_running
        init_directories
        write_pid
        setup_iptables_chain
        main_loop
        ;;
    stop)
        if [[ -f "$PID_FILE" ]]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null || true
            rm -f "$PID_FILE"
            echo "Monitor gestoppt"
        else
            echo "Monitor läuft nicht"
        fi
        ;;
    blocklist-status)
        init_directories
        _worker_script="${SCRIPT_DIR}/external-blocklist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" status
        else
            echo "Blocklist-Worker nicht gefunden"
        fi
        ;;
    blocklist-sync)
        init_directories
        setup_iptables_chain
        _worker_script="${SCRIPT_DIR}/external-blocklist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" sync
        else
            echo "Blocklist-Worker nicht gefunden"
        fi
        ;;
    blocklist-flush)
        init_directories
        _worker_script="${SCRIPT_DIR}/external-blocklist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" flush
        else
            echo "Blocklist-Worker nicht gefunden"
        fi
        ;;
    whitelist-status)
        init_directories
        _worker_script="${SCRIPT_DIR}/external-whitelist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" status
        else
            echo "Whitelist-Worker nicht gefunden"
        fi
        ;;
    whitelist-sync)
        init_directories
        _worker_script="${SCRIPT_DIR}/external-whitelist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" sync
        else
            echo "Whitelist-Worker nicht gefunden"
        fi
        ;;
    whitelist-flush)
        init_directories
        _worker_script="${SCRIPT_DIR}/external-whitelist-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" flush
        else
            echo "Whitelist-Worker nicht gefunden"
        fi
        ;;
    geoip-status)
        init_directories
        _worker_script="${SCRIPT_DIR}/geoip-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" status
        else
            echo "GeoIP-Worker nicht gefunden"
        fi
        ;;
    geoip-sync)
        init_directories
        setup_iptables_chain
        _worker_script="${SCRIPT_DIR}/geoip-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" sync
        else
            echo "GeoIP-Worker nicht gefunden"
        fi
        ;;
    geoip-flush)
        init_directories
        _worker_script="${SCRIPT_DIR}/geoip-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" flush
        else
            echo "GeoIP-Worker nicht gefunden"
        fi
        ;;
    geoip-lookup)
        if [[ -z "${2:-}" ]]; then
            echo "Nutzung: $0 geoip-lookup <IP-Adresse>" >&2
            exit 1
        fi
        init_directories
        _worker_script="${SCRIPT_DIR}/geoip-worker.sh"
        if [[ -f "$_worker_script" ]]; then
            bash "$_worker_script" lookup "$2"
        else
            echo "GeoIP-Worker nicht gefunden"
        fi
        ;;
    status)
        init_directories
        show_status
        ;;
    flush)
        init_directories
        setup_iptables_chain
        flush_all_bans
        echo "Alle Sperren aufgehoben"
        ;;
    reset-offenses)
        init_directories
        if [[ -n "${2:-}" ]]; then
            reset_offense_level "$2"
            echo "Offense-Zähler für $2 zurückgesetzt"
        else
            flush_all_offenses
        fi
        ;;
    unban)
        if [[ -z "${2:-}" ]]; then
            echo "Nutzung: $0 unban <IP-Adresse>" >&2
            exit 1
        fi
        init_directories
        unban_client "$2" "manual"
        echo "Client $2 entsperrt"
        ;;
    test)
        echo "Teste Verbindung zur AdGuard Home API..."
        check_dependencies
        init_directories
        if response=$(query_adguard_log); then
            entry_count=$(echo "$response" | jq '.data | length' 2>/dev/null || echo "0")
            echo "✅ Verbindung erfolgreich! $entry_count Log-Einträge gefunden."
        else
            echo "❌ Verbindung fehlgeschlagen! Prüfe URL und Zugangsdaten in $CONFIG_FILE"
            exit 1
        fi
        ;;
    history)
        init_directories
        show_history "${2:-50}"
        ;;
    dry-run)
        DRY_RUN=true
        check_dependencies
        check_already_running
        init_directories
        write_pid
        setup_iptables_chain
        main_loop
        ;;
    *)
        cat << USAGE
AdGuard Shield ${VERSION}

Service-Steuerung (empfohlen):
  sudo systemctl start adguard-shield
  sudo systemctl stop adguard-shield
  sudo systemctl restart adguard-shield
  sudo systemctl status adguard-shield

Nutzung: $0 {status|history|flush|unban|reset-offenses|test|dry-run|blocklist-status|blocklist-sync|blocklist-flush|whitelist-status|whitelist-sync|whitelist-flush|geoip-status|geoip-sync|geoip-flush|geoip-lookup}

Verwaltungsbefehle:
  status             Zeigt aktive Sperren, Regeln und Wiederholungstäter
  history [N]        Zeigt die letzten N Ban-Einträge (Standard: 50)
  flush              Hebt alle Sperren auf
  unban IP           Entsperrt eine bestimmte IP-Adresse
  reset-offenses [IP] Setzt Offense-Zähler zurück (alle oder eine bestimmte IP)
  test               Testet die Verbindung zur AdGuard Home API
  dry-run            Startet im Testmodus (keine echten Sperren, Vordergrund!)
  blocklist-status   Zeigt Status der externen Blocklisten
  blocklist-sync     Einmalige Synchronisation der externen Blocklisten
  blocklist-flush    Entfernt alle Sperren der externen Blocklisten
  whitelist-status   Zeigt Status der externen Whitelisten
  whitelist-sync     Einmalige Synchronisation der externen Whitelisten
  whitelist-flush    Entfernt alle aufgelösten Whitelist-IPs
  geoip-status       Zeigt Status der GeoIP-Länderfilter
  geoip-sync         Einmalige GeoIP-Prüfung aller aktiven Clients
  geoip-flush        Alle GeoIP-Sperren aufheben
  geoip-lookup IP    GeoIP-Lookup für eine einzelne IP-Adresse

Interne Befehle (nicht direkt verwenden — nur über systemd):
  start              Startet den Monitor im Vordergrund
  stop               Stoppt den Monitor

Konfiguration: $CONFIG_FILE
Log-Datei:     $LOG_FILE
Datenbank:     $DB_FILE
State:         $STATE_DIR

USAGE
        exit 0
        ;;
esac
