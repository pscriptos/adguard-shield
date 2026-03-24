#!/bin/bash
###############################################################################
# AdGuard Shield
# Überwacht DNS-Anfragen und sperrt Clients bei Überschreitung des Limits
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

VERSION="v0.6.2"

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

# ─── Abhängigkeiten prüfen ────────────────────────────────────────────────────
check_dependencies() {
    local missing=()
    for cmd in curl jq iptables ip6tables date; do
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
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Header schreiben falls Datei neu ist
    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "# AdGuard Shield - Ban History" > "$BAN_HISTORY_FILE"
        echo "# Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | PROTOKOLL | GRUND" >> "$BAN_HISTORY_FILE"
        echo "#──────────────────────────────────────────────────────────────────────────────────────────────────" >> "$BAN_HISTORY_FILE"
    fi

    if [[ -z "$duration" && "$action" == "BAN" ]]; then
        duration="${BAN_DURATION}s"
    fi
    [[ -z "$duration" ]] && duration="-"
    [[ -z "$protocol" ]] && protocol="-"

    printf "%-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %-10s | %s\n" \
        "$timestamp" "$action" "$client_ip" "${domain:--}" "${count:--}" "$duration" "$protocol" "${reason:-rate-limit}" \
        >> "$BAN_HISTORY_FILE"
}

# ─── Progressive Ban (Recidive) ─────────────────────────────────────────────
# Liest die aktuelle Offense-Stufe einer IP aus der Offense-Datei
get_offense_level() {
    local client_ip="$1"
    local offense_file="${STATE_DIR}/${client_ip//[:\/]/_}.offenses"

    if [[ ! -f "$offense_file" ]]; then
        echo "0"
        return
    fi

    local level last_offense now reset_after
    level=$(grep '^OFFENSE_LEVEL=' "$offense_file" | cut -d= -f2 || true)
    last_offense=$(grep '^LAST_OFFENSE_EPOCH=' "$offense_file" | cut -d= -f2 || true)
    now=$(date '+%s')
    reset_after="${PROGRESSIVE_BAN_RESET_AFTER:-86400}"

    # Prüfen ob der Zähler abgelaufen ist (Reset nach Zeitraum ohne Vergehen)
    if [[ -n "$last_offense" && $((now - last_offense)) -gt "$reset_after" ]]; then
        log "INFO" "Progressive Ban: Offense-Zähler für $client_ip zurückgesetzt (>${reset_after}s ohne Vergehen)"
        rm -f "$offense_file"
        echo "0"
        return
    fi

    echo "${level:-0}"
}

# Erhöht die Offense-Stufe einer IP und gibt die neue Stufe zurück
increment_offense_level() {
    local client_ip="$1"
    local offense_file="${STATE_DIR}/${client_ip//[:\/]/_}.offenses"
    local current_level
    current_level=$(get_offense_level "$client_ip")
    local new_level=$((current_level + 1))
    local now
    now=$(date '+%s')
    local now_readable
    now_readable=$(date '+%Y-%m-%d %H:%M:%S')

    # Erstes Vergehen merken (bevor Datei überschrieben wird)
    local first_offense
    first_offense=$(grep '^FIRST_OFFENSE=' "$offense_file" 2>/dev/null | cut -d= -f2 || true)
    [[ -z "$first_offense" ]] && first_offense="$now_readable"

    cat > "$offense_file" << EOF
CLIENT_IP=$client_ip
OFFENSE_LEVEL=$new_level
LAST_OFFENSE_EPOCH=$now
LAST_OFFENSE=$now_readable
FIRST_OFFENSE=$first_offense
EOF

    echo "$new_level"
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

# Setzt den Offense-Zähler einer IP zurück
reset_offense_level() {
    local client_ip="$1"
    local offense_file="${STATE_DIR}/${client_ip//[:\/]/_}.offenses"
    rm -f "$offense_file"
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

# ─── Verzeichnisse erstellen ──────────────────────────────────────────────────
init_directories() {
    mkdir -p "$STATE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$PID_FILE")"
    mkdir -p "$(dirname "$BAN_HISTORY_FILE")"
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
        entry=$(echo "$entry" | xargs)  # trim
        if [[ "$ip" == "$entry" ]]; then
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
    local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"
    if [[ -f "$state_file" ]]; then
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
        if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
            log "WARN" "[DRY-RUN] WÜRDE sperren: $client_ip (${count}x $domain in ${window}s via $protocol) für ${duration_display} [Stufe $offense_level] [${reason}]"
        else
            log "WARN" "[DRY-RUN] WÜRDE sperren: $client_ip (${count}x $domain in ${window}s via $protocol) [${reason}]"
        fi
        log_ban_history "DRY" "$client_ip" "$domain" "$count" "dry-run (${reason})" "${duration_display}" "$protocol"
        return 0
    fi

    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]]; then
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

    # State speichern
    cat > "$state_file" << EOF
CLIENT_IP=$client_ip
DOMAIN=$domain
COUNT=$count
BAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
BAN_UNTIL_EPOCH=$ban_until
BAN_UNTIL=$ban_until_display
BAN_DURATION=${effective_duration}
OFFENSE_LEVEL=$offense_level
IS_PERMANENT=$is_permanent
REASON=$reason
PROTOCOL=$protocol
EOF

    # Ban-History Eintrag
    local history_duration="${duration_display}"
    [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" ]] && history_duration="${duration_display} (Stufe ${offense_level})"
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
    local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"

    # Domain und Protokoll aus State lesen bevor wir löschen
    local domain="-"
    local protocol="-"
    if [[ -f "$state_file" ]]; then
        domain=$(grep '^DOMAIN=' "$state_file" | cut -d= -f2 || true)
        protocol=$(grep '^PROTOCOL=' "$state_file" | cut -d= -f2 || true)
    fi
    [[ -z "$protocol" ]] && protocol="-"

    log "INFO" "ENTSPERRE Client: $client_ip ($reason)"

    if [[ "$client_ip" == *:* ]]; then
        ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    else
        iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    fi

    rm -f "$state_file"

    # Ban-History Eintrag
    log_ban_history "UNBAN" "$client_ip" "$domain" "-" "$reason" "-" "$protocol"

    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "unban" "$client_ip" "$domain" ""
    fi
}

# ─── Abgelaufene Sperren aufheben ───────────────────────────────────────────
check_expired_bans() {
    local now
    now=$(date '+%s')

    for state_file in "${STATE_DIR}"/*.ban; do
        [[ -f "$state_file" ]] || continue

        local ban_until_epoch
        ban_until_epoch=$(grep '^BAN_UNTIL_EPOCH=' "$state_file" | cut -d= -f2 || true)
        local client_ip
        client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2 || true)
        local is_permanent
        is_permanent=$(grep '^IS_PERMANENT=' "$state_file" | cut -d= -f2 || true)

        # Permanente Sperren nicht automatisch aufheben
        if [[ "$is_permanent" == "true" || "$ban_until_epoch" == "0" ]]; then
            log "DEBUG" "Client $client_ip ist permanent gesperrt – überspringe"
            continue
        fi

        if [[ -n "$ban_until_epoch" && "$now" -ge "$ban_until_epoch" ]]; then
            unban_client "$client_ip" "expired"
        fi
    done
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

        # Dauer-Anzeige mit Stufe
        local dur_line
        if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && -n "$offense_level" ]]; then
            dur_line="**${duration_display}** [Stufe ${offense_level}/${PROGRESSIVE_BAN_MAX_LEVEL:-0}]"
        else
            dur_line=$(format_duration "${BAN_DURATION}")
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

            ban_client "$client" "$domain" "$count" "rate-limit" "$RATE_LIMIT_WINDOW" "$proto_display"
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
        local state_file="${STATE_DIR}/${client//[:\/]/_}.ban"
        if [[ -f "$state_file" ]]; then
            log "DEBUG" "Client $client ist bereits gesperrt (Subdomain-Flood übersprungen)"
            continue
        fi

        ban_client "$client" "*.${base_domain}" "$unique_count" "subdomain-flood" "$window" "$proto_display"
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

    # Aktive Sperren
    local ban_count=0
    if [[ -d "$STATE_DIR" ]]; then
        for state_file in "${STATE_DIR}"/*.ban; do
            [[ -f "$state_file" ]] || continue
            ban_count=$((ban_count + 1))
            local s_ip s_domain s_level s_perm s_dur s_until s_reason s_count s_proto
            s_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2 || true)
            s_domain=$(grep '^DOMAIN=' "$state_file" | cut -d= -f2 || true)
            s_level=$(grep '^OFFENSE_LEVEL=' "$state_file" | cut -d= -f2 || true)
            s_perm=$(grep '^IS_PERMANENT=' "$state_file" | cut -d= -f2 || true)
            s_dur=$(grep '^BAN_DURATION=' "$state_file" | cut -d= -f2 || true)
            s_until=$(grep '^BAN_UNTIL=' "$state_file" | cut -d= -f2 || true)
            s_reason=$(grep '^REASON=' "$state_file" | cut -d= -f2 || true)
            s_count=$(grep '^COUNT=' "$state_file" | cut -d= -f2 || true)
            s_proto=$(grep '^PROTOCOL=' "$state_file" | cut -d= -f2 || true)
            s_reason="${s_reason:-rate-limit}"
            s_proto="${s_proto:-?}"

            local reason_tag=""
            [[ "$s_reason" == "subdomain-flood" ]] && reason_tag=" (Subdomain-Flood)"

            local count_info=""
            if [[ -n "$s_count" && "$s_count" != "-" ]]; then
                if [[ "$s_reason" == "subdomain-flood" ]]; then
                    count_info=", ${s_count} Subdomains"
                else
                    count_info=", ${s_count} Anfragen"
                fi
            fi

            local proto_tag=" via ${s_proto}"

            if [[ "$s_perm" == "true" ]]; then
                echo "  🚫 Gesperrt: $s_ip → $s_domain [PERMANENT, Stufe ${s_level:-?}${count_info}${proto_tag}]${reason_tag}"
            elif [[ -n "$s_level" && "$s_level" -gt 0 ]]; then
                echo "  🚫 Gesperrt: $s_ip → $s_domain [Stufe ${s_level}, $(format_duration "${s_dur:-$BAN_DURATION}"), bis $s_until${count_info}${proto_tag}]${reason_tag}"
            else
                echo "  🚫 Gesperrt: $s_ip → $s_domain [bis $s_until${count_info}${proto_tag}]${reason_tag}"
            fi
        done
    fi

    echo ""
    if [[ $ban_count -eq 0 ]]; then
        echo "  ✅ Keine aktiven Sperren"
    else
        echo "  Gesamt: $ban_count aktive Sperren"
    fi

    # Offense-Informationen anzeigen (Wiederholungstäter)
    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" == "true" && -d "$STATE_DIR" ]]; then
        local offense_count=0
        local offense_output=""
        for offense_file in "${STATE_DIR}"/*.offenses; do
            [[ -f "$offense_file" ]] || continue
            local o_ip o_level o_last
            o_ip=$(grep '^CLIENT_IP=' "$offense_file" | cut -d= -f2 || true)
            o_level=$(grep '^OFFENSE_LEVEL=' "$offense_file" | cut -d= -f2 || true)
            o_last=$(grep '^LAST_OFFENSE=' "$offense_file" | cut -d= -f2 || true)
            offense_count=$((offense_count + 1))
            local next_dur
            next_dur=$(calculate_ban_duration "$((o_level + 1))")
            if [[ "$next_dur" -eq 0 ]]; then
                offense_output+="     ⚠ $o_ip: Stufe $o_level (letztes Vergehen: $o_last) → nächste Sperre: PERMANENT\n"
            else
                offense_output+="     ⚠ $o_ip: Stufe $o_level (letztes Vergehen: $o_last) → nächste Sperre: $(format_duration "$next_dur")\n"
            fi
        done

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

    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "  Noch keine History vorhanden."
        echo "  Datei: $BAN_HISTORY_FILE"
        echo ""
        return
    fi

    # Header zeigen
    head -3 "$BAN_HISTORY_FILE" | sed 's/^/  /'
    echo ""

    # Letzte N Einträge (ohne Header-Zeilen)
    grep -v '^#' "$BAN_HISTORY_FILE" | tail -n "$lines" | sed 's/^/  /'

    echo ""
    local total
    total=$(grep -vc '^#' "$BAN_HISTORY_FILE" 2>/dev/null || echo "0")
    local bans
    bans=$(grep -c '| BAN ' "$BAN_HISTORY_FILE" 2>/dev/null || echo "0")
    local unbans
    unbans=$(grep -c '| UNBAN ' "$BAN_HISTORY_FILE" 2>/dev/null || echo "0")
    echo "  Gesamt: $total Einträge ($bans Sperren, $unbans Entsperrungen)"
    echo "  Datei:  $BAN_HISTORY_FILE"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Alle Sperren aufheben ──────────────────────────────────────────────────
flush_all_bans() {
    log "INFO" "Alle Sperren werden aufgehoben..."

    for state_file in "${STATE_DIR}"/*.ban; do
        [[ -f "$state_file" ]] || continue
        local client_ip
        client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2 || true)
        unban_client "$client_ip" "manual-flush"
    done

    # Chain leeren
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null || true

    log "INFO" "Alle Sperren aufgehoben"
}

# ─── Alle Offense-Zähler zurücksetzen ────────────────────────────────────────
flush_all_offenses() {
    local count=0
    for offense_file in "${STATE_DIR}"/*.offenses; do
        [[ -f "$offense_file" ]] || continue
        local o_ip
        o_ip=$(grep '^CLIENT_IP=' "$offense_file" | cut -d= -f2 || true)
        log "INFO" "Offense-Zähler zurückgesetzt: $o_ip"
        rm -f "$offense_file"
        count=$((count + 1))
    done
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
    if [[ "${ABUSEIPDB_ENABLED:-false}" == "true" ]]; then
        log "INFO" "  AbuseIPDB Reporting: AKTIV (Kategorien: ${ABUSEIPDB_CATEGORIES:-4})"
    else
        log "INFO" "  AbuseIPDB Reporting: deaktiviert"
    fi
    log "INFO" "═══════════════════════════════════════════════════════════"

    # Service-Start-Benachrichtigung senden
    if [[ "${NOTIFY_ENABLED:-false}" == "true" ]]; then
        send_notification "service_start" "" "" ""
    fi

    # Blocklist-Worker als Hintergrundprozess starten
    start_blocklist_worker

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

Nutzung: $0 {status|history|flush|unban|reset-offenses|test|dry-run|blocklist-status|blocklist-sync|blocklist-flush}

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

Interne Befehle (nicht direkt verwenden — nur über systemd):
  start              Startet den Monitor im Vordergrund
  stop               Stoppt den Monitor

Konfiguration: $CONFIG_FILE
Log-Datei:     $LOG_FILE
Ban-History:   $BAN_HISTORY_FILE
State:         $STATE_DIR

USAGE
        exit 0
        ;;
esac
