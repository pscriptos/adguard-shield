#!/bin/bash
###############################################################################
# AdGuard Shield - Externer Blocklist-Worker
# Lädt externe IP-Blocklisten herunter und sperrt/entsperrt IPs automatisch.
# Wird als Hintergrundprozess vom Hauptscript gestartet.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Datum:   2026-03-03
# Lizenz:  MIT
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-shield.conf"

# ─── Konfiguration laden ───────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "FEHLER: Konfigurationsdatei nicht gefunden: $CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=adguard-shield.conf
source "$CONFIG_FILE"

# ─── Worker PID-File ──────────────────────────────────────────────────────────
WORKER_PID_FILE="/var/run/adguard-blocklist-worker.pid"

# ─── Logging (eigene Funktion, nutzt gleiche Log-Datei) ───────────────────────
declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)

log() {
    local level="$1"
    shift
    local message="$*"
    local configured_level="${LOG_LEVEL:-INFO}"

    if [[ ${LOG_LEVELS[$level]:-1} -ge ${LOG_LEVELS[$configured_level]:-1} ]]; then
        local timestamp
        timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
        local log_entry="[$timestamp] [$level] [BLOCKLIST-WORKER] $message"
        echo "$log_entry" | tee -a "$LOG_FILE"
    fi
}

# ─── Ban-History ─────────────────────────────────────────────────────────────
log_ban_history() {
    local action="$1"
    local client_ip="$2"
    local reason="${3:-external-blocklist}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "# AdGuard Shield - Ban History" > "$BAN_HISTORY_FILE"
        echo "# Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | GRUND" >> "$BAN_HISTORY_FILE"
        echo "#───────────────────────────────────────────────────────────────────────────────" >> "$BAN_HISTORY_FILE"
    fi

    local duration="permanent"
    [[ "$EXTERNAL_BLOCKLIST_BAN_DURATION" -gt 0 ]] && duration="${EXTERNAL_BLOCKLIST_BAN_DURATION}s"

    printf "%-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %s\n" \
        "$timestamp" "$action" "$client_ip" "-" "-" "$duration" "$reason" \
        >> "$BAN_HISTORY_FILE"
}

# ─── Verzeichnisse erstellen ──────────────────────────────────────────────────
init_directories() {
    mkdir -p "$EXTERNAL_BLOCKLIST_CACHE_DIR"
    mkdir -p "$STATE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
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

# ─── IP sperren ──────────────────────────────────────────────────────────────
ban_ip() {
    local ip="$1"
    local state_file="${STATE_DIR}/ext_${ip//[:\/]/_}.ban"

    # Bereits gesperrt?
    if [[ -f "$state_file" ]]; then
        log "DEBUG" "IP $ip bereits über externe Blocklist gesperrt"
        return 0
    fi

    # Nicht auch vom Hauptscript gesperrt? (State-Datei ohne ext_ Prefix)
    local main_state_file="${STATE_DIR}/${ip//[:\/]/_}.ban"
    if [[ -f "$main_state_file" ]]; then
        log "DEBUG" "IP $ip bereits vom Rate-Limiter gesperrt - überspringe"
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "WARN" "[DRY-RUN] WÜRDE sperren (externe Blocklist): $ip"
        log_ban_history "DRY" "$ip" "external-blocklist-dry-run"
        return 0
    fi

    log "WARN" "SPERRE IP (externe Blocklist): $ip"

    # iptables-Regel setzen
    if [[ "$ip" == *:* ]]; then
        ip6tables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null || true
    else
        iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null || true
    fi

    # State speichern
    local ban_until_epoch="0"
    local ban_until_display="permanent"
    if [[ "$EXTERNAL_BLOCKLIST_BAN_DURATION" -gt 0 ]]; then
        ban_until_epoch=$(date -d "+${EXTERNAL_BLOCKLIST_BAN_DURATION} seconds" '+%s' 2>/dev/null \
            || date -v "+${EXTERNAL_BLOCKLIST_BAN_DURATION}S" '+%s')
        ban_until_display=$(date -d "@$ban_until_epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null \
            || date -r "$ban_until_epoch" '+%Y-%m-%d %H:%M:%S')
    fi

    cat > "$state_file" << EOF
CLIENT_IP=$ip
DOMAIN=-
COUNT=-
BAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
BAN_UNTIL_EPOCH=$ban_until_epoch
BAN_UNTIL=$ban_until_display
SOURCE=external-blocklist
EOF

    log_ban_history "BAN" "$ip" "external-blocklist"

    # Benachrichtigung senden
    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "ban" "$ip"
    fi
}

# ─── IP entsperren ───────────────────────────────────────────────────────────
unban_ip() {
    local ip="$1"
    local reason="${2:-external-blocklist-removed}"
    local state_file="${STATE_DIR}/ext_${ip//[:\/]/_}.ban"

    [[ -f "$state_file" ]] || return 0

    log "INFO" "ENTSPERRE IP (externe Blocklist entfernt): $ip"

    if [[ "$ip" == *:* ]]; then
        ip6tables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null || true
    else
        iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null || true
    fi

    rm -f "$state_file"
    log_ban_history "UNBAN" "$ip" "$reason"

    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "unban" "$ip"
    fi
}

# ─── Benachrichtigung ────────────────────────────────────────────────────────
send_notification() {
    local action="$1"
    local ip="$2"

    [[ -z "${NOTIFY_WEBHOOK_URL:-}" ]] && return

    local message
    if [[ "$action" == "ban" ]]; then
        message="🚫 Externe Blocklist: IP **$ip** gesperrt."
    else
        message="✅ Externe Blocklist: IP **$ip** entsperrt (aus Liste entfernt)."
    fi

    case "${NOTIFY_TYPE:-generic}" in
        discord)
            curl -s -H "Content-Type: application/json" \
                -d "{\"content\": \"$message\"}" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
        slack)
            curl -s -H "Content-Type: application/json" \
                -d "{\"text\": \"$message\"}" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
        gotify)
            curl -s -X POST "$NOTIFY_WEBHOOK_URL" \
                -F "title=AdGuard Shield - Externe Blocklist" \
                -F "message=$message" \
                -F "priority=5" &>/dev/null &
            ;;
        ntfy)
            local ntfy_url="${NTFY_SERVER_URL:-https://ntfy.sh}"
            local -a curl_args=(
                -s -X POST "${ntfy_url}/${NTFY_TOPIC}"
                -H "Title: AdGuard Shield - Externe Blocklist"
                -H "Priority: ${NTFY_PRIORITY:-3}"
                -H "Tags: rotating_light,blocklist"
                -d "$(echo "$message" | sed 's/\*\*//g')"
            )
            [[ -n "${NTFY_TOKEN:-}" ]] && curl_args+=(-H "Authorization: Bearer ${NTFY_TOKEN}")
            curl "${curl_args[@]}" &>/dev/null &
            ;;
        generic)
            curl -s -H "Content-Type: application/json" \
                -d "{\"message\": \"$message\", \"action\": \"$action\", \"client\": \"$ip\", \"source\": \"external-blocklist\"}" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
    esac
}

# ─── Externe Blocklist herunterladen ─────────────────────────────────────────
download_blocklist() {
    local url="$1"
    local index="$2"
    local cache_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/blocklist_${index}.txt"
    local etag_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/blocklist_${index}.etag"
    local tmp_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/blocklist_${index}.tmp"

    log "DEBUG" "Prüfe externe Blocklist: $url"

    # HTTP-Header für bedingte Anfrage vorbereiten
    local -a curl_args=(
        -s
        -L
        --connect-timeout 10
        --max-time 30
        -o "$tmp_file"
        -w "%{http_code}"
    )

    # ETag für If-None-Match Header nutzen falls vorhanden
    if [[ -f "$etag_file" ]]; then
        local stored_etag
        stored_etag=$(cat "$etag_file")
        curl_args+=(-H "If-None-Match: ${stored_etag}")
    fi

    # Download-Header separat abfragen für ETag
    local http_code
    http_code=$(curl "${curl_args[@]}" -D "${tmp_file}.headers" "$url" 2>/dev/null) || {
        log "WARN" "Fehler beim Download der Blocklist: $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        return 1
    }

    # 304 Not Modified - keine Änderung
    if [[ "$http_code" == "304" ]]; then
        log "DEBUG" "Blocklist nicht geändert (HTTP 304): $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        return 1
    fi

    # Fehlerhafte HTTP-Codes
    if [[ "$http_code" != "200" ]]; then
        log "WARN" "Blocklist Download fehlgeschlagen (HTTP $http_code): $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        return 1
    fi

    # Neuen ETag speichern falls vorhanden
    if [[ -f "${tmp_file}.headers" ]]; then
        local new_etag
        new_etag=$(grep -i '^etag:' "${tmp_file}.headers" | head -1 | sed 's/^[^:]*: *//;s/\r$//')
        if [[ -n "$new_etag" ]]; then
            echo "$new_etag" > "$etag_file"
        fi
    fi
    rm -f "${tmp_file}.headers"

    # Prüfen ob sich der Inhalt tatsächlich geändert hat (Fallback für Server ohne ETag)
    if [[ -f "$cache_file" ]]; then
        if diff -q "$tmp_file" "$cache_file" &>/dev/null; then
            log "DEBUG" "Blocklist Inhalt unverändert: $url"
            rm -f "$tmp_file"
            return 1
        fi
    fi

    # Neue Datei übernehmen
    mv "$tmp_file" "$cache_file"
    log "INFO" "Blocklist aktualisiert: $url"
    return 0
}

# ─── IPs aus Blocklist-Datei parsen ──────────────────────────────────────────
parse_blocklist_ips() {
    local cache_file="$1"

    [[ -f "$cache_file" ]] || return

    # Zeilen lesen, Leerzeilen und Kommentare ignorieren, IPs extrahieren
    while IFS= read -r line; do
        # Leerzeilen überspringen
        [[ -z "$line" ]] && continue
        # Kommentare überspringen (# am Anfang)
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        # Whitespace trimmen
        line=$(echo "$line" | xargs)
        # Leere Zeilen nach Trim überspringen
        [[ -z "$line" ]] && continue
        # CIDR-Notation oder reine IP ausgeben
        echo "$line"
    done < "$cache_file"
}

# ─── Aktuelle externe Sperren ermitteln ──────────────────────────────────────
get_currently_banned_external_ips() {
    for state_file in "${STATE_DIR}"/ext_*.ban; do
        [[ -f "$state_file" ]] || continue
        grep '^CLIENT_IP=' "$state_file" | cut -d= -f2
    done
}

# ─── Abgelaufene externe Sperren prüfen ─────────────────────────────────────
check_expired_external_bans() {
    [[ "$EXTERNAL_BLOCKLIST_BAN_DURATION" -gt 0 ]] || return

    local now
    now=$(date '+%s')

    for state_file in "${STATE_DIR}"/ext_*.ban; do
        [[ -f "$state_file" ]] || continue

        local ban_until_epoch
        ban_until_epoch=$(grep '^BAN_UNTIL_EPOCH=' "$state_file" | cut -d= -f2)
        local client_ip
        client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2)

        if [[ -n "$ban_until_epoch" && "$ban_until_epoch" -gt 0 && "$now" -ge "$ban_until_epoch" ]]; then
            unban_ip "$client_ip" "external-blocklist-expired"
        fi
    done
}

# ─── Blocklisten synchronisieren ─────────────────────────────────────────────
sync_blocklists() {
    local any_updated=false

    # Alle URLs holen
    IFS=',' read -ra urls <<< "$EXTERNAL_BLOCKLIST_URLS"
    local index=0

    for url in "${urls[@]}"; do
        url=$(echo "$url" | xargs)  # trim
        [[ -z "$url" ]] && continue

        if download_blocklist "$url" "$index"; then
            any_updated=true
        fi
        index=$((index + 1))
    done

    # Alle gewünschten IPs zusammenführen (aus allen Cache-Dateien)
    local all_desired_ips_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/.all_ips.tmp"
    > "$all_desired_ips_file"

    for cache_file in "${EXTERNAL_BLOCKLIST_CACHE_DIR}"/blocklist_*.txt; do
        [[ -f "$cache_file" ]] || continue
        parse_blocklist_ips "$cache_file" >> "$all_desired_ips_file"
    done

    # Duplikate entfernen und sortieren
    local unique_ips_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/.all_ips_unique.tmp"
    sort -u "$all_desired_ips_file" > "$unique_ips_file"

    local desired_count
    desired_count=$(wc -l < "$unique_ips_file" | xargs)
    log "DEBUG" "Externe Blockliste enthält $desired_count eindeutige IPs"

    # ─── Neue IPs sperren ────────────────────────────────────────────────────
    local new_bans=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        # Whitelist prüfen
        if is_whitelisted "$ip"; then
            log "DEBUG" "IP $ip ist auf der Whitelist - überspringe (externe Blocklist)"
            continue
        fi

        ban_ip "$ip"
        new_bans=$((new_bans + 1))
    done < "$unique_ips_file"

    # ─── Entfernte IPs entsperren ────────────────────────────────────────────
    if [[ "$EXTERNAL_BLOCKLIST_AUTO_UNBAN" == "true" ]]; then
        local removed_count=0
        while IFS= read -r banned_ip; do
            [[ -z "$banned_ip" ]] && continue
            # Prüfen ob die IP noch in der gewünschten Liste ist
            if ! grep -qxF "$banned_ip" "$unique_ips_file" 2>/dev/null; then
                unban_ip "$banned_ip" "external-blocklist-removed"
                removed_count=$((removed_count + 1))
            fi
        done < <(get_currently_banned_external_ips)

        if [[ $removed_count -gt 0 ]]; then
            log "INFO" "$removed_count IPs aus externer Blocklist entfernt und entsperrt"
        fi
    fi

    # Abgelaufene Sperren prüfen (nur bei zeitlich begrenzten Sperren)
    check_expired_external_bans

    # Aufräumen
    rm -f "$all_desired_ips_file" "$unique_ips_file"

    if [[ "$new_bans" -gt 0 ]]; then
        log "INFO" "$new_bans neue IPs aus externer Blocklist gesperrt"
    fi
}

# ─── PID-Management ──────────────────────────────────────────────────────────
write_pid() {
    echo $$ > "$WORKER_PID_FILE"
}

cleanup() {
    log "INFO" "Externer Blocklist-Worker wird beendet..."
    rm -f "$WORKER_PID_FILE"
    exit 0
}

check_already_running() {
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            log "DEBUG" "Blocklist-Worker läuft bereits (PID: $old_pid)"
            return 1
        else
            rm -f "$WORKER_PID_FILE"
        fi
    fi
    return 0
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
show_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Externer Blocklist-Worker - Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [[ "$EXTERNAL_BLOCKLIST_ENABLED" != "true" ]]; then
        echo "  ⚠️  Externer Blocklist-Worker ist deaktiviert"
        echo "  Aktivieren: EXTERNAL_BLOCKLIST_ENABLED=true in $CONFIG_FILE"
        echo ""
        return
    fi

    # Worker-Prozess Status
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local pid
        pid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "  ✅ Worker läuft (PID: $pid)"
        else
            echo "  ❌ Worker nicht aktiv (veraltete PID-Datei)"
        fi
    else
        echo "  ❌ Worker nicht aktiv"
    fi

    echo ""

    # Konfigurierte URLs
    echo "  Konfigurierte Blocklisten:"
    IFS=',' read -ra urls <<< "$EXTERNAL_BLOCKLIST_URLS"
    local index=0
    for url in "${urls[@]}"; do
        url=$(echo "$url" | xargs)
        [[ -z "$url" ]] && continue
        local cache_file="${EXTERNAL_BLOCKLIST_CACHE_DIR}/blocklist_${index}.txt"
        local ip_count=0
        if [[ -f "$cache_file" ]]; then
            ip_count=$(grep -cv '^\s*#\|^\s*$' "$cache_file" 2>/dev/null || echo "0")
            local last_modified
            last_modified=$(date -r "$cache_file" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unbekannt")
            echo "    [$index] $url"
            echo "        IPs: $ip_count | Zuletzt aktualisiert: $last_modified"
        else
            echo "    [$index] $url (noch nicht heruntergeladen)"
        fi
        index=$((index + 1))
    done

    echo ""

    # Aktive externe Sperren
    local ext_ban_count=0
    for state_file in "${STATE_DIR}"/ext_*.ban; do
        [[ -f "$state_file" ]] || continue
        ext_ban_count=$((ext_ban_count + 1))
    done
    echo "  Aktive Sperren (externe Blocklist): $ext_ban_count"

    echo ""
    echo "  Prüfintervall: ${EXTERNAL_BLOCKLIST_INTERVAL}s"
    echo "  Auto-Unban: ${EXTERNAL_BLOCKLIST_AUTO_UNBAN}"
    if [[ "$EXTERNAL_BLOCKLIST_BAN_DURATION" -gt 0 ]]; then
        echo "  Sperrdauer: ${EXTERNAL_BLOCKLIST_BAN_DURATION}s"
    else
        echo "  Sperrdauer: permanent (bis aus Liste entfernt)"
    fi
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Einmalig synchronisieren ────────────────────────────────────────────────
run_once() {
    init_directories
    setup_iptables_chain

    if [[ -z "${EXTERNAL_BLOCKLIST_URLS:-}" ]]; then
        log "ERROR" "Keine externen Blocklist-URLs konfiguriert (EXTERNAL_BLOCKLIST_URLS)"
        exit 1
    fi

    log "INFO" "Einmalige Blocklist-Synchronisation..."
    sync_blocklists
    log "INFO" "Synchronisation abgeschlossen"
}

# ─── Hauptschleife ──────────────────────────────────────────────────────────
main_loop() {
    init_directories
    setup_iptables_chain

    if [[ -z "${EXTERNAL_BLOCKLIST_URLS:-}" ]]; then
        log "ERROR" "Keine externen Blocklist-URLs konfiguriert (EXTERNAL_BLOCKLIST_URLS)"
        exit 1
    fi

    log "INFO" "═══════════════════════════════════════════════════════════"
    log "INFO" "Externer Blocklist-Worker gestartet"
    log "INFO" "  URLs: ${EXTERNAL_BLOCKLIST_URLS}"
    log "INFO" "  Prüfintervall: ${EXTERNAL_BLOCKLIST_INTERVAL}s"
    log "INFO" "  Auto-Unban: ${EXTERNAL_BLOCKLIST_AUTO_UNBAN}"
    log "INFO" "═══════════════════════════════════════════════════════════"

    while true; do
        sync_blocklists
        sleep "$EXTERNAL_BLOCKLIST_INTERVAL"
    done
}

# ─── Signal-Handler ──────────────────────────────────────────────────────────
trap cleanup SIGTERM SIGINT SIGHUP

# ─── Kommandozeilen-Argumente ────────────────────────────────────────────────
case "${1:-start}" in
    start)
        if ! check_already_running; then
            exit 0
        fi
        write_pid
        main_loop
        ;;
    stop)
        if [[ -f "$WORKER_PID_FILE" ]]; then
            kill "$(cat "$WORKER_PID_FILE")" 2>/dev/null || true
            rm -f "$WORKER_PID_FILE"
            echo "Blocklist-Worker gestoppt"
        else
            echo "Blocklist-Worker läuft nicht"
        fi
        ;;
    sync)
        run_once
        ;;
    status)
        init_directories
        show_status
        ;;
    flush)
        init_directories
        echo "Entferne alle externen Blocklist-Sperren..."
        for state_file in "${STATE_DIR}"/ext_*.ban; do
            [[ -f "$state_file" ]] || continue
            _ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2)
            unban_ip "$_ip" "manual-flush"
        done
        echo "Alle externen Blocklist-Sperren aufgehoben"
        ;;
    *)
        cat << USAGE
AdGuard Shield - Externer Blocklist-Worker

Nutzung: $0 {start|stop|sync|status|flush}

Befehle:
  start      Startet den Worker (Dauerbetrieb)
  stop       Stoppt den Worker
  sync       Einmalige Synchronisation
  status     Zeigt Status und konfigurierte Listen
  flush      Entfernt alle externen Blocklist-Sperren

Konfiguration: $CONFIG_FILE

USAGE
        exit 0
        ;;
esac
