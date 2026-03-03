#!/bin/bash
###############################################################################
# AdGuard Shield
# Überwacht DNS-Anfragen und sperrt Clients bei Überschreitung des Limits
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Datum:   2026-03-03
# Lizenz:  MIT
###############################################################################

VERSION="0.3.0"

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
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Header schreiben falls Datei neu ist
    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "# AdGuard Shield - Ban History" > "$BAN_HISTORY_FILE"
        echo "# Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | GRUND" >> "$BAN_HISTORY_FILE"
        echo "#───────────────────────────────────────────────────────────────────────────────" >> "$BAN_HISTORY_FILE"
    fi

    local duration="-"
    [[ "$action" == "BAN" ]] && duration="${BAN_DURATION}s"

    printf "%-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %s\n" \
        "$timestamp" "$action" "$client_ip" "${domain:--}" "${count:--}" "$duration" "${reason:-rate-limit}" \
        >> "$BAN_HISTORY_FILE"
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
    local ban_until
    ban_until=$(date -d "+${BAN_DURATION} seconds" '+%s' 2>/dev/null || date -v "+${BAN_DURATION}S" '+%s')

    # Prüfen ob bereits gesperrt
    local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"
    if [[ -f "$state_file" ]]; then
        log "DEBUG" "Client $client_ip ist bereits gesperrt"
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "WARN" "[DRY-RUN] WÜRDE sperren: $client_ip (${count}x $domain in ${RATE_LIMIT_WINDOW}s)"
        log_ban_history "DRY" "$client_ip" "$domain" "$count" "dry-run"
        return 0
    fi

    log "WARN" "SPERRE Client: $client_ip (${count}x $domain in ${RATE_LIMIT_WINDOW}s) für ${BAN_DURATION}s"

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
BAN_UNTIL=$(date -d "@$ban_until" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$ban_until" '+%Y-%m-%d %H:%M:%S')
EOF

    # Ban-History Eintrag
    log_ban_history "BAN" "$client_ip" "$domain" "$count" "rate-limit"

    # Benachrichtigung senden
    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "ban" "$client_ip" "$domain" "$count"
    fi
}

# ─── Client entsperren ──────────────────────────────────────────────────────
unban_client() {
    local client_ip="$1"
    local reason="${2:-expired}"
    local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"

    # Domain aus State lesen bevor wir löschen
    local domain="-"
    if [[ -f "$state_file" ]]; then
        domain=$(grep '^DOMAIN=' "$state_file" | cut -d= -f2)
    fi

    log "INFO" "ENTSPERRE Client: $client_ip ($reason)"

    if [[ "$client_ip" == *:* ]]; then
        ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    else
        iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    fi

    rm -f "$state_file"

    # Ban-History Eintrag
    log_ban_history "UNBAN" "$client_ip" "$domain" "-" "$reason"

    if [[ "$NOTIFY_ENABLED" == "true" ]]; then
        send_notification "unban" "$client_ip" "" ""
    fi
}

# ─── Abgelaufene Sperren aufheben ───────────────────────────────────────────
check_expired_bans() {
    local now
    now=$(date '+%s')

    for state_file in "${STATE_DIR}"/*.ban; do
        [[ -f "$state_file" ]] || continue

        local ban_until_epoch
        ban_until_epoch=$(grep '^BAN_UNTIL_EPOCH=' "$state_file" | cut -d= -f2)
        local client_ip
        client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2)

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

    [[ -z "$NOTIFY_WEBHOOK_URL" ]] && return

    local message
    if [[ "$action" == "ban" ]]; then
        message="🚫 AdGuard Shield: Client **$client_ip** gesperrt (${count}x $domain in ${RATE_LIMIT_WINDOW}s). Sperre für ${BAN_DURATION}s."
    else
        message="✅ AdGuard Shield: Client **$client_ip** wurde entsperrt."
    fi

    case "$NOTIFY_TYPE" in
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
                -F "title=AdGuard Shield" \
                -F "message=$message" \
                -F "priority=5" &>/dev/null &
            ;;
        ntfy)
            send_ntfy_notification "$action" "$message"
            ;;
        generic)
            curl -s -H "Content-Type: application/json" \
                -d "{\"message\": \"$message\", \"action\": \"$action\", \"client\": \"$client_ip\", \"domain\": \"$domain\"}" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
    esac
}

# ─── Ntfy Benachrichtigung ───────────────────────────────────────────────────
send_ntfy_notification() {
    local action="$1"
    local message="$2"

    if [[ -z "${NTFY_TOPIC:-}" ]]; then
        log "WARN" "Ntfy: Kein Topic konfiguriert (NTFY_TOPIC ist leer)"
        return 1
    fi

    local ntfy_url="${NTFY_SERVER_URL:-https://ntfy.sh}"
    local priority="${NTFY_PRIORITY:-4}"
    local title="AdGuard Shield"
    local tags

    if [[ "$action" == "ban" ]]; then
        tags="rotating_light,ban"
    else
        tags="white_check_mark,unban"
    fi

    # Markdown-Formatierung entfernen für Ntfy
    local clean_message
    clean_message=$(echo "$message" | sed 's/\*\*//g')

    local -a curl_args=(
        -s
        -X POST
        "${ntfy_url}/${NTFY_TOPIC}"
        -H "Title: ${title}"
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

    # Extrahiere Client-IP + Domain Paare aus dem Zeitfenster
    # und zähle die Häufigkeit pro (client, domain) Kombination
    # Unterstützt .question.name (alte API) und .question.host (neue API)
    # Unterstützt Timestamps mit UTC ("Z") und Zeitzonen-Offset ("+01:00")
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
                domain: ((.question.name // .question.host // "unknown") | rtrimstr("."))
            }
        ] |
        group_by(.client + "|" + .domain) |
        map({
            client: .[0].client,
            domain: .[0].domain,
            count: length
        }) |
        .[] |
        select(.count > 0) |
        "\(.client)|\(.domain)|\(.count)"
    ') || {
        log "ERROR" "jq Analyse fehlgeschlagen - API-Antwort-Format prüfen (ist AdGuard Home erreichbar?)"
        return
    }

    if [[ -z "$violations" ]]; then
        log "INFO" "Keine Anfragen im Zeitfenster gefunden"
        return
    fi

    # Prüfe jede Kombination gegen das Limit
    while IFS='|' read -r client domain count; do
        [[ -z "$client" || -z "$domain" || -z "$count" ]] && continue

        log "INFO" "Client: $client, Domain: $domain, Anfragen: $count/$RATE_LIMIT_MAX_REQUESTS"

        if [[ "$count" -gt "$RATE_LIMIT_MAX_REQUESTS" ]]; then
            if is_whitelisted "$client"; then
                log "INFO" "Client $client ist auf der Whitelist - keine Sperre (${count}x $domain)"
                continue
            fi

            ban_client "$client" "$domain" "$count"
        fi
    done <<< "$violations"
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
show_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield - Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Aktive Sperren
    local ban_count=0
    if [[ -d "$STATE_DIR" ]]; then
        for state_file in "${STATE_DIR}"/*.ban; do
            [[ -f "$state_file" ]] || continue
            ban_count=$((ban_count + 1))
            echo "  🚫 Gesperrt:"
            while IFS='=' read -r key value; do
                printf "     %-20s %s\n" "$key:" "$value"
            done < "$state_file"
            echo ""
        done
    fi

    if [[ $ban_count -eq 0 ]]; then
        echo "  ✅ Keine aktiven Sperren"
    else
        echo "  Gesamt: $ban_count aktive Sperren"
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
        client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2)
        unban_client "$client_ip" "manual-flush"
    done

    # Chain leeren
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null || true

    log "INFO" "Alle Sperren aufgehoben"
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
    log "INFO" "AdGuard Shield v${VERSION} gestartet"
    log "INFO" "  Limit: ${RATE_LIMIT_MAX_REQUESTS} Anfragen pro ${RATE_LIMIT_WINDOW}s"
    log "INFO" "  Sperrdauer: ${BAN_DURATION}s"
    log "INFO" "  Prüfintervall: ${CHECK_INTERVAL}s"
    log "INFO" "  Dry-Run: ${DRY_RUN}"
    log "INFO" "  Whitelist: ${WHITELIST}"
    log "INFO" "  Externe Blocklist: ${EXTERNAL_BLOCKLIST_ENABLED:-false}"
    log "INFO" "═══════════════════════════════════════════════════════════"

    # Blocklist-Worker als Hintergrundprozess starten
    start_blocklist_worker

    while true; do
        # Abgelaufene Sperren prüfen
        check_expired_bans

        # API abfragen
        local api_response
        if api_response=$(query_adguard_log); then
            analyze_queries "$api_response"
        fi

        sleep "$CHECK_INTERVAL"
    done
}

# ─── Signal-Handler ──────────────────────────────────────────────────────────
trap cleanup SIGTERM SIGINT SIGHUP

# ─── Kommandozeilen-Argumente ────────────────────────────────────────────────
case "${1:-start}" in
    start)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] AdGuard Shield v${VERSION} wird gestartet..."
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
AdGuard Shield v${VERSION}

Nutzung: $0 {start|stop|status|history|flush|unban|test|dry-run|blocklist-status|blocklist-sync|blocklist-flush}

Befehle:
  start              Startet den Monitor (inkl. Blocklist-Worker)
  stop               Stoppt den Monitor
  status             Zeigt aktive Sperren und Regeln
  history [N]        Zeigt die letzten N Ban-Einträge (Standard: 50)
  flush              Hebt alle Sperren auf
  unban IP           Entsperrt eine bestimmte IP-Adresse
  test               Testet die Verbindung zur AdGuard Home API
  dry-run            Startet im Testmodus (keine echten Sperren)
  blocklist-status   Zeigt Status der externen Blocklisten
  blocklist-sync     Einmalige Synchronisation der externen Blocklisten
  blocklist-flush    Entfernt alle Sperren der externen Blocklisten

Konfiguration: $CONFIG_FILE
Log-Datei:     $LOG_FILE
Ban-History:   $BAN_HISTORY_FILE
State:         $STATE_DIR

USAGE
        exit 0
        ;;
esac
