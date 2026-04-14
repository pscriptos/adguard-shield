#!/bin/bash
###############################################################################
# AdGuard Shield - GeoIP Worker
# Prüft Client-IPs auf Herkunftsland und sperrt/erlaubt basierend auf Konfig.
# Wird als Hintergrundprozess vom Hauptscript gestartet.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
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
WORKER_PID_FILE="/var/run/adguard-geoip-worker.pid"

# ─── GeoIP Cache ──────────────────────────────────────────────────────────────
GEOIP_CACHE_DIR="${STATE_DIR}/geoip-cache"

# ─── MaxMind Auto-Download Verzeichnis ────────────────────────────────────────
GEOIP_DB_DIR="${SCRIPT_DIR}/geoip"
GEOIP_AUTO_DB="${GEOIP_DB_DIR}/GeoLite2-Country.mmdb"
GEOIP_DB_UPDATE_INTERVAL=86400  # 24 Stunden (fest)

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
        local log_entry="[$timestamp] [$level] [GEOIP-WORKER] $message"
        echo "$log_entry" | tee -a "$LOG_FILE" >&2
    fi
}

# ─── Ban-History ─────────────────────────────────────────────────────────────
log_ban_history() {
    local action="$1"
    local client_ip="$2"
    local country="${3:-}"
    local reason="${4:-geoip}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "# AdGuard Shield - Ban History" > "$BAN_HISTORY_FILE"
        echo "# Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | PROTOKOLL | GRUND" >> "$BAN_HISTORY_FILE"
        echo "#──────────────────────────────────────────────────────────────────────────────────────────────────" >> "$BAN_HISTORY_FILE"
    fi

    local duration="permanent"

    printf "%-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %-10s | %s\n" \
        "$timestamp" "$action" "$client_ip" "Land: ${country:-?}" "-" "$duration" "-" "$reason" \
        >> "$BAN_HISTORY_FILE"
}

# ─── Verzeichnisse erstellen ──────────────────────────────────────────────────
init_directories() {
    mkdir -p "$GEOIP_CACHE_DIR"
    mkdir -p "$GEOIP_DB_DIR"
    mkdir -p "$STATE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
}

# ─── Private IP-Adressen erkennen ────────────────────────────────────────────
is_private_ip() {
    local ip="$1"

    # IPv6 Loopback und Link-Local
    if [[ "$ip" == "::1" || "$ip" == fe80:* || "$ip" == fc00:* || "$ip" == fd00:* ]]; then
        return 0
    fi

    # IPv4 private Bereiche
    if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^127\. || "$ip" == "0.0.0.0" ]]; then
        return 0
    fi

    # IPv4 CGNAT
    if [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
        return 0
    fi

    return 1
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

    # Externe Whitelist prüfen
    local ext_wl_file="${EXTERNAL_WHITELIST_CACHE_DIR:-/var/lib/adguard-shield/external-whitelist}/resolved_ips.txt"
    if [[ -f "$ext_wl_file" ]] && grep -qxF "$ip" "$ext_wl_file" 2>/dev/null; then
        return 0
    fi

    return 1
}

# ─── MaxMind GeoLite2 Auto-Download & Update ─────────────────────────────────
# Lädt die GeoLite2-Country.mmdb herunter, wenn GEOIP_LICENSE_KEY gesetzt ist
# und kein eigener GEOIP_MMDB_PATH angegeben wurde.
# Aktualisiert automatisch alle 24 Stunden.
update_maxmind_db() {
    local license_key="${GEOIP_LICENSE_KEY:-}"

    # Kein License-Key → nichts zu tun
    if [[ -z "$license_key" ]]; then
        return 0
    fi

    # User hat eigenen Pfad gesetzt → kein Auto-Download
    if [[ -n "${GEOIP_MMDB_PATH:-}" ]]; then
        return 0
    fi

    # Prüfen ob Update nötig (alle 24h)
    if [[ -f "$GEOIP_AUTO_DB" ]]; then
        local db_age
        db_age=$(( $(date '+%s') - $(stat -c '%Y' "$GEOIP_AUTO_DB" 2>/dev/null || stat -f '%m' "$GEOIP_AUTO_DB" 2>/dev/null || echo "0") ))
        if [[ "$db_age" -lt "$GEOIP_DB_UPDATE_INTERVAL" ]]; then
            log "DEBUG" "MaxMind DB ist aktuell (Alter: $((db_age / 3600))h, nächstes Update in $(( (GEOIP_DB_UPDATE_INTERVAL - db_age) / 3600 ))h)"
            return 0
        fi
        log "INFO" "MaxMind DB ist älter als 24h – starte Update..."
    else
        log "INFO" "MaxMind DB nicht vorhanden – starte Erstdownload..."
    fi

    # Download-URL zusammenbauen (MaxMind Permalink)
    local download_url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${license_key}&suffix=tar.gz"
    local tmp_file="${GEOIP_DB_DIR}/GeoLite2-Country.tar.gz"
    local tmp_extract="${GEOIP_DB_DIR}/extract_tmp"

    # Herunterladen
    local http_code
    http_code=$(curl -s -o "$tmp_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 60 \
        "$download_url" 2>/dev/null) || true

    if [[ "$http_code" != "200" ]]; then
        rm -f "$tmp_file"
        case "$http_code" in
            401) log "ERROR" "MaxMind Download fehlgeschlagen: Ungültiger License-Key (HTTP 401)" ;;
            403) log "ERROR" "MaxMind Download fehlgeschlagen: Zugriff verweigert (HTTP 403) – License-Key prüfen" ;;
            *)   log "ERROR" "MaxMind Download fehlgeschlagen (HTTP ${http_code:-timeout})" ;;
        esac
        return 1
    fi

    # Entpacken
    rm -rf "$tmp_extract"
    mkdir -p "$tmp_extract"

    if ! tar -xzf "$tmp_file" -C "$tmp_extract" 2>/dev/null; then
        log "ERROR" "MaxMind DB: tar-Archiv konnte nicht entpackt werden"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # .mmdb Datei finden und verschieben
    local mmdb_file
    mmdb_file=$(find "$tmp_extract" -name 'GeoLite2-Country.mmdb' -type f 2>/dev/null | head -1)

    if [[ -z "$mmdb_file" || ! -f "$mmdb_file" ]]; then
        log "ERROR" "MaxMind DB: GeoLite2-Country.mmdb nicht im Archiv gefunden"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    mv "$mmdb_file" "$GEOIP_AUTO_DB"
    rm -f "$tmp_file"
    rm -rf "$tmp_extract"

    log "INFO" "MaxMind GeoLite2-Country DB erfolgreich aktualisiert: $GEOIP_AUTO_DB"
    return 0
}

# ─── Effektiven MMDB-Pfad ermitteln ──────────────────────────────────────────
# Priorität: GEOIP_MMDB_PATH (User) > Auto-Download > leer (Fallback auf geoiplookup)
resolve_mmdb_path() {
    # User hat eigenen Pfad gesetzt
    if [[ -n "${GEOIP_MMDB_PATH:-}" && -f "${GEOIP_MMDB_PATH:-}" ]]; then
        echo "$GEOIP_MMDB_PATH"
        return 0
    fi

    # Auto-Download DB vorhanden
    if [[ -f "$GEOIP_AUTO_DB" ]]; then
        echo "$GEOIP_AUTO_DB"
        return 0
    fi

    # Kein MMDB verfügbar
    echo ""
    return 1
}

# ─── GeoIP Lookup ────────────────────────────────────────────────────────────
# Gibt den ISO 3166-1 Alpha-2 Ländercode zurück (z.B. "DE", "US", "CN")
# Nutzt Cache um wiederholte Lookups zu vermeiden
geoip_lookup() {
    local ip="$1"
    local cache_file="${GEOIP_CACHE_DIR}/${ip//[:\/]/_}.country"

    # Cache prüfen (max 24 Stunden alt)
    if [[ -f "$cache_file" ]]; then
        local cache_age
        cache_age=$(( $(date '+%s') - $(stat -c '%Y' "$cache_file" 2>/dev/null || stat -f '%m' "$cache_file" 2>/dev/null || echo "0") ))
        if [[ "$cache_age" -lt 86400 ]]; then
            cat "$cache_file"
            return 0
        fi
    fi

    local country_code=""

    # Effektiven MMDB-Pfad ermitteln (User-Pfad oder Auto-Download)
    local effective_mmdb
    effective_mmdb=$(resolve_mmdb_path 2>/dev/null) || true

    # Methode 1: MaxMind mmdbinspect (bevorzugt, genauer)
    if [[ -n "$effective_mmdb" && -f "$effective_mmdb" ]] && command -v mmdbinspect &>/dev/null; then
        country_code=$(mmdbinspect -db "$effective_mmdb" -ip "$ip" 2>/dev/null \
            | jq -r '.[0].Records[0].Record.country.iso_code // empty' 2>/dev/null || true)
    fi

    # Methode 2: geoiplookup (GeoIP Legacy)
    if [[ -z "$country_code" ]] && command -v geoiplookup &>/dev/null; then
        if [[ "$ip" == *:* ]]; then
            # IPv6
            if command -v geoiplookup6 &>/dev/null; then
                country_code=$(geoiplookup6 "$ip" 2>/dev/null \
                    | grep -oP '(?<=: )[A-Z]{2}(?=,)' | head -1 || true)
            fi
        else
            # IPv4
            country_code=$(geoiplookup "$ip" 2>/dev/null \
                | grep -oP '(?<=: )[A-Z]{2}(?=,)' | head -1 || true)
        fi
    fi

    # Methode 3: mmdblookup (libmaxminddb)
    if [[ -z "$country_code" && -n "$effective_mmdb" && -f "$effective_mmdb" ]] && command -v mmdblookup &>/dev/null; then
        country_code=$(mmdblookup --file "$effective_mmdb" --ip "$ip" country iso_code 2>/dev/null \
            | grep -oP '"[A-Z]{2}"' | tr -d '"' | head -1 || true)
    fi

    if [[ -n "$country_code" ]]; then
        echo "$country_code" > "$cache_file"
        echo "$country_code"
        return 0
    fi

    # Unbekannt – nicht cachen (könnte temporärer Fehler sein)
    echo ""
    return 1
}

# ─── GeoIP Prüfung: Soll eine IP gesperrt werden? ────────────────────────────
# Return 0 = sperren, Return 1 = erlauben
should_block_by_geoip() {
    local country_code="$1"
    local mode="${GEOIP_MODE:-blocklist}"
    local countries="${GEOIP_COUNTRIES:-}"

    [[ -z "$country_code" || -z "$countries" ]] && return 1

    # Länder-Liste in Array umwandeln
    IFS=',' read -ra country_list <<< "$countries"

    local found=false
    for c in "${country_list[@]}"; do
        c=$(echo "$c" | xargs | tr '[:lower:]' '[:upper:]')  # trim + uppercase
        if [[ "$country_code" == "$c" ]]; then
            found=true
            break
        fi
    done

    if [[ "$mode" == "blocklist" ]]; then
        # Blocklist-Modus: Sperren wenn Land in der Liste
        [[ "$found" == "true" ]] && return 0 || return 1
    elif [[ "$mode" == "allowlist" ]]; then
        # Allowlist-Modus: Sperren wenn Land NICHT in der Liste
        [[ "$found" == "true" ]] && return 1 || return 0
    fi

    return 1
}

# ─── IP via iptables sperren ─────────────────────────────────────────────────
ban_ip_geoip() {
    local client_ip="$1"
    local country_code="$2"
    local mode="${GEOIP_MODE:-blocklist}"

    # Prüfen ob bereits gesperrt
    local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"
    if [[ -f "$state_file" ]]; then
        log "DEBUG" "GeoIP: $client_ip ist bereits gesperrt"
        return 0
    fi

    # GeoIP-Sperren sind immer permanent
    local ban_until=0
    local ban_until_display="PERMANENT"

    local reason_text
    if [[ "$mode" == "blocklist" ]]; then
        reason_text="geoip-blocklist (Land: $country_code)"
    else
        reason_text="geoip-allowlist (Land: $country_code)"
    fi

    log "WARN" "GeoIP SPERRE: $client_ip (Land: $country_code, Modus: $mode) PERMANENT"

    # iptables Regel setzen
    if [[ "$client_ip" == *:* ]]; then
        ip6tables -I "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    else
        iptables -I "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
    fi

    # State-Datei erstellen
    cat > "$state_file" << EOF
CLIENT_IP=$client_ip
DOMAIN=GeoIP:${country_code}
COUNT=-
BAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
BAN_UNTIL_EPOCH=0
BAN_UNTIL=PERMANENT
BAN_DURATION=0
OFFENSE_LEVEL=0
IS_PERMANENT=true
REASON=geoip
PROTOCOL=-
GEOIP_COUNTRY=$country_code
GEOIP_MODE=$mode
EOF

    # Ban-History
    log_ban_history "BAN" "$client_ip" "$country_code" "$reason_text"

    # Benachrichtigung senden
    if [[ "${GEOIP_NOTIFY:-true}" == "true" && "${NOTIFY_ENABLED:-false}" == "true" ]]; then
        send_geoip_notification "ban" "$client_ip" "$country_code" "PERMANENT" "$mode"
    fi
}

# ─── GeoIP Benachrichtigung ──────────────────────────────────────────────────
send_geoip_notification() {
    local action="$1"
    local client_ip="$2"
    local country_code="$3"
    local duration="${4:-PERMANENT}"
    local mode="${5:-blocklist}"
    local my_hostname
    my_hostname=$(hostname)

    local title="🌍 🛡️ AdGuard Shield"
    local mode_label
    [[ "$mode" == "blocklist" ]] && mode_label="Blocklist" || mode_label="Allowlist"

    local message="🌍 AdGuard Shield GeoIP-Sperre auf ${my_hostname}
---
IP: ${client_ip}
Land: ${country_code}
Modus: ${mode_label}
Dauer: ${duration}

Whois: https://www.whois.com/whois/${client_ip}
AbuseIPDB: https://www.abuseipdb.com/check/${client_ip}"

    case "${NOTIFY_TYPE:-}" in
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
            local ntfy_url="${NTFY_SERVER_URL:-https://ntfy.sh}"
            local -a curl_args=(
                -s -X POST
                "${ntfy_url}/${NTFY_TOPIC}"
                -H "Title: 🛡️ AdGuard Shield GeoIP"
                -H "Priority: ${NTFY_PRIORITY:-4}"
                -H "Tags: globe_with_meridians,ban"
                -d "$message"
            )
            [[ -n "${NTFY_TOKEN:-}" ]] && curl_args+=(-H "Authorization: Bearer ${NTFY_TOKEN}")
            curl "${curl_args[@]}" &>/dev/null &
            ;;
        generic)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" --arg cl "$client_ip" --arg cc "$country_code" \
                '{message: $msg, action: "geoip-ban", client: $cl, country: $cc}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null &
            ;;
    esac
}

# ─── iptables Chain Setup ────────────────────────────────────────────────────
setup_iptables_chain() {
    if ! iptables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        iptables -N "$IPTABLES_CHAIN"
        for port in $BLOCKED_PORTS; do
            iptables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            iptables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
    fi
    if ! ip6tables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        ip6tables -N "$IPTABLES_CHAIN"
        for port in $BLOCKED_PORTS; do
            ip6tables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            ip6tables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
    fi
}

# ─── GeoIP-Tools Verfügbarkeit prüfen ────────────────────────────────────────
check_geoip_tools() {
    # Effektiven MMDB-Pfad ermitteln
    local effective_mmdb
    effective_mmdb=$(resolve_mmdb_path 2>/dev/null) || true

    # mmdbinspect + MMDB
    if [[ -n "$effective_mmdb" && -f "$effective_mmdb" ]]; then
        if command -v mmdbinspect &>/dev/null; then
            echo "mmdbinspect"
            return 0
        elif command -v mmdblookup &>/dev/null; then
            echo "mmdblookup"
            return 0
        fi
    fi

    # geoiplookup (Legacy GeoIP)
    if command -v geoiplookup &>/dev/null; then
        echo "geoiplookup"
        return 0
    fi

    echo "none"
    return 1
}

# ─── Client-IPs aus AdGuard API extrahieren ──────────────────────────────────
get_active_clients() {
    local response
    response=$(curl -s -u "${ADGUARD_USER}:${ADGUARD_PASS}" \
        --connect-timeout 5 \
        --max-time 10 \
        -k "${ADGUARD_URL}/control/querylog?limit=${API_QUERY_LIMIT:-500}&response_status=all" 2>/dev/null)

    if [[ -z "$response" || "$response" == "null" ]]; then
        log "ERROR" "Keine Antwort von AdGuard Home API"
        return 1
    fi

    # Eindeutige Client-IPs extrahieren
    echo "$response" | jq -r '.data // [] | [.[].client // .[].client_info.ip] | unique | .[]' 2>/dev/null | sort -u
}

# ─── Auto-Unban: GeoIP-Sperren aufheben bei Konfigurationsänderung ────────────
# Prüft alle bestehenden GeoIP-Sperren und hebt sie auf, wenn:
# - Das Land nicht mehr in GEOIP_COUNTRIES steht
# - Der Modus gewechselt wurde (blocklist ↔ allowlist)
# - GeoIP deaktiviert wurde
auto_unban_geoip() {
    local unban_count=0

    for f in "${STATE_DIR}"/*.ban; do
        [[ -f "$f" ]] || continue

        local reason
        reason=$(grep '^REASON=' "$f" | cut -d= -f2 || true)
        [[ "$reason" != "geoip" ]] && continue

        local client_ip country_code old_mode
        client_ip=$(grep '^CLIENT_IP=' "$f" | cut -d= -f2 || true)
        country_code=$(grep '^GEOIP_COUNTRY=' "$f" | cut -d= -f2 || true)
        old_mode=$(grep '^GEOIP_MODE=' "$f" | cut -d= -f2 || true)

        local should_unban=false

        # GeoIP deaktiviert → alle GeoIP-Sperren aufheben
        if [[ "${GEOIP_ENABLED:-false}" != "true" ]]; then
            should_unban=true
        # Modus gewechselt → alle GeoIP-Sperren aufheben und neu prüfen
        elif [[ -n "$old_mode" && "$old_mode" != "${GEOIP_MODE:-blocklist}" ]]; then
            should_unban=true
        # Prüfen ob das Land nach aktueller Konfiguration noch gesperrt sein soll
        elif [[ -n "$country_code" ]] && ! should_block_by_geoip "$country_code"; then
            should_unban=true
        fi

        if [[ "$should_unban" == "true" ]]; then
            log "INFO" "GeoIP Auto-Unban: $client_ip (Land: ${country_code:-?}, war: ${old_mode:-?})"

            # iptables Regel entfernen
            if [[ "$client_ip" == *:* ]]; then
                ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
            else
                iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
            fi

            rm -f "$f"
            log_ban_history "UNBAN" "$client_ip" "$country_code" "geoip-auto-unban"
            unban_count=$((unban_count + 1))
        fi
    done

    if [[ $unban_count -gt 0 ]]; then
        log "INFO" "GeoIP Auto-Unban: $unban_count Sperren aufgehoben (Länderliste/Modus geändert)"
    fi
}

# ─── Einmaliger GeoIP-Sync ──────────────────────────────────────────────────
sync_geoip() {
    # Auto-Unban zuerst: bestehende Sperren prüfen, die nicht mehr zur Config passen
    auto_unban_geoip

    if [[ "${GEOIP_ENABLED:-false}" != "true" ]]; then
        log "INFO" "GeoIP ist deaktiviert"
        return 0
    fi

    # MaxMind DB automatisch herunterladen/aktualisieren (falls License-Key gesetzt)
    update_maxmind_db || true

    local countries="${GEOIP_COUNTRIES:-}"
    if [[ -z "$countries" ]]; then
        log "WARN" "GeoIP: Keine Länder konfiguriert (GEOIP_COUNTRIES ist leer)"
        return 0
    fi

    local tool
    tool=$(check_geoip_tools) || {
        log "ERROR" "GeoIP: Kein GeoIP-Tool verfügbar. Installiere geoip-bin oder mmdbinspect."
        return 1
    }
    log "INFO" "GeoIP-Sync gestartet (Tool: $tool, Modus: ${GEOIP_MODE:-blocklist}, Länder: $countries)"

    # Client-IPs aus der API holen
    local clients
    clients=$(get_active_clients) || {
        log "ERROR" "GeoIP: Konnte aktive Clients nicht ermitteln"
        return 1
    }

    local checked=0
    local blocked=0
    local skipped=0

    while IFS= read -r client_ip; do
        [[ -z "$client_ip" || "$client_ip" == "null" ]] && continue

        # Private IPs überspringen
        if [[ "${GEOIP_SKIP_PRIVATE:-true}" == "true" ]] && is_private_ip "$client_ip"; then
            log "DEBUG" "GeoIP: Private IP übersprungen: $client_ip"
            skipped=$((skipped + 1))
            continue
        fi

        # Whitelist prüfen
        if is_whitelisted "$client_ip"; then
            log "DEBUG" "GeoIP: Whitelisted IP übersprungen: $client_ip"
            skipped=$((skipped + 1))
            continue
        fi

        # Bereits gesperrt?
        local state_file="${STATE_DIR}/${client_ip//[:\/]/_}.ban"
        if [[ -f "$state_file" ]]; then
            skipped=$((skipped + 1))
            continue
        fi

        checked=$((checked + 1))

        # GeoIP Lookup
        local country_code
        country_code=$(geoip_lookup "$client_ip") || true

        if [[ -z "$country_code" ]]; then
            log "DEBUG" "GeoIP: Kein Ergebnis für $client_ip"
            continue
        fi

        log "DEBUG" "GeoIP: $client_ip → $country_code"

        # Prüfen ob gesperrt werden soll
        if should_block_by_geoip "$country_code"; then
            ban_ip_geoip "$client_ip" "$country_code"
            blocked=$((blocked + 1))
        fi
    done <<< "$clients"

    log "INFO" "GeoIP-Sync abgeschlossen: $checked geprüft, $blocked gesperrt, $skipped übersprungen"
}

# ─── Worker-Hauptschleife ────────────────────────────────────────────────────
start_worker() {
    if [[ "${GEOIP_ENABLED:-false}" != "true" ]]; then
        log "DEBUG" "GeoIP-Worker ist deaktiviert"
        return 0
    fi

    # PID schreiben
    echo $$ > "$WORKER_PID_FILE"
    trap 'rm -f "$WORKER_PID_FILE"; exit 0' SIGTERM SIGINT SIGHUP

    local interval="${GEOIP_CHECK_INTERVAL:-0}"
    [[ "$interval" -le 0 ]] && interval="${CHECK_INTERVAL:-10}"

    log "INFO" "GeoIP-Worker gestartet (PID: $$, Intervall: ${interval}s)"

    # Beim Start: MaxMind DB herunterladen/aktualisieren (falls License-Key gesetzt)
    update_maxmind_db || true

    while true; do
        sync_geoip
        sleep "$interval"
    done
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
show_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield - GeoIP Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [[ "${GEOIP_ENABLED:-false}" != "true" ]]; then
        echo "  ℹ️  GeoIP ist deaktiviert"
        echo ""
        return
    fi

    echo "  Modus:    ${GEOIP_MODE:-blocklist}"
    echo "  Länder:   ${GEOIP_COUNTRIES:-<keine>}"
    echo "  Sperrdauer: PERMANENT (Auto-Unban bei Änderung der Länderliste)"
    echo "  Private IPs überspringen: ${GEOIP_SKIP_PRIVATE:-true}"
    echo ""

    # MaxMind DB Info
    local eff_mmdb
    eff_mmdb=$(resolve_mmdb_path)
    if [[ -n "${GEOIP_MMDB_PATH:-}" ]]; then
        echo "  MMDB-Pfad: ${GEOIP_MMDB_PATH} (manuell konfiguriert)"
    elif [[ -n "${GEOIP_LICENSE_KEY:-}" ]]; then
        echo "  MMDB-Pfad: ${GEOIP_AUTO_DB} (Auto-Download)"
        if [[ -f "${GEOIP_AUTO_DB}" ]]; then
            local db_age db_age_h
            db_age=$(( $(date +%s) - $(stat -c %Y "${GEOIP_AUTO_DB}" 2>/dev/null || echo 0) ))
            db_age_h=$(( db_age / 3600 ))
            echo "  DB-Alter:  ${db_age_h}h (Update alle 24h)"
        else
            echo "  DB-Status: ⚠️  Noch nicht heruntergeladen"
        fi
    elif [[ -n "$eff_mmdb" ]]; then
        echo "  MMDB-Pfad: ${eff_mmdb}"
    else
        echo "  MMDB-Pfad: <nicht konfiguriert> (Fallback auf geoiplookup)"
    fi
    echo "  License-Key: $(if [[ -n "${GEOIP_LICENSE_KEY:-}" ]]; then echo "✅ konfiguriert"; else echo "❌ nicht gesetzt (kein Auto-Download)"; fi)"
    echo ""

    # GeoIP Tools prüfen
    echo "  GeoIP Tools:"
    local tool
    tool=$(check_geoip_tools 2>/dev/null) || tool="none"
    case "$tool" in
        mmdbinspect) echo "  ✅ mmdbinspect mit MaxMind DB" ;;
        mmdblookup)  echo "  ✅ mmdblookup mit MaxMind DB" ;;
        geoiplookup) echo "  ✅ geoiplookup (Legacy GeoIP)" ;;
        none)        echo "  ❌ Kein GeoIP-Tool gefunden!" ;;
    esac
    echo ""

    # Worker-Status
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local wpid
        wpid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$wpid" 2>/dev/null; then
            echo "  Worker: Läuft (PID: $wpid)"
        else
            echo "  Worker: Abgestürzt (PID: $wpid existiert nicht mehr)"
        fi
    else
        echo "  Worker: Nicht gestartet"
    fi
    echo ""

    # GeoIP-Sperren anzeigen
    local geoip_bans=0
    if [[ -d "$STATE_DIR" ]]; then
        for f in "${STATE_DIR}"/*.ban; do
            [[ -f "$f" ]] || continue
            local reason
            reason=$(grep '^REASON=' "$f" | cut -d= -f2 || true)
            if [[ "$reason" == "geoip" ]]; then
                geoip_bans=$((geoip_bans + 1))
                local s_ip s_country s_until
                s_ip=$(grep '^CLIENT_IP=' "$f" | cut -d= -f2 || true)
                s_country=$(grep '^GEOIP_COUNTRY=' "$f" | cut -d= -f2 || true)
                s_until=$(grep '^BAN_UNTIL=' "$f" | cut -d= -f2 || true)
                echo "  🌍 $s_ip → Land: ${s_country:-?} (bis: ${s_until:-?})"
            fi
        done
    fi

    if [[ $geoip_bans -eq 0 ]]; then
        echo "  Keine aktiven GeoIP-Sperren"
    else
        echo ""
        echo "  Gesamt: $geoip_bans aktive GeoIP-Sperren"
    fi

    # Cache-Statistik
    if [[ -d "$GEOIP_CACHE_DIR" ]]; then
        local cache_count
        cache_count=$(find "$GEOIP_CACHE_DIR" -name '*.country' -type f 2>/dev/null | wc -l)
        echo ""
        echo "  Cache: $cache_count IP-Lookups zwischengespeichert"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Einzelne IP nachschlagen ────────────────────────────────────────────────
lookup_ip() {
    local ip="$1"

    local eff_mmdb
    eff_mmdb=$(resolve_mmdb_path)

    local tool
    tool=$(check_geoip_tools 2>/dev/null) || tool="none"

    if [[ "$tool" == "none" ]]; then
        echo "❌ Kein GeoIP-Tool verfügbar."
        echo "   Installiere geoip-bin: sudo apt install geoip-bin geoip-database"
        echo "   Oder mmdbinspect mit MaxMind GeoLite2 DB"
        return 1
    fi

    local country_code
    country_code=$(geoip_lookup "$ip") || true

    if [[ -z "$country_code" ]]; then
        echo "IP: $ip → Land: unbekannt (kein GeoIP-Ergebnis)"
        return 1
    fi

    echo "IP: $ip → Land: $country_code (Tool: $tool)"
    [[ -n "$eff_mmdb" ]] && echo "   MMDB: $eff_mmdb"

    # Prüfen ob diese IP gesperrt werden würde
    if [[ "${GEOIP_ENABLED:-false}" == "true" && -n "${GEOIP_COUNTRIES:-}" ]]; then
        if should_block_by_geoip "$country_code"; then
            echo "→ Würde GESPERRT werden (Modus: ${GEOIP_MODE:-blocklist}, Länder: ${GEOIP_COUNTRIES})"
        else
            echo "→ Würde ERLAUBT werden (Modus: ${GEOIP_MODE:-blocklist}, Länder: ${GEOIP_COUNTRIES})"
        fi
    fi
}

# ─── Cache leeren ────────────────────────────────────────────────────────────
flush_cache() {
    if [[ -d "$GEOIP_CACHE_DIR" ]]; then
        local count
        count=$(find "$GEOIP_CACHE_DIR" -name '*.country' -type f 2>/dev/null | wc -l)
        rm -f "${GEOIP_CACHE_DIR}"/*.country 2>/dev/null || true
        echo "✅ GeoIP-Cache geleert ($count Einträge entfernt)"
        log "INFO" "GeoIP-Cache geleert ($count Einträge)"
    else
        echo "ℹ️  GeoIP-Cache-Verzeichnis existiert nicht"
    fi
}

# ─── GeoIP-Sperren aufheben ─────────────────────────────────────────────────
flush_geoip_bans() {
    local count=0
    if [[ -d "$STATE_DIR" ]]; then
        for f in "${STATE_DIR}"/*.ban; do
            [[ -f "$f" ]] || continue
            local reason
            reason=$(grep '^REASON=' "$f" | cut -d= -f2 || true)
            if [[ "$reason" == "geoip" ]]; then
                local client_ip
                client_ip=$(grep '^CLIENT_IP=' "$f" | cut -d= -f2 || true)

                # iptables Regel entfernen
                if [[ "$client_ip" == *:* ]]; then
                    ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
                else
                    iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
                fi

                rm -f "$f"
                log_ban_history "UNBAN" "$client_ip" "" "geoip-flush"
                count=$((count + 1))
            fi
        done
    fi

    echo "✅ $count GeoIP-Sperren aufgehoben"
    log "INFO" "$count GeoIP-Sperren aufgehoben (flush)"
}

# ─── Hauptprogramm ──────────────────────────────────────────────────────────
case "${1:-help}" in
    start)
        init_directories
        setup_iptables_chain
        start_worker
        ;;
    sync)
        init_directories
        setup_iptables_chain
        sync_geoip
        ;;
    status)
        init_directories
        show_status
        ;;
    lookup)
        if [[ -z "${2:-}" ]]; then
            echo "Nutzung: $0 lookup <IP-Adresse>" >&2
            exit 1
        fi
        init_directories
        lookup_ip "$2"
        ;;
    flush)
        init_directories
        flush_geoip_bans
        ;;
    flush-cache)
        init_directories
        flush_cache
        ;;
    stop)
        if [[ -f "$WORKER_PID_FILE" ]]; then
            local wpid
            wpid=$(cat "$WORKER_PID_FILE")
            if kill -0 "$wpid" 2>/dev/null; then
                kill "$wpid" 2>/dev/null || true
                rm -f "$WORKER_PID_FILE"
                echo "GeoIP-Worker gestoppt"
            else
                rm -f "$WORKER_PID_FILE"
                echo "GeoIP-Worker war nicht aktiv"
            fi
        else
            echo "GeoIP-Worker läuft nicht"
        fi
        ;;
    *)
        cat << USAGE
AdGuard Shield - GeoIP Worker

Nutzung: $0 {start|stop|sync|status|lookup|flush|flush-cache}

Befehle:
  start        Startet den GeoIP-Worker (Hintergrundprozess)
  stop         Stoppt den GeoIP-Worker
  sync         Einmalige GeoIP-Prüfung aller aktiven Clients
  status       Zeigt GeoIP-Status und aktive Sperren
  lookup <IP>  GeoIP-Lookup für eine einzelne IP
  flush        Alle GeoIP-Sperren aufheben
  flush-cache  GeoIP-Lookup-Cache leeren

Konfiguration in: $CONFIG_FILE
  GEOIP_ENABLED=true/false
  GEOIP_MODE=blocklist/allowlist
  GEOIP_COUNTRIES="CN,RU,..."

USAGE
        exit 0
        ;;
esac
