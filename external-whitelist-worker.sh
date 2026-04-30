#!/bin/bash
###############################################################################
# AdGuard Shield - Externer Whitelist-Worker
# Lädt externe Whitelist-Dateien herunter, löst Domains zu IPs auf und
# stellt diese dem Hauptscript als dynamische Whitelist zur Verfügung.
# Ideal für DynDNS-Domains mit wechselnden IP-Adressen.
# Wird als Hintergrundprozess vom Hauptscript gestartet.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Datum:   2026-04-04
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

# shellcheck source=db.sh
source "${SCRIPT_DIR}/db.sh"

# ─── Standardwerte ────────────────────────────────────────────────────────────
EXTERNAL_WHITELIST_CACHE_DIR="${EXTERNAL_WHITELIST_CACHE_DIR:-/var/lib/adguard-shield/external-whitelist}"

# ─── Worker PID-File ──────────────────────────────────────────────────────────
WORKER_PID_FILE="/var/run/adguard-whitelist-worker.pid"

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
        local log_entry="[$timestamp] [$level] [WHITELIST-WORKER] $message"
        echo "$log_entry" | tee -a "$LOG_FILE" >&2
    fi
}

# ─── Verzeichnisse erstellen ──────────────────────────────────────────────────
init_directories() {
    mkdir -p "$EXTERNAL_WHITELIST_CACHE_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    db_init
}

# ─── Eintrag-Validierung ─────────────────────────────────────────────────────

# Prüft IPv4-Adresse mit optionalem CIDR
_is_valid_ipv4() {
    local ip="$1" addr="$1" prefix=""
    if [[ "$ip" == */* ]]; then
        addr="${ip%/*}"
        prefix="${ip#*/}"
        { [[ "$prefix" =~ ^[0-9]+$ ]] && [[ "$prefix" -le 32 ]]; } || return 1
    fi
    local IFS='.'
    read -ra _octets <<< "$addr"
    [[ ${#_octets[@]} -eq 4 ]] || return 1
    local o
    for o in "${_octets[@]}"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        [[ "$o" -le 255 ]]     || return 1
    done
    return 0
}

# Prüft IPv6-Adresse mit optionalem CIDR
_is_valid_ipv6() {
    local ip="$1" addr="$1"
    if [[ "$ip" == */* ]]; then
        addr="${ip%/*}"
        local prefix="${ip#*/}"
        { [[ "$prefix" =~ ^[0-9]+$ ]] && [[ "$prefix" -le 128 ]]; } || return 1
    fi
    [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9] ]] && return 1
    [[ "$addr" == *:* ]]              || return 1
    [[ "$addr" =~ ^[0-9a-fA-F:\.]+$ ]] || return 1
    return 0
}

# Prüft ob ein Hostname syntaktisch plausibel ist
_is_valid_hostname() {
    local host="$1"
    host="${host%.}"                      # trailing dot entfernen
    [[ -z "$host" ]]      && return 1
    [[ ${#host} -gt 253 ]] && return 1
    [[ "$host" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1
    [[ "$host" =~ ^[.\-]  ]]            && return 1
    [[ "$host" == *.*     ]]            || return 1
    return 0
}

# ─── Externe Whitelist herunterladen ─────────────────────────────────────────
download_whitelist() {
    local url="$1"
    local index="$2"
    local cache_file="${EXTERNAL_WHITELIST_CACHE_DIR}/whitelist_${index}.txt"
    local etag_file="${EXTERNAL_WHITELIST_CACHE_DIR}/whitelist_${index}.etag"
    local tmp_file="${EXTERNAL_WHITELIST_CACHE_DIR}/whitelist_${index}.tmp"

    log "DEBUG" "Prüfe externe Whitelist: $url"

    local -a curl_args=(
        -s
        -L
        --connect-timeout 10
        --max-time 30
        -o "$tmp_file"
        -w "%{http_code}"
    )

    if [[ -f "$etag_file" ]]; then
        local stored_etag
        stored_etag=$(cat "$etag_file")
        curl_args+=(-H "If-None-Match: ${stored_etag}")
    fi

    local http_code
    http_code=$(curl "${curl_args[@]}" -D "${tmp_file}.headers" "$url" 2>/dev/null) || {
        log "WARN" "Fehler beim Download der Whitelist: $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        return 1
    }

    if [[ "$http_code" == "304" ]]; then
        log "DEBUG" "Whitelist nicht geändert (HTTP 304): $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        # Auch bei 304 müssen wir DNS neu auflösen (dynamische IPs!)
        return 0
    fi

    if [[ "$http_code" != "200" ]]; then
        log "WARN" "Whitelist Download fehlgeschlagen (HTTP $http_code): $url"
        rm -f "$tmp_file" "${tmp_file}.headers"
        return 1
    fi

    if [[ -f "${tmp_file}.headers" ]]; then
        local new_etag
        new_etag=$(grep -i '^etag:' "${tmp_file}.headers" | head -1 | sed 's/^[^:]*: *//;s/\r$//')
        if [[ -n "$new_etag" ]]; then
            echo "$new_etag" > "$etag_file"
        fi
    fi
    rm -f "${tmp_file}.headers"

    if [[ -f "$cache_file" ]]; then
        if diff -q "$tmp_file" "$cache_file" &>/dev/null; then
            log "DEBUG" "Whitelist Inhalt unverändert: $url"
            rm -f "$tmp_file"
            return 0
        fi
    fi

    mv "$tmp_file" "$cache_file"
    log "INFO" "Whitelist aktualisiert: $url"
    return 0
}

# ─── Einträge aus Whitelist-Datei parsen und IPs auflösen ───────────────────
# Gibt pro Zeile eine IP-Adresse aus (aufgelöste Domains + direkte IPs)
parse_whitelist_entries() {
    local cache_file="$1"

    [[ -f "$cache_file" ]] || return

    while IFS= read -r line; do
        line="${line%$'\r'}"
        line="${line#$'\xef\xbb\xbf'}"

        [[ -z "$line" ]]                    && continue
        [[ "$line" =~ ^[[:space:]]*# ]]     && continue

        line=$(echo "$line" | xargs)
        line=$(echo "$line" | sed 's/[[:space:]]*[#;].*$//' | xargs)
        [[ -z "$line" ]] && continue

        # URLs ablehnen
        if [[ "$line" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
            log "WARN" "Whitelist-Eintrag übersprungen (URL nicht erlaubt): $line"
            continue
        fi

        # Hosts-Datei-Format erkennen
        if [[ "$line" =~ ^[^[:space:]]+[[:space:]]+[^[:space:]] ]]; then
            local _first="${line%% *}"
            local _rest="${line#* }"
            local _second="${_rest%% *}"
            if [[ "$_first" == "0.0.0.0"  || "$_first" =~ ^127\.   ||
                  "$_first" == "::1"       || "$_first" == "::0"    ||
                  "$_first" == "::" ]]; then
                log "DEBUG" "Whitelist Hosts-Format erkannt, extrahiere: $_second"
                line="$_second"
            else
                log "WARN" "Whitelist-Eintrag übersprungen (unbekanntes Format): $line"
                continue
            fi
        fi

        # Klassifizieren und validieren
        if [[ "$line" == *:* ]]; then
            # IPv6
            if _is_valid_ipv6 "$line"; then
                echo "$line"
            else
                log "WARN" "Whitelist-Eintrag übersprungen (ungültige IPv6): $line"
            fi

        elif [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            # IPv4 (nur Ziffern, Punkte und optionaler CIDR-Suffix)
            [[ "$line" == "0.0.0.0"* ]] && continue
            if _is_valid_ipv4 "$line"; then
                echo "$line"
            else
                log "WARN" "Whitelist-Eintrag übersprungen (ungültige IPv4): $line"
            fi

        else
            # Hostname → DNS-Auflösung (wird bei jedem Durchlauf neu aufgelöst!)
            if ! _is_valid_hostname "$line"; then
                log "WARN" "Whitelist-Eintrag übersprungen (kein gültiger Hostname): $line"
                continue
            fi
            local resolved
            resolved=$(getent ahosts "$line" 2>/dev/null | awk '{print $1}' | sort -u) || resolved=""
            if [[ -z "$resolved" ]]; then
                log "WARN" "Whitelist-Hostname konnte nicht aufgelöst werden: $line"
                continue
            fi
            local resolved_count=0
            while IFS= read -r resolved_ip; do
                [[ -z "$resolved_ip" ]]            && continue
                [[ "$resolved_ip" == "0.0.0.0" ]] && continue
                [[ "$resolved_ip" == "::"  ]]      && continue
                [[ "$resolved_ip" == "::0" ]]      && continue
                echo "$resolved_ip"
                resolved_count=$((resolved_count + 1))
            done <<< "$resolved"
            if [[ $resolved_count -gt 0 ]]; then
                log "DEBUG" "Whitelist-Hostname aufgelöst: $line → $resolved_count IP(s)"
            else
                log "WARN" "Whitelist-Hostname lieferte nur ungültige Adressen: $line"
            fi
        fi
    done < "$cache_file"
}

# ─── Whitelisten synchronisieren ─────────────────────────────────────────────
sync_whitelists() {
    # Alle URLs herunterladen
    IFS=',' read -ra urls <<< "$EXTERNAL_WHITELIST_URLS"
    local index=0

    for url in "${urls[@]}"; do
        url=$(echo "$url" | xargs)
        [[ -z "$url" ]] && continue

        download_whitelist "$url" "$index" || true
        index=$((index + 1))
    done

    # Alle Eintraege aus Cache-Dateien parsen und IPs aufloesen
    local all_ips_file="${EXTERNAL_WHITELIST_CACHE_DIR}/.all_ips.tmp"
    > "$all_ips_file"

    for cache_file in "${EXTERNAL_WHITELIST_CACHE_DIR}"/whitelist_*.txt; do
        [[ -f "$cache_file" ]] || continue
        parse_whitelist_entries "$cache_file" >> "$all_ips_file"
    done

    # Duplikate entfernen und in SQLite-Whitelist schreiben (atomar)
    local unique_file="${EXTERNAL_WHITELIST_CACHE_DIR}/.all_ips_unique.tmp"
    sort -u "$all_ips_file" > "$unique_file"
    local unique_count
    unique_count=$(wc -l < "$unique_file" | xargs)

    db_whitelist_sync "external" < "$unique_file"

    rm -f "$all_ips_file" "$unique_file"

    log "DEBUG" "Externe Whitelist: $unique_count eindeutige IPs aufgelöst"

    # Pruefen ob gesperrte IPs jetzt auf der Whitelist stehen
    check_banned_whitelist_ips
}

# ─── Gesperrte IPs prüfen die jetzt gewhitelistet sind ──────────────────────
check_banned_whitelist_ips() {
    # Alle gesperrten IPs pruefen, ob sie jetzt auf der Whitelist stehen
    local banned_ips
    banned_ips=$(db_query "SELECT a.client_ip FROM active_bans a INNER JOIN whitelist_cache w ON a.client_ip = w.ip_address;")
    [[ -z "$banned_ips" ]] && return

    while IFS= read -r client_ip; do
        [[ -z "$client_ip" ]] && continue
        log "INFO" "Gesperrte IP $client_ip ist jetzt auf externer Whitelist – entsperre automatisch"

        if [[ "$client_ip" == *:* ]]; then
            ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        else
            iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        fi

        db_ban_delete "$client_ip"
        db_history_add "UNBAN" "$client_ip" "-" "-" "external-whitelist" "-" "-"
    done <<< "$banned_ips"
}

# ─── PID-Management ──────────────────────────────────────────────────────────
write_pid() {
    echo $$ > "$WORKER_PID_FILE"
}

cleanup() {
    log "INFO" "Externer Whitelist-Worker wird beendet..."
    rm -f "$WORKER_PID_FILE"
    exit 0
}

check_already_running() {
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            log "DEBUG" "Whitelist-Worker läuft bereits (PID: $old_pid)"
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
    echo "  Externer Whitelist-Worker - Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [[ "$EXTERNAL_WHITELIST_ENABLED" != "true" ]]; then
        echo "  ⚠️  Externer Whitelist-Worker ist deaktiviert"
        echo "  Aktivieren: EXTERNAL_WHITELIST_ENABLED=true in $CONFIG_FILE"
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
    echo "  Konfigurierte Whitelisten:"
    IFS=',' read -ra urls <<< "$EXTERNAL_WHITELIST_URLS"
    local index=0
    for url in "${urls[@]}"; do
        url=$(echo "$url" | xargs)
        [[ -z "$url" ]] && continue
        local cache_file="${EXTERNAL_WHITELIST_CACHE_DIR}/whitelist_${index}.txt"
        if [[ -f "$cache_file" ]]; then
            local entry_count
            entry_count=$(grep -cv '^\s*#\|^\s*$' "$cache_file" 2>/dev/null || echo "0")
            local last_modified
            last_modified=$(date -r "$cache_file" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unbekannt")
            echo "    [$index] $url"
            echo "        Einträge: $entry_count | Zuletzt aktualisiert: $last_modified"
        else
            echo "    [$index] $url (noch nicht heruntergeladen)"
        fi
        index=$((index + 1))
    done

    echo ""

    # Aufgelöste IPs aus Datenbank
    local resolved_count
    resolved_count=$(db_whitelist_count)

    if [[ "${resolved_count:-0}" -gt 0 ]]; then
        echo "  Aufgelöste IPs: $resolved_count"

        if [[ "$resolved_count" -le 20 ]]; then
            echo ""
            echo "  Aktuelle IPs:"
            local all_wl_ips
            all_wl_ips=$(db_whitelist_get_all)
            while IFS= read -r ip; do
                echo "    ✅ $ip"
            done <<< "$all_wl_ips"
        else
            echo ""
            echo "  Erste 20 IPs:"
            local first_wl_ips
            first_wl_ips=$(db_query "SELECT ip_address FROM whitelist_cache LIMIT 20;")
            while IFS= read -r ip; do
                echo "    ✅ $ip"
            done <<< "$first_wl_ips"
            echo "    ... ($((resolved_count - 20)) weitere)"
        fi
    else
        echo "  Aufgelöste IPs: 0 (noch keine Synchronisation durchgeführt)"
    fi

    echo ""
    echo "  Prüfintervall: ${EXTERNAL_WHITELIST_INTERVAL}s"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Einmalig synchronisieren ────────────────────────────────────────────────
run_once() {
    init_directories

    if [[ -z "${EXTERNAL_WHITELIST_URLS:-}" ]]; then
        log "ERROR" "Keine externen Whitelist-URLs konfiguriert (EXTERNAL_WHITELIST_URLS)"
        exit 1
    fi

    log "INFO" "Einmalige Whitelist-Synchronisation..."
    sync_whitelists
    log "INFO" "Whitelist-Synchronisation abgeschlossen"
}

# ─── Hauptschleife ──────────────────────────────────────────────────────────
main_loop() {
    init_directories

    if [[ -z "${EXTERNAL_WHITELIST_URLS:-}" ]]; then
        log "ERROR" "Keine externen Whitelist-URLs konfiguriert (EXTERNAL_WHITELIST_URLS)"
        exit 1
    fi

    log "INFO" "═══════════════════════════════════════════════════════════"
    log "INFO" "Externer Whitelist-Worker gestartet"
    log "INFO" "  URLs: ${EXTERNAL_WHITELIST_URLS}"
    log "INFO" "  Prüfintervall: ${EXTERNAL_WHITELIST_INTERVAL}s"
    log "INFO" "═══════════════════════════════════════════════════════════"

    while true; do
        sync_whitelists
        sleep "$EXTERNAL_WHITELIST_INTERVAL"
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
            echo "Whitelist-Worker gestoppt"
        else
            echo "Whitelist-Worker läuft nicht"
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
        echo "Entferne aufgelöste externe Whitelist-IPs..."
        db_whitelist_clear
        echo "Externe Whitelist-IPs entfernt"
        ;;
    *)
        cat << USAGE
AdGuard Shield - Externer Whitelist-Worker

Nutzung: $0 {start|stop|sync|status|flush}

Befehle:
  start      Startet den Worker (Dauerbetrieb)
  stop       Stoppt den Worker
  sync       Einmalige Synchronisation (DNS-Auflösung)
  status     Zeigt Status und aufgelöste IPs
  flush      Entfernt alle aufgelösten Whitelist-IPs

Konfiguration: $CONFIG_FILE

USAGE
        exit 0
        ;;
esac
