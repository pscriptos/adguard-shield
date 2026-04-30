#!/bin/bash
###############################################################################
# AdGuard Shield - Offense-Cleanup-Worker
# Räumt abgelaufene Offense-Zähler (progressive Sperren) automatisch auf.
# Entfernt .offenses-Dateien, deren letztes Vergehen länger als
# PROGRESSIVE_BAN_RESET_AFTER zurückliegt.
# Wird als Hintergrundprozess vom Hauptscript gestartet.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Datum:   2026-04-16
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

# ─── Niedrigste Priorität setzen (CPU + I/O) ─────────────────────────────────
# Stellt sicher, dass der Worker auch bei manuellem Start nie andere Dienste
# verdrängt. nice 19 = niedrigste CPU-Priorität, ionice idle = nur bei freier I/O.
renice -n 19 $$ >/dev/null 2>&1 || true
ionice -c 3 -p $$ >/dev/null 2>&1 || true

# ─── Worker PID-File ──────────────────────────────────────────────────────────
WORKER_PID_FILE="/var/run/adguard-offense-cleanup-worker.pid"

# ─── Prüfintervall ───────────────────────────────────────────────────────────
# Prüft einmal pro Stunde – das ist völlig ausreichend für diese Aufgabe
OFFENSE_CLEANUP_INTERVAL=3600

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
        local log_entry="[$timestamp] [$level] [OFFENSE-CLEANUP] $message"
        echo "$log_entry" | tee -a "$LOG_FILE" >&2
    fi
}

# ─── Hilfsfunktionen ─────────────────────────────────────────────────────────
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

# ─── Verzeichnisse erstellen ──────────────────────────────────────────────────
init_directories() {
    mkdir -p "${STATE_DIR}"
    mkdir -p "$(dirname "$LOG_FILE")"
    db_init
}

# ─── Abgelaufene Offense-Zähler aufräumen ────────────────────────────────────
cleanup_expired_offenses() {
    local reset_after="${PROGRESSIVE_BAN_RESET_AFTER:-86400}"
    local now
    now=$(date '+%s')
    local cutoff=$((now - reset_after))

    local expired_rows
    expired_rows=$(db_query "SELECT client_ip, offense_level, last_offense_epoch FROM offense_tracking WHERE last_offense_epoch <= $cutoff;")

    if [[ -n "$expired_rows" ]]; then
        while IFS='|' read -r client_ip offense_level last_epoch; do
            [[ -z "$client_ip" ]] && continue
            local elapsed=$((now - last_epoch))
            log "INFO" "Offense-Zähler abgelaufen: $client_ip (Stufe $offense_level, letztes Vergehen vor $(format_duration $elapsed)) → entfernt"
        done <<< "$expired_rows"
    fi

    local cleaned
    cleaned=$(db_offense_delete_expired "$reset_after")

    if [[ "$cleaned" -gt 0 ]]; then
        log "INFO" "Offense-Cleanup: $cleaned abgelaufene Zähler entfernt"
    else
        log "DEBUG" "Offense-Cleanup: keine abgelaufenen Zähler gefunden"
    fi
}

# ─── PID-Management ──────────────────────────────────────────────────────────
write_pid() {
    echo $$ > "$WORKER_PID_FILE"
}

cleanup() {
    log "INFO" "Offense-Cleanup-Worker wird beendet..."
    rm -f "$WORKER_PID_FILE"
    exit 0
}

check_already_running() {
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            log "DEBUG" "Offense-Cleanup-Worker läuft bereits (PID: $old_pid)"
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
    echo "  Offense-Cleanup-Worker - Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [[ "${PROGRESSIVE_BAN_ENABLED:-false}" != "true" ]]; then
        echo "  ⚠️  Progressive Sperren sind deaktiviert"
        echo "  Aktivieren: PROGRESSIVE_BAN_ENABLED=true in $CONFIG_FILE"
        echo ""
        return
    fi

    # Worker-Prozess Status
    if [[ -f "$WORKER_PID_FILE" ]]; then
        local pid
        pid=$(cat "$WORKER_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "  🟢 Worker läuft (PID: $pid)"
        else
            echo "  🔴 Worker nicht aktiv (veraltete PID-Datei)"
        fi
    else
        echo "  🔴 Worker nicht aktiv"
    fi

    echo ""
    echo "  Reset-Zeitraum: $(format_duration "${PROGRESSIVE_BAN_RESET_AFTER:-86400}")"
    echo "  Prüfintervall: $(format_duration "$OFFENSE_CLEANUP_INTERVAL")"

    local reset_after="${PROGRESSIVE_BAN_RESET_AFTER:-86400}"
    local total
    total=$(db_offense_count)
    local expired
    expired=$(db_offense_count_expired "$reset_after")

    echo ""
    echo "  Offense-Zähler gesamt: $total"
    echo "  Davon abgelaufen: $expired"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Hauptschleife ──────────────────────────────────────────────────────────
main_loop() {
    init_directories

    log "INFO" "═══════════════════════════════════════════════════════════"
    log "INFO" "Offense-Cleanup-Worker gestartet"
    log "INFO" "  Reset-Zeitraum: $(format_duration "${PROGRESSIVE_BAN_RESET_AFTER:-86400}")"
    log "INFO" "  Prüfintervall: $(format_duration "$OFFENSE_CLEANUP_INTERVAL")"
    log "INFO" "═══════════════════════════════════════════════════════════"

    while true; do
        cleanup_expired_offenses
        sleep "$OFFENSE_CLEANUP_INTERVAL"
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
            echo "Offense-Cleanup-Worker gestoppt"
        else
            echo "Offense-Cleanup-Worker läuft nicht"
        fi
        ;;
    run-once)
        init_directories
        log "INFO" "Einmaliger Offense-Cleanup..."
        cleanup_expired_offenses
        log "INFO" "Cleanup abgeschlossen"
        ;;
    status)
        init_directories
        show_status
        ;;
    *)
        cat << USAGE
AdGuard Shield - Offense-Cleanup-Worker

Nutzung: $0 {start|stop|run-once|status}

Befehle:
  start      Startet den Worker (Dauerbetrieb)
  stop       Stoppt den Worker
  run-once   Einmaliger Cleanup-Durchlauf
  status     Zeigt Status und aktuelle Offense-Zähler

Konfiguration: $CONFIG_FILE
USAGE
        ;;
esac
