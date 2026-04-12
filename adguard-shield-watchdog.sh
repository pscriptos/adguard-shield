#!/bin/bash
###############################################################################
# AdGuard Shield - Watchdog
# Prüft ob der Hauptservice läuft und startet ihn bei Bedarf neu.
# Wird über adguard-shield-watchdog.timer alle 5 Minuten ausgeführt.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

set -euo pipefail

INSTALL_DIR="/opt/adguard-shield"
CONFIG_FILE="${INSTALL_DIR}/adguard-shield.conf"
SERVICE_NAME="adguard-shield.service"
LOG_FILE="/var/log/adguard-shield.log"
WATCHDOG_STATE_FILE="/var/lib/adguard-shield/watchdog.state"

# ─── Logging ──────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_entry="[$timestamp] [WATCHDOG] [$level] $message"

    echo "$log_entry" | tee -a "$LOG_FILE"
}

# ─── Benachrichtigung senden ──────────────────────────────────────────────────
send_watchdog_notification() {
    local action="$1"  # "recovery" oder "failure"
    local detail="$2"

    # Konfiguration laden für Benachrichtigungs-Einstellungen
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return
    fi
    source "$CONFIG_FILE"

    if [[ "${NOTIFY_ENABLED:-false}" != "true" ]]; then
        return
    fi

    local my_hostname
    my_hostname=$(hostname)
    local title message

    if [[ "$action" == "recovery" ]]; then
        title="🔄 AdGuard Shield Watchdog"
        message="🔄 AdGuard Shield Watchdog auf ${my_hostname}
---
Der Service war ausgefallen und wurde automatisch neu gestartet.
${detail}"
    elif [[ "$action" == "failure" ]]; then
        title="🚨 AdGuard Shield Watchdog"
        message="🚨 AdGuard Shield Watchdog auf ${my_hostname}
---
Der Service konnte NICHT automatisch neu gestartet werden!
Manuelles Eingreifen erforderlich.
${detail}"
    fi

    case "${NOTIFY_TYPE:-}" in
        discord)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" '{content: $msg}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null || true
            ;;
        slack)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" '{text: $msg}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null || true
            ;;
        gotify)
            curl -s -X POST "$NOTIFY_WEBHOOK_URL" \
                -F "title=${title}" \
                -F "message=${message}" \
                -F "priority=5" &>/dev/null || true
            ;;
        ntfy)
            if [[ -n "${NTFY_TOPIC:-}" ]]; then
                local ntfy_url="${NTFY_SERVER_URL:-https://ntfy.sh}"
                local auth_args=()
                if [[ -n "${NTFY_TOKEN:-}" ]]; then
                    auth_args=(-H "Authorization: Bearer ${NTFY_TOKEN}")
                fi
                curl -s \
                    -H "Title: ${title}" \
                    -H "Priority: ${NTFY_PRIORITY:-5}" \
                    -H "Tags: warning,watchdog" \
                    "${auth_args[@]}" \
                    -d "$message" \
                    "${ntfy_url}/${NTFY_TOPIC}" &>/dev/null || true
            fi
            ;;
        generic)
            local json_payload
            json_payload=$(jq -nc --arg msg "$message" --arg act "watchdog_${action}" \
                '{message: $msg, action: $act}')
            curl -s -H "Content-Type: application/json" \
                -d "$json_payload" \
                "$NOTIFY_WEBHOOK_URL" &>/dev/null || true
            ;;
    esac
}

# ─── Hauptlogik ──────────────────────────────────────────────────────────────
main() {
    # Verzeichnis für State-Datei sicherstellen
    mkdir -p "$(dirname "$WATCHDOG_STATE_FILE")"

    # Prüfen ob der Service aktiv ist
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        # Service läuft – falls vorher ausgefallen war, Status zurücksetzen
        if [[ -f "$WATCHDOG_STATE_FILE" ]]; then
            rm -f "$WATCHDOG_STATE_FILE"
        fi
        exit 0
    fi

    # Service läuft NICHT – Recovery versuchen
    log "WARN" "Service $SERVICE_NAME ist nicht aktiv – starte Recovery..."

    # Zähler für fehlgeschlagene Recovery-Versuche
    local fail_count=0
    if [[ -f "$WATCHDOG_STATE_FILE" ]]; then
        fail_count=$(cat "$WATCHDOG_STATE_FILE" 2>/dev/null || echo "0")
    fi

    # systemd reset-failed damit StartLimit zurückgesetzt wird
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

    # Service starten
    if systemctl start "$SERVICE_NAME" 2>/dev/null; then
        # Kurz warten und prüfen ob er auch wirklich läuft
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "INFO" "Service $SERVICE_NAME erfolgreich neu gestartet (Watchdog Recovery)"
            send_watchdog_notification "recovery" "Versuch: $((fail_count + 1))"
            rm -f "$WATCHDOG_STATE_FILE"
            exit 0
        fi
    fi

    # Start fehlgeschlagen
    fail_count=$((fail_count + 1))
    echo "$fail_count" > "$WATCHDOG_STATE_FILE"
    log "ERROR" "Service $SERVICE_NAME konnte nicht gestartet werden (Fehlversuch: $fail_count)"

    # Bei jedem 3. Fehlversuch eine Benachrichtigung senden (Spam vermeiden)
    if [[ $((fail_count % 3)) -eq 1 ]]; then
        send_watchdog_notification "failure" "Fehlversuche: $fail_count
Letzter Fehler: $(systemctl status "$SERVICE_NAME" 2>&1 | tail -5)"
    fi

    exit 1
}

main
