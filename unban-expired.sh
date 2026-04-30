#!/bin/bash
###############################################################################
# AdGuard Shield - Cron-basierter Unban-Timer
# Kann als Alternative zum Haupt-Script für das Entsperren genutzt werden.
# Wird z.B. alle 5 Minuten per Cron aufgerufen um abgelaufene Sperren zu prüfen.
#
# Crontab-Eintrag:
#   */5 * * * * /opt/adguard-shield/unban-expired.sh
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-shield.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    exit 1
fi
source "$CONFIG_FILE"
# shellcheck source=db.sh
source "${SCRIPT_DIR}/db.sh"

LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [UNBAN-TIMER]"

# Datenbank initialisieren
mkdir -p "${STATE_DIR}"
db_init

unban_count=0

# Abgelaufene Sperren aus der Datenbank abfragen
expired_ips=$(db_ban_get_expired)

if [[ -n "$expired_ips" ]]; then
    while IFS= read -r client_ip; do
        [[ -z "$client_ip" ]] && continue

        # Domain und Protokoll für History-Eintrag holen
        local_ban_data=$(db_ban_get "$client_ip")
        domain=$(echo "$local_ban_data" | cut -d'|' -f2)
        protocol=$(echo "$local_ban_data" | cut -d'|' -f10)

        echo "$LOG_PREFIX Entsperre abgelaufene Sperre: $client_ip" >> "$LOG_FILE"

        # iptables Regel entfernen
        if [[ "$client_ip" == *:* ]]; then
            ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        else
            iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        fi

        # Ban-History Eintrag
        db_history_add "UNBAN" "$client_ip" "${domain:--}" "-" "expired-cron" "-" "${protocol:-}"

        db_ban_delete "$client_ip"
        unban_count=$((unban_count + 1))
    done <<< "$expired_ips"
fi

if [[ $unban_count -gt 0 ]]; then
    echo "$LOG_PREFIX $unban_count Sperren aufgehoben" >> "$LOG_FILE"
fi
