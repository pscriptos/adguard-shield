#!/bin/bash
###############################################################################
# AdGuard Shield - Cron-basierter Unban-Timer
# Kann als Alternative zum Haupt-Script für das Entsperren genutzt werden.
# Wird z.B. alle 5 Minuten per Cron aufgerufen um abgelaufene Sperren zu prüfen.
#
# Crontab-Eintrag:
#   */5 * * * * /opt/adguard-ratelimit/unban-expired.sh
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-ratelimit.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    exit 1
fi
source "$CONFIG_FILE"

BAN_HISTORY_FILE="${BAN_HISTORY_FILE:-/var/log/adguard-ratelimit-bans.log}"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [UNBAN-TIMER]"
NOW=$(date '+%s')

# History-Eintrag schreiben
log_ban_history() {
    local action="$1"
    local client_ip="$2"
    local domain="${3:-}"
    local count="${4:-}"
    local reason="${5:-}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ ! -f "$BAN_HISTORY_FILE" ]]; then
        echo "# AdGuard Shield - Ban History" > "$BAN_HISTORY_FILE"
        echo "# Format: ZEITSTEMPEL | AKTION | CLIENT-IP | DOMAIN | ANFRAGEN | SPERRDAUER | GRUND" >> "$BAN_HISTORY_FILE"
        echo "#─────────────────────────────────────────────────────────────────────────────────" >> "$BAN_HISTORY_FILE"
    fi

    printf "%-19s | %-6s | %-39s | %-30s | %-8s | %-10s | %s\n" \
        "$timestamp" "$action" "$client_ip" "${domain:--}" "${count:--}" "-" "${reason:-expired}" \
        >> "$BAN_HISTORY_FILE"
}

unban_count=0

for state_file in "${STATE_DIR}"/*.ban; do
    [[ -f "$state_file" ]] || continue

    ban_until_epoch=$(grep '^BAN_UNTIL_EPOCH=' "$state_file" | cut -d= -f2)
    client_ip=$(grep '^CLIENT_IP=' "$state_file" | cut -d= -f2)
    domain=$(grep '^DOMAIN=' "$state_file" | cut -d= -f2)

    if [[ -n "$ban_until_epoch" && "$NOW" -ge "$ban_until_epoch" ]]; then
        echo "$LOG_PREFIX Entsperre abgelaufene Sperre: $client_ip" >> "$LOG_FILE"

        # iptables Regel entfernen
        if [[ "$client_ip" == *:* ]]; then
            ip6tables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        else
            iptables -D "$IPTABLES_CHAIN" -s "$client_ip" -j DROP 2>/dev/null || true
        fi

        # Ban-History Eintrag
        log_ban_history "UNBAN" "$client_ip" "$domain" "-" "expired-cron"

        rm -f "$state_file"
        unban_count=$((unban_count + 1))
    fi
done

if [[ $unban_count -gt 0 ]]; then
    echo "$LOG_PREFIX $unban_count Sperren aufgehoben" >> "$LOG_FILE"
fi
