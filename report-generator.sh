#!/bin/bash
###############################################################################
# AdGuard Shield - Report Generator
# Erstellt und versendet periodische Statistik-Reports per E-Mail.
#
# Nutzung:
#   report-generator.sh send       – Report sofort generieren und versenden
#   report-generator.sh test       – Test-E-Mail senden (Konfiguration prüfen)
#   report-generator.sh generate   – Report als Datei generieren (ohne Versand)
#   report-generator.sh install    – Cron-Job einrichten
#   report-generator.sh remove     – Cron-Job entfernen
#   report-generator.sh status     – Cron-Status anzeigen
#
# Crontab-Eintrag (wird automatisch verwaltet):
#   Wird je nach REPORT_INTERVAL als Cron-Job unter /etc/cron.d/ angelegt.
#
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-shield.conf"
CRON_FILE="/etc/cron.d/adguard-shield-report"

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
REPORT_ENABLED="${REPORT_ENABLED:-false}"
REPORT_INTERVAL="${REPORT_INTERVAL:-weekly}"
REPORT_TIME="${REPORT_TIME:-08:00}"
REPORT_EMAIL_TO="${REPORT_EMAIL_TO:-}"
REPORT_EMAIL_FROM="${REPORT_EMAIL_FROM:-adguard-shield@$(hostname -f 2>/dev/null || hostname)}"
REPORT_FORMAT="${REPORT_FORMAT:-html}"
REPORT_MAIL_CMD="${REPORT_MAIL_CMD:-msmtp}"
REPORT_BUSIEST_DAY_RANGE="${REPORT_BUSIEST_DAY_RANGE:-30}"
BAN_HISTORY_FILE="${BAN_HISTORY_FILE:-/var/log/adguard-shield-bans.log}"
BAN_HISTORY_RETENTION_DAYS="${BAN_HISTORY_RETENTION_DAYS:-0}"
STATE_DIR="${STATE_DIR:-/var/lib/adguard-shield}"
TEMPLATE_DIR="${SCRIPT_DIR}/templates"

# Version aus dem Hauptscript auslesen
VERSION="unknown"
if [[ -f "${SCRIPT_DIR}/adguard-shield.sh" ]]; then
    VERSION=$(grep -m1 '^VERSION=' "${SCRIPT_DIR}/adguard-shield.sh" 2>/dev/null | cut -d'"' -f2)
    VERSION="${VERSION:-unknown}"
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE="${LOG_FILE:-/var/log/adguard-shield.log}"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] [REPORT] $message" | tee -a "$LOG_FILE" >&2
}

# ─── Versionsnummern vergleichen ──────────────────────────────────────────────
# Gibt 0 zurück, wenn $1 > $2 (semver-Vergleich, v-Präfix wird ignoriert)
version_gt() {
    local v1="${1#v}"
    local v2="${2#v}"
    [[ "$v1" == "$v2" ]] && return 1
    local IFS='.' i a b
    read -ra ver1 <<< "$v1"
    read -ra ver2 <<< "$v2"
    local max_len=$(( ${#ver1[@]} > ${#ver2[@]} ? ${#ver1[@]} : ${#ver2[@]} ))
    for ((i=0; i<max_len; i++)); do
        a="${ver1[i]:-0}"
        b="${ver2[i]:-0}"
        [[ "$((10#${a}))" -gt "$((10#${b}))" ]] && return 0
        [[ "$((10#${a}))" -lt "$((10#${b}))" ]] && return 1
    done
    return 1
}

# ─── Versionsprüfung gegen Gitea-Releases ─────────────────────────────────────
check_for_update() {
    UPDATE_NOTICE_HTML=""
    UPDATE_NOTICE_TXT=""

    [[ "$VERSION" == "unknown" ]] && return

    local latest_tag
    latest_tag=$(curl -sf --max-time 5 \
        "https://git.techniverse.net/api/v1/repos/scriptos/adguard-shield/releases?limit=1&page=1" \
        2>/dev/null | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    [[ -z "$latest_tag" ]] && return

    if version_gt "$latest_tag" "$VERSION"; then
        UPDATE_NOTICE_HTML='<div class="update-notice">🆕 Update verfügbar: <strong>'"${latest_tag}"'</strong> · <a href="https://git.techniverse.net/scriptos/adguard-shield/releases">Jetzt aktualisieren →</a></div>'
        UPDATE_NOTICE_TXT="  ⚠  Neue Version verfügbar: ${latest_tag}
  Update: https://git.techniverse.net/scriptos/adguard-shield/releases
"
    fi
}



# ─── Berichtszeitraum berechnen ───────────────────────────────────────────────

# Gibt Epoch-Wert für heute 00:00:00 (Mitternacht) zurück
get_today_midnight() {
    date -d "today 00:00:00" '+%s' 2>/dev/null || date -v0H -v0M -v0S '+%s'
}

get_report_period() {
    local today_midnight
    today_midnight=$(get_today_midnight)
    # Ende des Berichtszeitraums ist immer das Ende von gestern (23:59:59)
    local end_epoch=$((today_midnight - 1))
    local start_epoch
    local period_label

    case "$REPORT_INTERVAL" in
        daily)
            start_epoch=$((today_midnight - 86400))
            period_label="Tagesbericht"
            ;;
        weekly)
            start_epoch=$((today_midnight - 7 * 86400))
            period_label="Wochenbericht"
            ;;
        biweekly)
            start_epoch=$((today_midnight - 14 * 86400))
            period_label="Zweiwochenbericht"
            ;;
        monthly)
            start_epoch=$((today_midnight - 30 * 86400))
            period_label="Monatsbericht"
            ;;
        *)
            start_epoch=$((today_midnight - 7 * 86400))
            period_label="Bericht"
            ;;
    esac

    local start_date
    start_date=$(date -d "@$start_epoch" '+%d.%m.%Y' 2>/dev/null || date -r "$start_epoch" '+%d.%m.%Y')
    local end_date
    end_date=$(date -d "@$end_epoch" '+%d.%m.%Y' 2>/dev/null || date -r "$end_epoch" '+%d.%m.%Y')

    if [[ "$REPORT_INTERVAL" == "daily" ]]; then
        echo "${period_label}: ${start_date}"
    else
        echo "${period_label}: ${start_date} – ${end_date}"
    fi
}

get_period_start_epoch() {
    local today_midnight
    today_midnight=$(get_today_midnight)

    case "$REPORT_INTERVAL" in
        daily)    echo $((today_midnight - 86400)) ;;
        weekly)   echo $((today_midnight - 7 * 86400)) ;;
        biweekly) echo $((today_midnight - 14 * 86400)) ;;
        monthly)  echo $((today_midnight - 30 * 86400)) ;;
        *)        echo $((today_midnight - 7 * 86400)) ;;
    esac
}

get_period_end_epoch() {
    # Ende des Berichtszeitraums = Ende von gestern (heute 00:00:00 minus 1 Sekunde)
    local today_midnight
    today_midnight=$(get_today_midnight)
    echo $((today_midnight - 1))
}

# ─── Ban-History bereinigen ────────────────────────────────────────────────────
cleanup_ban_history() {
    [[ "$BAN_HISTORY_RETENTION_DAYS" == "0" || -z "$BAN_HISTORY_RETENTION_DAYS" ]] && return

    local removed
    removed=$(db_history_cleanup "$BAN_HISTORY_RETENTION_DAYS")
    if [[ "${removed:-0}" -gt 0 ]]; then
        log "INFO" "Ban-History bereinigt: $removed Einträge älter als ${BAN_HISTORY_RETENTION_DAYS} Tage entfernt"
    fi
}

# ─── Statistiken für beliebigen Zeitraum berechnen ──────────────────────────
get_stats_for_epoch_range() {
    local start_epoch="$1"
    local end_epoch="$2"

    local result
    result=$(db_history_stats_for_range "$start_epoch" "$end_epoch")
    if [[ -z "$result" ]]; then
        echo "0|0|0|0"
        return
    fi
    echo "$result"
}

# ─── Statistiken berechnen ────────────────────────────────────────────────────
calculate_stats() {
    # Ban-History bereinigen (falls Retention konfiguriert)
    cleanup_ban_history

    # Datenbank initialisieren
    db_init

    local start_epoch
    start_epoch=$(get_period_start_epoch)
    local end_epoch
    end_epoch=$(get_period_end_epoch)

    local total_history
    total_history=$(db_history_count)

    if [[ "${total_history:-0}" -eq 0 ]]; then
        TOTAL_BANS=0
        TOTAL_UNBANS=0
        UNIQUE_IPS=0
        PERMANENT_BANS=0
        ACTIVE_BANS=0
        ABUSEIPDB_REPORTS=0
        RATELIMIT_BANS=0
        SUBDOMAIN_FLOOD_BANS=0
        EXTERNAL_BLOCKLIST_BANS=0
        BUSIEST_DAY="–"
        BUSIEST_DAY_LABEL="Aktivster Tag"
        TOP10_IPS=""
        TOP10_DOMAINS=""
        PROTOCOL_STATS=""
        RECENT_BANS=""
        return
    fi

    # Haupt-Statistiken per SQL
    local stats_row
    stats_row=$(db_history_report_stats "$start_epoch" "$end_epoch")
    IFS='|' read -r TOTAL_BANS TOTAL_UNBANS UNIQUE_IPS PERMANENT_BANS RATELIMIT_BANS SUBDOMAIN_FLOOD_BANS EXTERNAL_BLOCKLIST_BANS <<< "$stats_row"

    # Busiest-Day-Bereich berechnen
    local busiest_start_epoch
    if [[ "$REPORT_BUSIEST_DAY_RANGE" == "0" || -z "$REPORT_BUSIEST_DAY_RANGE" ]]; then
        busiest_start_epoch="$start_epoch"
    else
        local today_midnight
        today_midnight=$(get_today_midnight)
        busiest_start_epoch=$((today_midnight - REPORT_BUSIEST_DAY_RANGE * 86400))
    fi

    local busiest_row
    busiest_row=$(db_history_busiest_day "$busiest_start_epoch" "$end_epoch")
    if [[ -n "$busiest_row" ]]; then
        local busiest_raw busiest_cnt
        IFS='|' read -r busiest_raw busiest_cnt <<< "$busiest_row"
        local busiest_formatted
        busiest_formatted=$(date -d "$busiest_raw" '+%d.%m.%Y' 2>/dev/null || echo "$busiest_raw")
        BUSIEST_DAY="${busiest_formatted} (${busiest_cnt})"
    else
        BUSIEST_DAY="–"
    fi

    if [[ "$REPORT_BUSIEST_DAY_RANGE" == "0" || -z "$REPORT_BUSIEST_DAY_RANGE" ]]; then
        BUSIEST_DAY_LABEL="Aktivster Tag"
    else
        BUSIEST_DAY_LABEL="Aktivster Tag (${REPORT_BUSIEST_DAY_RANGE} Tage)"
    fi

    # Top-Listen per SQL (Ausgabe: "count|value" → umformatieren zu "count value")
    TOP10_IPS=$(db_history_top_ips "$start_epoch" "$end_epoch" 10 | sed 's/|/ /')
    TOP10_DOMAINS=$(db_history_top_domains "$start_epoch" "$end_epoch" 10 | sed 's/|/ /')
    PROTOCOL_STATS=$(db_history_protocol_stats "$start_epoch" "$end_epoch" | sed 's/|/ /')
    RECENT_BANS=$(db_history_recent_bans "$start_epoch" "$end_epoch" 10)

    # Aktuell aktive Sperren aus der Datenbank
    ACTIVE_BANS=$(db_ban_count)

    # AbuseIPDB Reports – zeitraum-gefiltert aus der Logdatei
    ABUSEIPDB_REPORTS=0
    if [[ -f "$LOG_FILE" ]]; then
        ABUSEIPDB_REPORTS=$(grep "AbuseIPDB:.*erfolgreich gemeldet" "$LOG_FILE" 2>/dev/null | \
            awk -v s="$start_epoch" -v e="$end_epoch" '
                {
                    ts = substr($0, 2, 19)
                    if (ts !~ /^[0-9]{4}/) next
                    ep = mktime(substr(ts,1,4) " " substr(ts,6,2) " " substr(ts,9,2) " " \
                                substr(ts,12,2) " " substr(ts,15,2) " " substr(ts,18,2))
                    if (ep >= s && ep <= e) count++
                }
                END { print count+0 }
            ' || echo "0")
    fi
}

# ─── HTML-Tabellen generieren ─────────────────────────────────────────────────
generate_top10_ips_html() {
    if [[ -z "$TOP10_IPS" ]]; then
        echo '<div class="no-data">Keine Daten im Berichtszeitraum</div>'
        return
    fi

    local max_count
    max_count=$(echo "$TOP10_IPS" | head -1 | awk '{print $1}')

    local html='<table><tr><th>#</th><th>IP-Adresse</th><th>Sperren</th></tr>'
    local rank=0

    while read -r count ip; do
        [[ -z "$count" || -z "$ip" ]] && continue
        rank=$((rank + 1))
        local rank_class=""
        [[ $rank -le 3 ]] && rank_class=" top3"
        local bar_width=100
        if [[ "$max_count" -gt 0 ]]; then
            bar_width=$((count * 100 / max_count))
        fi
        html+="<tr><td><span class=\"rank${rank_class}\">${rank}</span></td>"
        html+="<td class=\"ip-cell\">${ip}</td>"
        html+="<td><div class=\"bar-container\"><div class=\"bar\" style=\"width:${bar_width}%\"></div><span class=\"bar-value\">${count}</span></div></td>"
        html+="</tr>"
    done <<< "$TOP10_IPS"

    html+='</table>'
    echo "$html"
}

generate_top10_domains_html() {
    if [[ -z "$TOP10_DOMAINS" ]]; then
        echo '<div class="no-data">Keine Daten im Berichtszeitraum</div>'
        return
    fi

    local max_count
    max_count=$(echo "$TOP10_DOMAINS" | head -1 | awk '{print $1}')

    local html='<table><tr><th>#</th><th>Domain</th><th>Sperren</th></tr>'
    local rank=0

    while read -r count domain; do
        [[ -z "$count" || -z "$domain" ]] && continue
        rank=$((rank + 1))
        local rank_class=""
        [[ $rank -le 3 ]] && rank_class=" top3"
        local bar_width=100
        if [[ "$max_count" -gt 0 ]]; then
            bar_width=$((count * 100 / max_count))
        fi
        html+="<tr><td><span class=\"rank${rank_class}\">${rank}</span></td>"
        html+="<td>${domain}</td>"
        html+="<td><div class=\"bar-container\"><div class=\"bar\" style=\"width:${bar_width}%\"></div><span class=\"bar-value\">${count}</span></div></td>"
        html+="</tr>"
    done <<< "$TOP10_DOMAINS"

    html+='</table>'
    echo "$html"
}

generate_protocol_html() {
    if [[ -z "$PROTOCOL_STATS" ]]; then
        echo '<div class="no-data">Keine Daten im Berichtszeitraum</div>'
        return
    fi

    local html='<table><tr><th>Protokoll</th><th>Anzahl Sperren</th></tr>'

    while read -r count proto; do
        [[ -z "$count" || -z "$proto" ]] && continue
        local badge_class=""
        case "${proto,,}" in
            dns*)     badge_class="dns" ;;
            doh*)     badge_class="doh" ;;
            dot*)     badge_class="dot" ;;
            doq*)     badge_class="doq" ;;
        esac
        html+="<tr><td><span class=\"protocol-badge ${badge_class}\">${proto}</span></td>"
        html+="<td>${count}</td></tr>"
    done <<< "$PROTOCOL_STATS"

    html+='</table>'
    echo "$html"
}

generate_recent_bans_html() {
    if [[ -z "$RECENT_BANS" ]]; then
        echo '<div class="no-data">Keine Sperren im Berichtszeitraum</div>'
        return
    fi

    local html='<table><tr><th>Zeitpunkt</th><th>IP</th><th>Domain</th><th>Grund</th></tr>'

    while IFS='|' read -r timestamp action ip domain count duration protocol reason; do
        timestamp=$(echo "$timestamp" | xargs)
        ip=$(echo "$ip" | xargs)
        [[ -z "$timestamp" && -z "$ip" ]] && continue
        domain=$(echo "$domain" | xargs)
        reason=$(echo "$reason" | xargs)
        [[ "$domain" == "-" ]] && domain="–"
        [[ -z "$reason" ]] && reason="rate-limit"

        local reason_class="rate-limit"
        [[ "$reason" == *"subdomain"* ]] && reason_class="subdomain-flood"
        [[ "$reason" == *"external"* ]] && reason_class="external"

        # Datum kürzen für Anzeige
        local short_time
        short_time=$(echo "$timestamp" | awk '{print $1" "$2}' | cut -c6-)

        html+="<tr><td>${short_time}</td>"
        html+="<td class=\"ip-cell\">${ip}</td>"
        html+="<td>${domain}</td>"
        html+="<td><span class=\"reason-badge ${reason_class}\">${reason}</span></td>"
        html+="</tr>"
    done <<< "$RECENT_BANS"

    html+='</table>'
    echo "$html"
}

# ─── Zeitraum-Schnellübersicht (HTML) ─────────────────────────────────────────
generate_period_overview_html() {
    local today_midnight
    today_midnight=$(get_today_midnight)
    local now
    now=$(date '+%s')
    local yesterday_start=$((today_midnight - 86400))
    local yesterday_end=$((today_midnight - 1))

    # Zeiträume: "Label:start_epoch:end_epoch" (Doppelpunkt als Trennzeichen)
    local periods=()

    # Heute nur nach 20:00 Uhr einblenden
    local current_hour
    current_hour=$(date '+%H' | sed 's/^0*//')
    if [[ "${current_hour:-0}" -ge 20 ]]; then
        periods+=("Heute:${today_midnight}:${now}")
    fi

    periods+=(
        "Gestern:${yesterday_start}:${yesterday_end}"
        "Letzte 7 Tage:$((today_midnight - 7 * 86400)):${now}"
        "Letzte 14 Tage:$((today_midnight - 14 * 86400)):${now}"
        "Letzte 30 Tage:$((today_midnight - 30 * 86400)):${now}"
    )

    local html='<table>'
    html+='<tr>'
    html+='<th>Zeitraum</th>'
    html+='<th>Sperren</th>'
    html+='<th>Entsperrt</th>'
    html+='<th>Unique IPs</th>'
    html+='<th>Dauerhaft gebannt</th>'
    html+='</tr>'

    for period_def in "${periods[@]}"; do
        IFS=':' read -r label start_e end_e <<< "$period_def"
        local row_class=""
        case "$label" in
            Heute)   row_class=' class="period-today"' ;;
            Gestern) row_class=' class="period-gestern"' ;;
        esac
        local stats
        stats=$(get_stats_for_epoch_range "$start_e" "$end_e")
        IFS='|' read -r bans unbans unique perm <<< "$stats"

        html+="<tr${row_class}>"
        html+="<td><strong>${label}</strong></td>"
        html+="<td>${bans}</td>"
        html+="<td>${unbans}</td>"
        html+="<td>${unique}</td>"
        html+="<td>${perm}</td>"
        html+="</tr>"
    done

    html+='</table>'
    echo "$html"
}

# ─── TXT-Tabellen generieren ──────────────────────────────────────────────────
generate_top10_ips_txt() {
    if [[ -z "$TOP10_IPS" ]]; then
        echo "  Keine Daten im Berichtszeitraum"
        return
    fi

    local rank=0
    printf "  %-4s %-42s %s\n" "#" "IP-Adresse" "Sperren"
    printf "  %-4s %-42s %s\n" "──" "──────────────────────────────────────────" "───────"

    while read -r count ip; do
        [[ -z "$count" || -z "$ip" ]] && continue
        rank=$((rank + 1))
        printf "  %-4s %-42s %s\n" "${rank}." "$ip" "$count"
    done <<< "$TOP10_IPS"
}

generate_top10_domains_txt() {
    if [[ -z "$TOP10_DOMAINS" ]]; then
        echo "  Keine Daten im Berichtszeitraum"
        return
    fi

    local rank=0
    printf "  %-4s %-42s %s\n" "#" "Domain" "Sperren"
    printf "  %-4s %-42s %s\n" "──" "──────────────────────────────────────────" "───────"

    while read -r count domain; do
        [[ -z "$count" || -z "$domain" ]] && continue
        rank=$((rank + 1))
        printf "  %-4s %-42s %s\n" "${rank}." "$domain" "$count"
    done <<< "$TOP10_DOMAINS"
}

generate_protocol_txt() {
    if [[ -z "$PROTOCOL_STATS" ]]; then
        echo "  Keine Daten im Berichtszeitraum"
        return
    fi

    printf "  %-20s %s\n" "Protokoll" "Anzahl"
    printf "  %-20s %s\n" "────────────────────" "──────"

    while read -r count proto; do
        [[ -z "$count" || -z "$proto" ]] && continue
        printf "  %-20s %s\n" "$proto" "$count"
    done <<< "$PROTOCOL_STATS"
}

generate_recent_bans_txt() {
    if [[ -z "$RECENT_BANS" ]]; then
        echo "  Keine Sperren im Berichtszeitraum"
        return
    fi

    printf "  %-17s %-42s %-30s %s\n" "Zeitpunkt" "IP" "Domain" "Grund"
    printf "  %-17s %-42s %-30s %s\n" "─────────────────" "──────────────────────────────────────────" "──────────────────────────────" "──────────"

    while IFS='|' read -r timestamp action ip domain count duration protocol reason; do
        timestamp=$(echo "$timestamp" | xargs)
        ip=$(echo "$ip" | xargs)
        [[ -z "$timestamp" && -z "$ip" ]] && continue
        domain=$(echo "$domain" | xargs)
        reason=$(echo "$reason" | xargs)
        [[ "$domain" == "-" ]] && domain="–"
        [[ -z "$reason" ]] && reason="rate-limit"

        local short_time
        short_time=$(echo "$timestamp" | awk '{print $1" "$2}' | cut -c6-)

        printf "  %-17s %-42s %-30s %s\n" "$short_time" "$ip" "$domain" "$reason"
    done <<< "$RECENT_BANS"
}

# ─── Zeitraum-Schnellübersicht (TXT) ──────────────────────────────────────────
generate_period_overview_txt() {
    local today_midnight
    today_midnight=$(get_today_midnight)
    local now
    now=$(date '+%s')
    local yesterday_start=$((today_midnight - 86400))
    local yesterday_end=$((today_midnight - 1))

    local periods=()

    # Heute nur nach 20:00 Uhr einblenden
    local current_hour
    current_hour=$(date '+%H' | sed 's/^0*//')
    if [[ "${current_hour:-0}" -ge 20 ]]; then
        periods+=("Heute:${today_midnight}:${now}")
    fi

    periods+=(
        "Gestern:${yesterday_start}:${yesterday_end}"
        "Letzte 7 Tage:$((today_midnight - 7 * 86400)):${now}"
        "Letzte 14 Tage:$((today_midnight - 14 * 86400)):${now}"
        "Letzte 30 Tage:$((today_midnight - 30 * 86400)):${now}"
    )

    printf "  %-15s %-9s %-12s %-14s %-11s\n" \
        "Zeitraum" "Sperren" "Entsperrt" "Unique IPs" "Dauerhaft"
    printf "  %-15s %-9s %-12s %-14s %-11s\n" \
        "───────────────" "─────────" "────────────" "──────────────" "───────────"

    for period_def in "${periods[@]}"; do
        IFS=':' read -r label start_e end_e <<< "$period_def"
        local stats
        stats=$(get_stats_for_epoch_range "$start_e" "$end_e")
        IFS='|' read -r bans unbans unique perm <<< "$stats"
        printf "  %-15s %-9s %-12s %-14s %-11s\n" \
            "$label" "$bans" "$unbans" "$unique" "$perm"
    done
}

# ─── Report generieren ────────────────────────────────────────────────────────
generate_report() {
    local format="${1:-$REPORT_FORMAT}"

    log "INFO" "Generiere ${format^^}-Report..."

    # Statistiken berechnen
    calculate_stats

    # Update-Verfügbarkeit prüfen
    check_for_update

    local report_period
    report_period=$(get_report_period)
    local report_date
    report_date=$(date '+%d.%m.%Y %H:%M:%S')
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)

    if [[ "$format" == "html" ]]; then
        local template_file="${TEMPLATE_DIR}/report.html"
        if [[ ! -f "$template_file" ]]; then
            log "ERROR" "HTML-Template nicht gefunden: $template_file"
            return 1
        fi

        local report
        report=$(cat "$template_file")

        # Tabellen generieren
        local top10_ips_table
        top10_ips_table=$(generate_top10_ips_html)
        local top10_domains_table
        top10_domains_table=$(generate_top10_domains_html)
        local protocol_table
        protocol_table=$(generate_protocol_html)
        local recent_bans_table
        recent_bans_table=$(generate_recent_bans_html)
        local period_overview_table
        period_overview_table=$(generate_period_overview_html)

        # Platzhalter ersetzen
        report="${report//\{\{REPORT_PERIOD\}\}/$report_period}"
        report="${report//\{\{REPORT_DATE\}\}/$report_date}"
        report="${report//\{\{HOSTNAME\}\}/$hostname}"
        report="${report//\{\{VERSION\}\}/$VERSION}"
        report="${report//\{\{TOTAL_BANS\}\}/$TOTAL_BANS}"
        report="${report//\{\{TOTAL_UNBANS\}\}/$TOTAL_UNBANS}"
        report="${report//\{\{UNIQUE_IPS\}\}/$UNIQUE_IPS}"
        report="${report//\{\{PERMANENT_BANS\}\}/$PERMANENT_BANS}"
        report="${report//\{\{ACTIVE_BANS\}\}/$ACTIVE_BANS}"
        report="${report//\{\{ABUSEIPDB_REPORTS\}\}/$ABUSEIPDB_REPORTS}"
        report="${report//\{\{RATELIMIT_BANS\}\}/$RATELIMIT_BANS}"
        report="${report//\{\{SUBDOMAIN_FLOOD_BANS\}\}/$SUBDOMAIN_FLOOD_BANS}"
        report="${report//\{\{EXTERNAL_BLOCKLIST_BANS\}\}/$EXTERNAL_BLOCKLIST_BANS}"
        report="${report//\{\{BUSIEST_DAY\}\}/$BUSIEST_DAY}"
        report="${report//\{\{BUSIEST_DAY_LABEL\}\}/$BUSIEST_DAY_LABEL}"
        report="${report//\{\{TOP10_IPS_TABLE\}\}/$top10_ips_table}"
        report="${report//\{\{TOP10_DOMAINS_TABLE\}\}/$top10_domains_table}"
        report="${report//\{\{PROTOCOL_TABLE\}\}/$protocol_table}"
        report="${report//\{\{RECENT_BANS_TABLE\}\}/$recent_bans_table}"
        report="${report//\{\{PERIOD_OVERVIEW_TABLE\}\}/$period_overview_table}"
        report="${report//\{\{UPDATE_NOTICE\}\}/$UPDATE_NOTICE_HTML}"

        echo "$report"

    elif [[ "$format" == "txt" ]]; then
        local template_file="${TEMPLATE_DIR}/report.txt"
        if [[ ! -f "$template_file" ]]; then
            log "ERROR" "TXT-Template nicht gefunden: $template_file"
            return 1
        fi

        local report
        report=$(cat "$template_file")

        # Text-Tabellen generieren
        local top10_ips_txt
        top10_ips_txt=$(generate_top10_ips_txt)
        local top10_domains_txt
        top10_domains_txt=$(generate_top10_domains_txt)
        local protocol_txt
        protocol_txt=$(generate_protocol_txt)
        local recent_bans_txt
        recent_bans_txt=$(generate_recent_bans_txt)
        local period_overview_txt
        period_overview_txt=$(generate_period_overview_txt)

        # Platzhalter ersetzen
        report="${report//\{\{REPORT_PERIOD\}\}/$report_period}"
        report="${report//\{\{REPORT_DATE\}\}/$report_date}"
        report="${report//\{\{HOSTNAME\}\}/$hostname}"
        report="${report//\{\{VERSION\}\}/$VERSION}"
        report="${report//\{\{TOTAL_BANS\}\}/$TOTAL_BANS}"
        report="${report//\{\{TOTAL_UNBANS\}\}/$TOTAL_UNBANS}"
        report="${report//\{\{UNIQUE_IPS\}\}/$UNIQUE_IPS}"
        report="${report//\{\{PERMANENT_BANS\}\}/$PERMANENT_BANS}"
        report="${report//\{\{ACTIVE_BANS\}\}/$ACTIVE_BANS}"
        report="${report//\{\{ABUSEIPDB_REPORTS\}\}/$ABUSEIPDB_REPORTS}"
        report="${report//\{\{RATELIMIT_BANS\}\}/$RATELIMIT_BANS}"
        report="${report//\{\{SUBDOMAIN_FLOOD_BANS\}\}/$SUBDOMAIN_FLOOD_BANS}"
        report="${report//\{\{EXTERNAL_BLOCKLIST_BANS\}\}/$EXTERNAL_BLOCKLIST_BANS}"
        report="${report//\{\{BUSIEST_DAY\}\}/$BUSIEST_DAY}"
        report="${report//\{\{BUSIEST_DAY_LABEL\}\}/$BUSIEST_DAY_LABEL}"
        report="${report//\{\{TOP10_IPS_TEXT\}\}/$top10_ips_txt}"
        report="${report//\{\{TOP10_DOMAINS_TEXT\}\}/$top10_domains_txt}"
        report="${report//\{\{PROTOCOL_TEXT\}\}/$protocol_txt}"
        report="${report//\{\{RECENT_BANS_TEXT\}\}/$recent_bans_txt}"
        report="${report//\{\{PERIOD_OVERVIEW_TEXT\}\}/$period_overview_txt}"
        report="${report//\{\{UPDATE_NOTICE_TXT\}\}/$UPDATE_NOTICE_TXT}"

        echo "$report"
    else
        log "ERROR" "Unbekanntes Report-Format: $format"
        return 1
    fi
}

# ─── E-Mail senden ────────────────────────────────────────────────────────────
send_report_email() {
    if [[ -z "$REPORT_EMAIL_TO" ]]; then
        log "ERROR" "Kein E-Mail-Empfänger konfiguriert (REPORT_EMAIL_TO)"
        return 1
    fi

    # Prüfen ob Mail-Befehl verfügbar
    if ! command -v "$REPORT_MAIL_CMD" &>/dev/null; then
        log "ERROR" "Mail-Befehl nicht gefunden: $REPORT_MAIL_CMD"
        log "ERROR" "Bitte installieren, z.B.: sudo apt install msmtp msmtp-mta"
        log "ERROR" "Anleitung: https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/"
        return 1
    fi

    local report_content
    report_content=$(generate_report "$REPORT_FORMAT")

    if [[ -z "$report_content" ]]; then
        log "ERROR" "Report-Generierung fehlgeschlagen – keine Daten"
        return 1
    fi

    local subject="🛡️ AdGuard Shield $(get_report_period) – $(hostname)"
    local content_type="text/plain"
    [[ "$REPORT_FORMAT" == "html" ]] && content_type="text/html"

    log "INFO" "Sende Report an ${REPORT_EMAIL_TO} via ${REPORT_MAIL_CMD}..."

    # E-Mail zusammenbauen und senden
    {
        echo "From: ${REPORT_EMAIL_FROM}"
        echo "To: ${REPORT_EMAIL_TO}"
        echo "Subject: ${subject}"
        echo "MIME-Version: 1.0"
        echo "Content-Type: ${content_type}; charset=UTF-8"
        echo "Content-Transfer-Encoding: 8bit"
        echo "X-Mailer: AdGuard Shield Report Generator"
        echo ""
        echo "$report_content"
    } | "$REPORT_MAIL_CMD" -t 2>&1 || {
        log "ERROR" "E-Mail-Versand fehlgeschlagen (Exit-Code: $?)"
        log "ERROR" "Prüfe die ${REPORT_MAIL_CMD}-Konfiguration"
        return 1
    }

    log "INFO" "Report erfolgreich an ${REPORT_EMAIL_TO} gesendet"
}

# ─── Cron-Job verwalten ───────────────────────────────────────────────────────
install_cron() {
    if [[ "$REPORT_ENABLED" != "true" ]]; then
        log "WARN" "Report ist deaktiviert (REPORT_ENABLED=false)"
        echo "Report ist deaktiviert. Bitte REPORT_ENABLED=true setzen."
        return 1
    fi

    local hour minute
    hour=$(echo "$REPORT_TIME" | cut -d: -f1 | sed 's/^0//')
    minute=$(echo "$REPORT_TIME" | cut -d: -f2 | sed 's/^0//')

    local cron_schedule

    case "$REPORT_INTERVAL" in
        daily)
            cron_schedule="${minute} ${hour} * * *"
            ;;
        weekly)
            # Montag
            cron_schedule="${minute} ${hour} * * 1"
            ;;
        biweekly)
            # Alle zwei Wochen am Montag (ungerade Kalenderwochen)
            # Nutzt einen Test im Befehl selbst, da Cron keine 2-Wochen-Logik kann
            cron_schedule="${minute} ${hour} * * 1"
            ;;
        monthly)
            # 1. des Monats
            cron_schedule="${minute} ${hour} 1 * *"
            ;;
        *)
            log "ERROR" "Unbekanntes Intervall: $REPORT_INTERVAL"
            return 1
            ;;
    esac

    local cron_cmd="${SCRIPT_DIR}/report-generator.sh send"

    # Bei biweekly: Prüfung auf ungerade Kalenderwoche einbauen
    if [[ "$REPORT_INTERVAL" == "biweekly" ]]; then
        cron_cmd="[ \$(( \$(date +\\%V) \\% 2 )) -eq 1 ] && ${SCRIPT_DIR}/report-generator.sh send"
    fi

    # Cron-Datei schreiben
    cat > "$CRON_FILE" << EOF
# AdGuard Shield - Automatischer Report
# Generiert von: report-generator.sh install
# Intervall: ${REPORT_INTERVAL}
# Uhrzeit: ${REPORT_TIME}
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

${cron_schedule} root ${cron_cmd} >> /var/log/adguard-shield.log 2>&1
EOF

    chmod 644 "$CRON_FILE"

    log "INFO" "Cron-Job installiert: $CRON_FILE"
    echo "✅ Cron-Job installiert: $CRON_FILE"
    echo "   Intervall: $REPORT_INTERVAL"
    echo "   Uhrzeit:   $REPORT_TIME"
    echo "   Schedule:  $cron_schedule"
    echo "   Empfänger: $REPORT_EMAIL_TO"
}

remove_cron() {
    if [[ -f "$CRON_FILE" ]]; then
        rm -f "$CRON_FILE"
        log "INFO" "Cron-Job entfernt: $CRON_FILE"
        echo "✅ Cron-Job entfernt"
    else
        echo "ℹ️  Kein Cron-Job vorhanden"
    fi
}

show_cron_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield – Report Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Report aktiviert:    ${REPORT_ENABLED}"
    echo "  Intervall:           ${REPORT_INTERVAL}"
    echo "  Uhrzeit:             ${REPORT_TIME}"
    echo "  Format:              ${REPORT_FORMAT}"
    echo "  Empfänger:           ${REPORT_EMAIL_TO:-nicht konfiguriert}"
    echo "  Absender:            ${REPORT_EMAIL_FROM}"
    echo "  Mail-Befehl:         ${REPORT_MAIL_CMD}"
    echo "  Aktivster Tag:       letzte ${REPORT_BUSIEST_DAY_RANGE:-30} Tage"
    echo ""

    if command -v "$REPORT_MAIL_CMD" &>/dev/null; then
        echo "  ✅ ${REPORT_MAIL_CMD} ist installiert"
    else
        echo "  ❌ ${REPORT_MAIL_CMD} ist NICHT installiert"
        echo "     → Anleitung: https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/"
    fi

    echo ""

    if [[ -f "$CRON_FILE" ]]; then
        echo "  ✅ Cron-Job aktiv:"
        grep -v '^#' "$CRON_FILE" | grep -v '^$' | grep -v '^SHELL\|^PATH' | sed 's/^/     /'
    else
        echo "  ❌ Kein Cron-Job installiert"
        echo "     → Einrichten mit: sudo $(basename "$0") install"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Test-E-Mail senden ───────────────────────────────────────────────────────
send_test_email() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AdGuard Shield – E-Mail Test"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    local errors=0

    # 1. Empfänger prüfen
    echo -n "  1) E-Mail-Empfänger ... "
    if [[ -z "$REPORT_EMAIL_TO" ]]; then
        echo "❌ nicht konfiguriert (REPORT_EMAIL_TO ist leer)"
        errors=$((errors + 1))
    else
        echo "✅ $REPORT_EMAIL_TO"
    fi

    # 2. Absender prüfen
    echo -n "  2) E-Mail-Absender ... "
    echo "✅ $REPORT_EMAIL_FROM"

    # 3. Mail-Befehl prüfen
    echo -n "  3) Mail-Befehl ($REPORT_MAIL_CMD) ... "
    if command -v "$REPORT_MAIL_CMD" &>/dev/null; then
        local mail_path
        mail_path=$(command -v "$REPORT_MAIL_CMD")
        echo "✅ gefunden ($mail_path)"
    else
        echo "❌ NICHT gefunden"
        echo "     → Installieren: sudo apt install msmtp msmtp-mta"
        echo "     → Anleitung:    https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/"
        errors=$((errors + 1))
    fi

    # 4. Templates prüfen
    echo -n "  4) Report-Template ($REPORT_FORMAT) ... "
    local tpl="${TEMPLATE_DIR}/report.${REPORT_FORMAT}"
    if [[ -f "$tpl" ]]; then
        echo "✅ vorhanden"
    else
        echo "❌ nicht gefunden: $tpl"
        errors=$((errors + 1))
    fi

    # 5. Datenbank prüfen
    echo -n "  5) Datenbank ... "
    if [[ -f "$DB_FILE" ]]; then
        local entries
        entries=$(db_history_count 2>/dev/null || echo "0")
        echo "✅ vorhanden ($entries History-Einträge)"
    else
        echo "⚠️  nicht vorhanden (Report wird leer sein – das ist OK für einen Test)"
    fi

    echo ""

    if [[ $errors -gt 0 ]]; then
        echo "  ❌ $errors Fehler gefunden – bitte zuerst beheben."
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        return 1
    fi

    # 6. Test-Mail senden
    echo "  6) Sende Test-E-Mail an ${REPORT_EMAIL_TO} ..."
    echo ""

    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)
    local test_date
    test_date=$(date '+%d.%m.%Y %H:%M:%S')
    local subject="🧪 AdGuard Shield – Test-Mail von ${hostname}"
    local content_type="text/plain"
    [[ "$REPORT_FORMAT" == "html" ]] && content_type="text/html"

    local test_update_notice_html
    test_update_notice_html='<div style="display:inline-block;margin-top:10px;padding:7px 14px;background:#fff8e1;border:1px solid #ffc107;border-radius:8px;color:#7a5700;font-size:12px;font-weight:600;">🆕 Update verfügbar (Testanzeige): <strong>'"${VERSION}"'</strong> · <a href="https://git.techniverse.net/scriptos/adguard-shield/releases" style="color:#7a5700;font-weight:700;text-decoration:none;">Jetzt aktualisieren →</a></div>'
    local test_update_notice_txt
    test_update_notice_txt="  ⚠  Neue Version verfügbar (Testanzeige): ${VERSION}\n  Update: https://git.techniverse.net/scriptos/adguard-shield/releases\n"

    local test_body
    if [[ "$REPORT_FORMAT" == "html" ]]; then
        test_body=$(cat <<TESTHTML
<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;background:#f0f2f5;padding:30px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);color:#fff;padding:30px;text-align:center;">
<h1 style="margin:0;">🧪 Test-Mail</h1>
<p style="color:#a8b2d1;margin:6px 0 0;">AdGuard Shield Report</p>
</div>
<div style="padding:30px;">
<h2 style="color:#27ae60;">✅ E-Mail-Versand funktioniert!</h2>
<p>Diese Test-Mail bestätigt, dass der E-Mail-Versand für AdGuard Shield korrekt konfiguriert ist.</p>
<table style="width:100%;border-collapse:collapse;margin:20px 0;">
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Hostname</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${hostname}</td></tr>
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Zeitpunkt</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${test_date}</td></tr>
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Empfänger</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${REPORT_EMAIL_TO}</td></tr>
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Absender</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${REPORT_EMAIL_FROM}</td></tr>
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Mail-Befehl</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${REPORT_MAIL_CMD}</td></tr>
<tr><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;color:#6c757d;">Format</td><td style="padding:8px 14px;border-bottom:1px solid #f0f2f5;font-weight:600;">${REPORT_FORMAT}</td></tr>
<tr><td style="padding:8px 14px;color:#6c757d;">Intervall</td><td style="padding:8px 14px;font-weight:600;">${REPORT_INTERVAL}</td></tr>
</table>
<p style="color:#6c757d;font-size:13px;">Ab jetzt kannst du den automatischen Versand aktivieren mit:<br><code>sudo $(basename "$0") install</code></p>
</div>
<div style="background:#f8f9fc;padding:20px;font-size:12px;color:#6c757d;border-top:1px solid #e8ecf1;text-align:center;">
<div style="display:flex;justify-content:space-between;align-items:center;">
<span><a href="https://www.patrick-asmus.de" style="color:#0f3460;text-decoration:none;font-weight:600;">Patrick-Asmus.de</a>
<span style="margin:0 8px;color:#ced4da;">|</span>
<a href="https://www.cleveradmin.de" style="color:#0f3460;text-decoration:none;font-weight:600;">CleverAdmin.de</a></span>
<span><a href="https://git.techniverse.net/scriptos/adguard-shield.git" style="color:#0f3460;text-decoration:none;font-weight:600;">AdGuard Shield auf Gitea</a>
<span style="margin:0 8px;color:#ced4da;">|</span>
<a href="https://git.techniverse.net/scriptos/adguard-shield/src/branch/main/docs" style="color:#0f3460;text-decoration:none;font-weight:600;">docs</a></span>
</div>
<div style="margin-top:8px;font-size:11px;color:#adb5bd;text-align:center;">AdGuard Shield ${VERSION} &middot; ${hostname}</div>
${test_update_notice_html}
</div>
</div>
</body></html>
TESTHTML
)
    else
        test_body=$(cat <<TESTTXT
═══════════════════════════════════════════════════════════════
  🧪 AdGuard Shield – Test-Mail
═══════════════════════════════════════════════════════════════

  ✅ E-Mail-Versand funktioniert!

  Diese Test-Mail bestätigt, dass der E-Mail-Versand
  für AdGuard Shield korrekt konfiguriert ist.

  Hostname:     ${hostname}
  Zeitpunkt:    ${test_date}
  Empfänger:    ${REPORT_EMAIL_TO}
  Absender:     ${REPORT_EMAIL_FROM}
  Mail-Befehl:  ${REPORT_MAIL_CMD}
  Format:       ${REPORT_FORMAT}
  Intervall:    ${REPORT_INTERVAL}

  Ab jetzt kannst du den automatischen Versand aktivieren mit:
  sudo $(basename "$0") install

${test_update_notice_txt}
═══════════════════════════════════════════════════════════════
  AdGuard Shield ${VERSION} · ${hostname}

  Web:  https://www.patrick-asmus.de
  Blog: https://www.cleveradmin.de
  Repo: https://git.techniverse.net/scriptos/adguard-shield.git
  Docs: https://git.techniverse.net/scriptos/adguard-shield/src/branch/main/docs
═══════════════════════════════════════════════════════════════
TESTTXT
)
    fi

    local send_output
    send_output=$(
        {
            echo "From: ${REPORT_EMAIL_FROM}"
            echo "To: ${REPORT_EMAIL_TO}"
            echo "Subject: ${subject}"
            echo "MIME-Version: 1.0"
            echo "Content-Type: ${content_type}; charset=UTF-8"
            echo "Content-Transfer-Encoding: 8bit"
            echo "X-Mailer: AdGuard Shield Report Generator (Test)"
            echo ""
            echo "$test_body"
        } | "$REPORT_MAIL_CMD" -t 2>&1
    )
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo "  ✅ Test-E-Mail erfolgreich gesendet!"
        echo ""
        echo "  Prüfe dein Postfach: ${REPORT_EMAIL_TO}"
        echo "  (Evtl. auch im Spam-Ordner nachschauen)"
        log "INFO" "Test-E-Mail erfolgreich an ${REPORT_EMAIL_TO} gesendet"
    else
        echo "  ❌ Versand fehlgeschlagen (Exit-Code: $exit_code)"
        if [[ -n "$send_output" ]]; then
            echo ""
            echo "  Fehlermeldung:"
            echo "$send_output" | sed 's/^/     /'
        fi
        echo ""
        echo "  Troubleshooting:"
        echo "     1) ${REPORT_MAIL_CMD}-Konfiguration prüfen"
        echo "     2) Manuell testen: echo 'Test' | ${REPORT_MAIL_CMD} -t ${REPORT_EMAIL_TO}"
        echo "     3) Anleitung: https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/"
        log "ERROR" "Test-E-Mail fehlgeschlagen (Exit-Code: $exit_code): $send_output"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Hilfe ────────────────────────────────────────────────────────────────────
print_help() {
    echo "AdGuard Shield – Report Generator"
    echo ""
    echo "Nutzung: $(basename "$0") <Befehl>"
    echo ""
    echo "Befehle:"
    echo "  send       Report generieren und per E-Mail versenden"
    echo "  test       Test-E-Mail senden (prüft Konfiguration + Mailversand)"
    echo "  generate   Report als Datei generieren (Ausgabe auf stdout)"
    echo "  install    Cron-Job für automatischen Versand einrichten"
    echo "  remove     Cron-Job entfernen"
    echo "  status     Report-Konfiguration und Cron-Status anzeigen"
    echo "  --help     Diese Hilfe anzeigen"
    echo ""
    echo "Beispiele:"
    echo "  sudo $(basename "$0") send              # Report jetzt senden"
    echo "  sudo $(basename "$0") test              # Test-Mail senden"
    echo "  sudo $(basename "$0") generate > r.html # Report in Datei speichern"
    echo "  sudo $(basename "$0") install           # Automatischen Versand einrichten"
    echo "  sudo $(basename "$0") status            # Status anzeigen"
    echo ""
}

# ─── Kommandozeilen-Argumente ─────────────────────────────────────────────────
case "${1:---help}" in
    send)
        send_report_email
        ;;
    test)
        send_test_email
        ;;
    generate)
        generate_report "${2:-$REPORT_FORMAT}"
        ;;
    install)
        install_cron
        ;;
    remove)
        remove_cron
        ;;
    status)
        show_cron_status
        ;;
    --help|-h)
        print_help
        ;;
    *)
        echo "Unbekannter Befehl: $1"
        print_help
        exit 1
        ;;
esac
