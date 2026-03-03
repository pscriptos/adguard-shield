#!/bin/bash
###############################################################################
# AdGuard Shield - iptables Helper
# Verwaltet die Firewall-Regeln für AdGuard Shield
# Kann auch standalone genutzt werden zur Verwaltung der Sperren
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/adguard-ratelimit.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "FEHLER: Konfigurationsdatei nicht gefunden: $CONFIG_FILE" >&2
    exit 1
fi
source "$CONFIG_FILE"

# ─── Chain erstellen ─────────────────────────────────────────────────────────
create_chain() {
    echo "Erstelle iptables Chain: $IPTABLES_CHAIN"
    
    # IPv4
    if ! iptables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        iptables -N "$IPTABLES_CHAIN"
        for port in $BLOCKED_PORTS; do
            iptables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            iptables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
        echo "  ✅ IPv4 Chain erstellt"
    else
        echo "  ℹ️  IPv4 Chain existiert bereits"
    fi

    # IPv6
    if ! ip6tables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        ip6tables -N "$IPTABLES_CHAIN"
        for port in $BLOCKED_PORTS; do
            ip6tables -I INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN"
            ip6tables -I INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN"
        done
        echo "  ✅ IPv6 Chain erstellt"
    else
        echo "  ℹ️  IPv6 Chain existiert bereits"
    fi
}

# ─── Chain entfernen ─────────────────────────────────────────────────────────
remove_chain() {
    echo "Entferne iptables Chain: $IPTABLES_CHAIN"
    
    # IPv4 - Referenzen entfernen, dann Chain löschen
    if iptables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        for port in $BLOCKED_PORTS; do
            iptables -D INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN" 2>/dev/null || true
            iptables -D INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN" 2>/dev/null || true
        done
        iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
        iptables -X "$IPTABLES_CHAIN" 2>/dev/null || true
        echo "  ✅ IPv4 Chain entfernt"
    else
        echo "  ℹ️  IPv4 Chain existiert nicht"
    fi

    # IPv6
    if ip6tables -n -L "$IPTABLES_CHAIN" &>/dev/null; then
        for port in $BLOCKED_PORTS; do
            ip6tables -D INPUT -p tcp --dport "$port" -j "$IPTABLES_CHAIN" 2>/dev/null || true
            ip6tables -D INPUT -p udp --dport "$port" -j "$IPTABLES_CHAIN" 2>/dev/null || true
        done
        ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null || true
        ip6tables -X "$IPTABLES_CHAIN" 2>/dev/null || true
        echo "  ✅ IPv6 Chain entfernt"
    else
        echo "  ℹ️  IPv6 Chain existiert nicht"
    fi
}

# ─── Chain leeren ────────────────────────────────────────────────────────────
flush_chain() {
    echo "Leere iptables Chain: $IPTABLES_CHAIN"
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null && echo "  ✅ IPv4 geleert" || echo "  ⚠️  IPv4 Chain nicht gefunden"
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null && echo "  ✅ IPv6 geleert" || echo "  ⚠️  IPv6 Chain nicht gefunden"
    
    # State-Dateien auch aufräumen
    rm -f "${STATE_DIR}"/*.ban 2>/dev/null || true
    echo "  ✅ State-Dateien bereinigt"
}

# ─── IP manuell sperren ─────────────────────────────────────────────────────
ban_ip() {
    local ip="$1"
    echo "Sperre IP: $ip"
    
    if [[ "$ip" == *:* ]]; then
        ip6tables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
        echo "  ✅ IPv6 Adresse gesperrt"
    else
        iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
        echo "  ✅ IPv4 Adresse gesperrt"
    fi
}

# ─── IP entsperren ──────────────────────────────────────────────────────────
unban_ip() {
    local ip="$1"
    echo "Entsperre IP: $ip"
    
    if [[ "$ip" == *:* ]]; then
        ip6tables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null \
            && echo "  ✅ IPv6 Adresse entsperrt" \
            || echo "  ⚠️  IPv6 Regel nicht gefunden"
    else
        iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null \
            && echo "  ✅ IPv4 Adresse entsperrt" \
            || echo "  ⚠️  IPv4 Regel nicht gefunden"
    fi
    
    # State-Datei entfernen
    rm -f "${STATE_DIR}/${ip//[:\/]/_}.ban" 2>/dev/null || true
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
show_rules() {
    echo ""
    echo "══════════════════════════════════════════════════════════════════"
    echo "  iptables Regeln für Chain: $IPTABLES_CHAIN"
    echo "══════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "  --- IPv4 ---"
    if iptables -n -L "$IPTABLES_CHAIN" --line-numbers &>/dev/null; then
        iptables -n -L "$IPTABLES_CHAIN" --line-numbers -v 2>/dev/null | sed 's/^/    /'
    else
        echo "    Chain existiert nicht"
    fi
    
    echo ""
    echo "  --- IPv6 ---"
    if ip6tables -n -L "$IPTABLES_CHAIN" --line-numbers &>/dev/null; then
        ip6tables -n -L "$IPTABLES_CHAIN" --line-numbers -v 2>/dev/null | sed 's/^/    /'
    else
        echo "    Chain existiert nicht"
    fi

    echo ""
    echo "  --- Aktive Sperren (State) ---"
    local count=0
    if [[ -d "$STATE_DIR" ]]; then
        for f in "${STATE_DIR}"/*.ban; do
            [[ -f "$f" ]] || continue
            count=$((count + 1))
            local ip domain ban_time ban_until
            ip=$(grep '^CLIENT_IP=' "$f" | cut -d= -f2)
            domain=$(grep '^DOMAIN=' "$f" | cut -d= -f2)
            ban_time=$(grep '^BAN_TIME=' "$f" | cut -d= -f2)
            ban_until=$(grep '^BAN_UNTIL=' "$f" | cut -d= -f2)
            printf "    %-20s %-30s seit %-20s bis %s\n" "$ip" "$domain" "$ban_time" "$ban_until"
        done
    fi
    
    if [[ $count -eq 0 ]]; then
        echo "    Keine aktiven Sperren"
    fi
    echo ""
}

# ─── Persistenz (iptables-save/restore kompatibel) ──────────────────────────
save_rules() {
    local save_file="${STATE_DIR}/iptables-rules.v4"
    local save_file6="${STATE_DIR}/iptables-rules.v6"
    
    iptables-save > "$save_file" 2>/dev/null && echo "  ✅ IPv4 Regeln gespeichert: $save_file"
    ip6tables-save > "$save_file6" 2>/dev/null && echo "  ✅ IPv6 Regeln gespeichert: $save_file6"
}

restore_rules() {
    local save_file="${STATE_DIR}/iptables-rules.v4"
    local save_file6="${STATE_DIR}/iptables-rules.v6"
    
    [[ -f "$save_file" ]] && iptables-restore < "$save_file" && echo "  ✅ IPv4 Regeln wiederhergestellt"
    [[ -f "$save_file6" ]] && ip6tables-restore < "$save_file6" && echo "  ✅ IPv6 Regeln wiederhergestellt"
}

# ─── Hauptprogramm ──────────────────────────────────────────────────────────
case "${1:-help}" in
    create)
        create_chain
        ;;
    remove)
        remove_chain
        ;;
    flush)
        flush_chain
        ;;
    ban)
        [[ -z "${2:-}" ]] && { echo "Nutzung: $0 ban <IP>" >&2; exit 1; }
        ban_ip "$2"
        ;;
    unban)
        [[ -z "${2:-}" ]] && { echo "Nutzung: $0 unban <IP>" >&2; exit 1; }
        unban_ip "$2"
        ;;
    status|show)
        show_rules
        ;;
    save)
        save_rules
        ;;
    restore)
        restore_rules
        ;;
    *)
        cat << USAGE
iptables Helper für AdGuard Rate-Limit

Nutzung: $0 {create|remove|flush|ban|unban|status|save|restore}

Befehle:
  create       Erstellt die iptables Chain
  remove       Entfernt die Chain und alle Regeln
  flush        Leert alle Regeln in der Chain
  ban <IP>     Sperrt eine IP-Adresse manuell
  unban <IP>   Entsperrt eine IP-Adresse
  status       Zeigt alle aktuellen Regeln
  save         Speichert die aktuellen Regeln
  restore      Stellt gespeicherte Regeln wieder her

Chain-Name: $IPTABLES_CHAIN
Gesperrte Ports: $BLOCKED_PORTS

USAGE
        ;;
esac
