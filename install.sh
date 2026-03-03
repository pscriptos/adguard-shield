#!/bin/bash
###############################################################################
# AdGuard Shield - Installer
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

VERSION="1.0.0"

set -euo pipefail

INSTALL_DIR="/opt/adguard-ratelimit"
SERVICE_FILE="/etc/systemd/system/adguard-ratelimit.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${BLUE}"
    echo " ▄▄▄      ▓█████▄   ▄████  █    ██  ▄▄▄       ██▀███  ▓█████▄      ██████  ██░ ██  ██▓▓█████  ██▓    ▓█████▄ "
    echo "▒████▄    ▒██▀ ██▌ ██▒ ▀█▒ ██  ▓██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌   ▒██    ▒ ▓██░ ██▒▓██▒▓█   ▀ ▓██▒    ▒██▀ ██▌"
    echo "▒██  ▀█▄  ░██   █▌▒██░▄▄▄░▓██  ▒██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌   ░ ▓██▄   ▒██▀▀██░▒██▒▒███   ▒██░    ░██   █▌"
    echo "░██▄▄▄▄██ ░▓█▄   ▌░▓█  ██▓▓▓█  ░██░░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌     ▒   ██▒░▓█ ░██ ░██░▒▓█  ▄ ▒██░    ░▓█▄   ▌"
    echo " ▓█   ▓██▒░▒████▓ ░▒▓███▀▒▒▒█████▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▓    ▒██████▒▒░▓█▒░██▓░██░░▒████▒░██████▒░▒████▓ "
    echo " ▒▒   ▓▒█░ ▒▒▓  ▒  ░▒   ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░░ ▒░ ░░ ▒░▓  ░ ▒▒▓  ▒ "
    echo "  ▒   ▒▒ ░ ░ ▒  ▒   ░   ░ ░░▒░ ░ ░   ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░ ░  ░░ ░ ▒  ░ ░ ▒  ▒ "
    echo "  ░   ▒    ░ ░  ░ ░ ░   ░  ░░░ ░ ░   ░   ▒     ░░   ░  ░ ░  ░    ░  ░  ░   ░  ░░ ░ ▒ ░   ░     ░ ░    ░ ░  ░ "
    echo "      ░  ░   ░          ░    ░           ░  ░   ░        ░             ░   ░  ░  ░ ░     ░  ░    ░  ░   ░    "
    echo "           ░                                           ░                                              ░      "
    echo -e "${NC}"
    echo -e "${GREEN}  Version: ${VERSION}${NC}"
    echo -e "${BLUE}  Autor:   Patrick Asmus${NC}"
    echo -e "${BLUE}  E-Mail:  support@techniverse.net${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Dieses Script muss als root ausgeführt werden!${NC}" >&2
        echo "Bitte mit 'sudo $0' ausführen."
        exit 1
    fi
}

check_dependencies() {
    echo -e "${YELLOW}Prüfe Abhängigkeiten...${NC}"
    local missing=()

    for cmd in curl jq iptables ip6tables; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ✅ $cmd"
        else
            echo -e "  ❌ $cmd"
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Installiere fehlende Pakete...${NC}"

        if command -v apt &>/dev/null; then
            apt update -qq
            apt install -y -qq curl jq iptables
        elif command -v dnf &>/dev/null; then
            dnf install -y curl jq iptables
        elif command -v yum &>/dev/null; then
            yum install -y curl jq iptables
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm curl jq iptables
        else
            echo -e "${RED}Konnte Paketmanager nicht erkennen. Bitte installiere manuell: ${missing[*]}${NC}"
            exit 1
        fi
    fi
    echo ""
}

install_files() {
    echo -e "${YELLOW}Installiere Dateien nach $INSTALL_DIR ...${NC}"

    mkdir -p "$INSTALL_DIR"
    mkdir -p /var/lib/adguard-ratelimit
    mkdir -p /var/log

    # Dateien kopieren
    cp "$SCRIPT_DIR/adguard-ratelimit.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/iptables-helper.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/unban-expired.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/external-blocklist-worker.sh" "$INSTALL_DIR/"

    # Konfigurationsdatei nur kopieren wenn nicht vorhanden (Update-Sicher)
    if [[ ! -f "$INSTALL_DIR/adguard-ratelimit.conf" ]]; then
        cp "$SCRIPT_DIR/adguard-ratelimit.conf" "$INSTALL_DIR/"
        echo -e "  ✅ Konfiguration kopiert (NEU)"
    else
        cp "$SCRIPT_DIR/adguard-ratelimit.conf" "$INSTALL_DIR/adguard-ratelimit.conf.new"
        echo -e "  ℹ️  Konfiguration existiert bereits - neue Version als .conf.new gespeichert"
    fi

    # Ausführbar machen
    chmod +x "$INSTALL_DIR/adguard-ratelimit.sh"
    chmod +x "$INSTALL_DIR/iptables-helper.sh"
    chmod +x "$INSTALL_DIR/unban-expired.sh"
    chmod +x "$INSTALL_DIR/external-blocklist-worker.sh"
    chmod 600 "$INSTALL_DIR/adguard-ratelimit.conf"

    echo -e "  ✅ Dateien installiert"
    echo ""
}

install_service() {
    echo -e "${YELLOW}Installiere systemd Service...${NC}"

    cp "$SCRIPT_DIR/adguard-ratelimit.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable adguard-ratelimit.service

    echo -e "  ✅ Service installiert und aktiviert"
    echo ""
}

configure() {
    echo -e "${YELLOW}Konfiguration:${NC}"
    echo ""

    local conf="$INSTALL_DIR/adguard-ratelimit.conf"

    # AdGuard URL
    read -rp "  AdGuard Home URL [http://127.0.0.1:3000]: " adguard_url
    adguard_url="${adguard_url:-http://127.0.0.1:3000}"
    sed -i "s|^ADGUARD_URL=.*|ADGUARD_URL=\"$adguard_url\"|" "$conf"

    # Benutzername
    read -rp "  AdGuard Home Benutzername [admin]: " adguard_user
    adguard_user="${adguard_user:-admin}"
    sed -i "s|^ADGUARD_USER=.*|ADGUARD_USER=\"$adguard_user\"|" "$conf"

    # Passwort
    read -rsp "  AdGuard Home Passwort: " adguard_pass
    echo ""
    if [[ -n "$adguard_pass" ]]; then
        # Einfache Quotes damit $-Zeichen im Passwort nicht expandiert werden
        sed -i "s|^ADGUARD_PASS=.*|ADGUARD_PASS='$adguard_pass'|" "$conf"
    fi

    # Rate Limit
    read -rp "  Max. Anfragen pro Domain/Client pro Minute [30]: " rate_limit
    rate_limit="${rate_limit:-30}"
    sed -i "s|^RATE_LIMIT_MAX_REQUESTS=.*|RATE_LIMIT_MAX_REQUESTS=$rate_limit|" "$conf"

    # Sperrdauer
    read -rp "  Sperrdauer in Sekunden [3600]: " ban_duration
    ban_duration="${ban_duration:-3600}"
    sed -i "s|^BAN_DURATION=.*|BAN_DURATION=$ban_duration|" "$conf"

    # Whitelist
    read -rp "  Whitelist IPs (kommagetrennt) [127.0.0.1,::1]: " whitelist
    whitelist="${whitelist:-127.0.0.1,::1}"
    sed -i "s|^WHITELIST=.*|WHITELIST=\"$whitelist\"|" "$conf"

    echo ""
    echo -e "  ✅ Konfiguration gespeichert"
    echo ""
}

test_connection() {
    echo -e "${YELLOW}Teste Verbindung zur AdGuard Home API...${NC}"

    source "$INSTALL_DIR/adguard-ratelimit.conf"

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${ADGUARD_USER}:${ADGUARD_PASS}" \
        --connect-timeout 5 \
        "${ADGUARD_URL}/control/querylog?limit=1" 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo -e "  ✅ Verbindung erfolgreich! (HTTP $response)"
    else
        echo -e "  ❌ Verbindung fehlgeschlagen (HTTP $response)"
        echo -e "  ${YELLOW}Bitte prüfe URL und Zugangsdaten in: $INSTALL_DIR/adguard-ratelimit.conf${NC}"
    fi
    echo ""
}

print_summary() {
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  AdGuard Shield - Installation abgeschlossen!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Installationspfad:  $INSTALL_DIR"
    echo "  Konfiguration:      $INSTALL_DIR/adguard-ratelimit.conf"
    echo "  Service:            adguard-ratelimit.service"
    echo "  Log-Datei:          /var/log/adguard-ratelimit.log"
    echo ""
    echo "  Nächste Schritte:"
    echo "  ─────────────────"
    echo "  1. Konfiguration prüfen:"
    echo "     sudo nano $INSTALL_DIR/adguard-ratelimit.conf"
    echo ""
    echo "  2. Erst im Dry-Run testen:"
    echo "     sudo $INSTALL_DIR/adguard-ratelimit.sh dry-run"
    echo ""
    echo "  3. Service starten:"
    echo "     sudo systemctl start adguard-ratelimit"
    echo ""
    echo "  4. Status prüfen:"
    echo "     sudo systemctl status adguard-ratelimit"
    echo "     sudo $INSTALL_DIR/adguard-ratelimit.sh status"
    echo ""
    echo "  5. Logs verfolgen:"
    echo "     sudo journalctl -u adguard-ratelimit -f"
    echo "     sudo tail -f /var/log/adguard-ratelimit.log"
    echo ""
    echo "  Weitere Befehle:"
    echo "     sudo $INSTALL_DIR/iptables-helper.sh status"
    echo "     sudo $INSTALL_DIR/adguard-ratelimit.sh flush"
    echo "     sudo $INSTALL_DIR/adguard-ratelimit.sh unban <IP>"
    echo ""
}

# ─── Deinstallation ─────────────────────────────────────────────────────────
uninstall() {
    echo -e "${YELLOW}Deinstalliere AdGuard Shield...${NC}"
    echo ""

    # Service stoppen und deaktivieren
    if systemctl is-active adguard-ratelimit &>/dev/null; then
        systemctl stop adguard-ratelimit
        echo "  ✅ Service gestoppt"
    fi
    if systemctl is-enabled adguard-ratelimit &>/dev/null; then
        systemctl disable adguard-ratelimit
        echo "  ✅ Service deaktiviert"
    fi
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo "  ✅ Service-Datei entfernt"

    # iptables Chain aufräumen
    if [[ -f "$INSTALL_DIR/iptables-helper.sh" ]]; then
        bash "$INSTALL_DIR/iptables-helper.sh" remove || true
    fi

    # Dateien entfernen
    read -rp "  Konfiguration und Logs behalten? [j/N]: " keep
    if [[ "${keep,,}" == "j" ]]; then
        rm -f "$INSTALL_DIR/adguard-ratelimit.sh"
        rm -f "$INSTALL_DIR/iptables-helper.sh"
        echo "  ✅ Scripts entfernt (Konfiguration behalten)"
    else
        rm -rf "$INSTALL_DIR"
        rm -rf /var/lib/adguard-ratelimit
        rm -f /var/log/adguard-ratelimit.log*
        echo "  ✅ Alles entfernt"
    fi

    echo ""
    echo -e "${GREEN}Deinstallation abgeschlossen.${NC}"
}

# ─── Hauptprogramm ──────────────────────────────────────────────────────────
case "${1:-install}" in
    install)
        print_header
        check_root
        check_dependencies
        install_files
        configure
        install_service
        test_connection
        print_summary
        ;;
    uninstall)
        print_header
        check_root
        uninstall
        ;;
    update)
        print_header
        check_root
        install_files
        systemctl daemon-reload
        echo -e "${GREEN}AdGuard Shield Update abgeschlossen. Service neustarten mit: sudo systemctl restart adguard-ratelimit${NC}"
        ;;
    *)
        echo "Nutzung: $0 {install|uninstall|update}"
        exit 1
        ;;
esac
