#!/bin/bash
###############################################################################
# AdGuard Shield - Uninstaller
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
#
# Dieses Script befindet sich im Installationsverzeichnis und kann daher
# ohne die originalen Installationsdateien ausgeführt werden:
#   sudo bash /opt/adguard-shield/uninstall.sh
###############################################################################

# INSTALL_DIR ergibt sich aus dem Verzeichnis, in dem dieses Script liegt
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/adguard-shield.service"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
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
    echo -e "${GREEN}  Uninstaller${NC}"
    echo -e "${BLUE}  Autor:   Patrick Asmus${NC}"
    echo -e
    echo -e "${BLUE}  E-Mail:  support@techniverse.net${NC}"
    echo -e "${BLUE}  Web:     https://www.patrick-asmus.de${NC}"
    echo ""
    echo -e "${BLUE}───────────────────────────────────────────────────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${BLUE}  Repo:    https://git.techniverse.net/scriptos/adguard-shield${NC}"
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

do_uninstall() {
    check_root

    # Prüfen ob installiert
    if [[ ! -d "$INSTALL_DIR" ]]; then
        echo -e "${RED}AdGuard Shield ist nicht installiert (Verzeichnis nicht gefunden: $INSTALL_DIR)!${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Deinstalliere AdGuard Shield aus: ${BOLD}$INSTALL_DIR${NC}"
    echo ""

    # Sicherheitsabfrage
    read -rep "  Wirklich deinstallieren? [j/N]: " confirm
    if [[ "${confirm,,}" != "j" ]]; then
        echo -e "${GREEN}Deinstallation abgebrochen.${NC}"
        exit 0
    fi
    echo ""

    # Service stoppen und deaktivieren
    if systemctl is-active adguard-shield &>/dev/null; then
        systemctl stop adguard-shield
        echo "  ✅ Service gestoppt"
    fi
    if systemctl is-enabled adguard-shield &>/dev/null; then
        systemctl disable adguard-shield
        echo "  ✅ Service deaktiviert"
    fi
    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        echo "  ✅ Service-Datei entfernt"
    fi

    # iptables Chain aufräumen
    if [[ -f "$INSTALL_DIR/iptables-helper.sh" ]]; then
        bash "$INSTALL_DIR/iptables-helper.sh" remove || true
    fi

    # Dateien entfernen
    read -rep "  Konfiguration und Logs behalten? [j/N]: " keep
    if [[ "${keep,,}" == "j" ]]; then
        rm -f "$INSTALL_DIR/adguard-shield.sh"
        rm -f "$INSTALL_DIR/iptables-helper.sh"
        rm -f "$INSTALL_DIR/unban-expired.sh"
        rm -f "$INSTALL_DIR/external-blocklist-worker.sh"
        rm -f "$INSTALL_DIR/external-whitelist-worker.sh"
        rm -f "$INSTALL_DIR/report-generator.sh"
        rm -f "$INSTALL_DIR/uninstall.sh"
        rm -rf "$INSTALL_DIR/templates"
        echo "  ✅ Scripts entfernt (Konfiguration und Logs behalten)"
        echo ""
        echo -e "${YELLOW}  Konfiguration verbleibt in: $INSTALL_DIR/adguard-shield.conf${NC}"
        echo -e "${YELLOW}  Logs verbleiben in: /var/log/adguard-shield*.log${NC}"
    else
        rm -rf "$INSTALL_DIR"
        rm -rf /var/lib/adguard-shield
        rm -f /var/log/adguard-shield.log*
        rm -f /var/log/adguard-shield-bans.log
        echo "  ✅ Alles entfernt"
    fi

    echo ""
    echo -e "${GREEN}Deinstallation abgeschlossen.${NC}"
}

print_header
do_uninstall
