#!/bin/bash
###############################################################################
# AdGuard Shield - Installer / Updater / Uninstaller
# Autor:   Patrick Asmus
# E-Mail:  support@techniverse.net
# Lizenz:  MIT
###############################################################################

VERSION="v1.0.0"

set -euo pipefail

INSTALL_DIR="/opt/adguard-shield"
SERVICE_FILE="/etc/systemd/system/adguard-shield.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    echo -e "${GREEN}  Version: ${VERSION}${NC}"
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

# ─── Hilfe-Menü ──────────────────────────────────────────────────────────────
print_help() {
    echo -e "${BOLD}Nutzung:${NC} sudo bash $0 [BEFEHL]"
    echo ""
    echo -e "${BOLD}Verfügbare Befehle:${NC}"
    echo ""
    echo -e "  ${GREEN}install${NC}      Vollständige Neuinstallation durchführen"
    echo -e "               Installiert alle Dateien, fragt die Konfiguration ab,"
    echo -e "               richtet den systemd Service ein und aktiviert Autostart."
    echo ""
    echo -e "  ${GREEN}update${NC}       Update auf die neueste Version"
    echo -e "               Aktualisiert alle Scripts, führt eine automatische"
    echo -e "               Konfigurations-Migration durch (neue Parameter werden"
    echo -e "               hinzugefügt, bestehende Einstellungen bleiben erhalten),"
    echo -e "               migriert bestehende Daten nach SQLite (einmalig)"
    echo -e "               und startet den Service automatisch neu."
    echo ""
    echo -e "  ${GREEN}uninstall${NC}    Vollständige Deinstallation"
    echo -e "               Stoppt den Service, entfernt iptables-Regeln und"
    echo -e "               löscht alle Dateien (optional Konfiguration behalten)."
    echo -e "               Delegiert automatisch an den im Installationsverzeichnis"
    echo -e "               liegenden Uninstaller — kein Behalten der Installationsdateien nötig."
    echo -e "               Direkt ausführbar: ${CYAN}sudo bash $INSTALL_DIR/uninstall.sh${NC}"
    echo ""
    echo -e "  ${GREEN}status${NC}       Installationsstatus anzeigen"
    echo -e "               Zeigt ob AdGuard Shield installiert ist, welche Version"
    echo -e "               läuft und ob der Service aktiv ist."
    echo ""
    echo -e "  ${GREEN}--help, -h${NC}   Diese Hilfe anzeigen"
    echo ""
    echo -e "${BOLD}Beispiele:${NC}"
    echo -e "  ${CYAN}sudo bash install.sh install${NC}                           # Neuinstallation"
    echo -e "  ${CYAN}sudo bash install.sh update${NC}                            # Update durchführen"
    echo -e "  ${CYAN}sudo bash install.sh uninstall${NC}                         # Deinstallation"
    echo -e "  ${CYAN}sudo bash install.sh status${NC}                           # Status prüfen"
    echo ""
    echo -e "${BOLD}Service-Befehle:${NC}"
    echo -e "  ${CYAN}sudo systemctl start adguard-shield${NC}                    # Service starten"
    echo -e "  ${CYAN}sudo systemctl stop adguard-shield${NC}                     # Service stoppen"
    echo -e "  ${CYAN}sudo systemctl restart adguard-shield${NC}                  # Service neustarten"
    echo -e "  ${CYAN}sudo systemctl status adguard-shield${NC}                   # Service-Status"
    echo -e "  ${CYAN}sudo journalctl -u adguard-shield -f${NC}                   # Logs live verfolgen"
    echo ""
    echo -e "${BOLD}Monitor-Befehle (nach Installation):${NC}"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh start${NC}       # Monitor im Vordergrund starten"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh stop${NC}        # Monitor stoppen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh status${NC}      # Status & aktive Sperren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh history${NC}     # Ban-History anzeigen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh unban IP${NC}    # Einzelne IP entsperren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh flush${NC}       # Alle Sperren aufheben"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh test${NC}        # API-Verbindung testen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh dry-run${NC}     # Testmodus (nur loggen)"
    echo ""
    echo -e "${BOLD}Externe Whitelist-Befehle:${NC}"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh whitelist-status${NC}   # Status der externen Whitelisten"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh whitelist-sync${NC}     # Einmalige Synchronisation"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh whitelist-flush${NC}    # Aufgelöste IPs entfernen"
    echo ""
    echo -e "${BOLD}iptables-Befehle:${NC}"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh status${NC}     # Firewall-Regeln anzeigen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh ban IP${NC}     # IP manuell sperren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh unban IP${NC}   # IP entsperren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh flush${NC}      # Alle Regeln leeren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh create${NC}     # Chain erstellen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh remove${NC}     # Chain komplett entfernen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh save${NC}       # Regeln speichern"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/iptables-helper.sh restore${NC}    # Regeln wiederherstellen"
    echo ""
    echo -e "${BOLD}Report-Befehle:${NC}"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/report-generator.sh status${NC}    # Report-Konfiguration anzeigen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/report-generator.sh send${NC}      # Report sofort senden"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/report-generator.sh generate${NC}  # Report als Datei generieren"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/report-generator.sh install${NC}   # Cron-Job einrichten"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/report-generator.sh remove${NC}    # Cron-Job entfernen"
    echo ""
    echo -e "${BOLD}Watchdog-Befehle:${NC}"
    echo -e "  ${CYAN}sudo systemctl status adguard-shield-watchdog.timer${NC}    # Watchdog-Status"
    echo -e "  ${CYAN}sudo systemctl list-timers adguard-shield-watchdog.timer${NC} # Nächste Ausführung"
    echo -e "  ${CYAN}sudo systemctl enable adguard-shield-watchdog.timer${NC}    # Watchdog aktivieren"
    echo -e "  ${CYAN}sudo systemctl disable adguard-shield-watchdog.timer${NC}   # Watchdog deaktivieren"
    echo -e "  ${CYAN}sudo journalctl -u adguard-shield-watchdog.service${NC}     # Watchdog-Logs"
    echo ""
    echo -e "${BOLD}GeoIP-Befehle:${NC}"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh geoip-status${NC}    # GeoIP-Status anzeigen"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh geoip-sync${NC}      # Einmalige GeoIP-Prüfung"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh geoip-flush${NC}     # Alle GeoIP-Sperren aufheben"
    echo -e "  ${CYAN}sudo /opt/adguard-shield/adguard-shield.sh geoip-lookup IP${NC}  # GeoIP-Lookup einer IP"
    echo ""
    echo -e "${BOLD}Voraussetzungen:${NC}"
    echo "  - Linux Server (Debian/Ubuntu empfohlen)"
    echo "  - Root-Zugriff (sudo)"
    echo "  - AdGuard Home installiert und erreichbar"
    echo "  - Pakete: curl, jq, iptables, gawk, sqlite3 (werden bei Installation automatisch installiert)"
    echo "  - GeoIP (optional): geoip-bin + geoip-database oder MaxMind GeoLite2 DB"
    echo ""
    echo -e "${BOLD}Dokumentation:${NC}"
    echo "  https://git.techniverse.net/scriptos/adguard-shield"
    echo ""
}

# ─── Interaktives Menü ───────────────────────────────────────────────────────
show_menu() {
    echo -e "${BOLD}Was möchtest du tun?${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC} Installation    — AdGuard Shield neu installieren"
    echo -e "  ${CYAN}2)${NC} Update          — Auf die neueste Version aktualisieren"
    echo -e "  ${CYAN}3)${NC} Deinstallation  — AdGuard Shield vollständig entfernen"
    echo -e "  ${CYAN}4)${NC} Status          — Installationsstatus anzeigen"
    echo -e "  ${CYAN}5)${NC} Hilfe           — Hilfe & Befehlsübersicht anzeigen"
    echo -e "  ${CYAN}0)${NC} Beenden"
    echo ""
    read -rep "  Auswahl [0-5]: " choice
    echo ""

    case "$choice" in
        1) do_install ;;
        2) do_update ;;
        3) do_uninstall ;;
        4) do_status ;;
        5) print_help ;;
        0) echo -e "${GREEN}Auf Wiedersehen!${NC}"; exit 0 ;;
        *) echo -e "${RED}Ungültige Auswahl.${NC}"; exit 1 ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Dieses Script muss als root ausgeführt werden!${NC}" >&2
        echo "Bitte mit 'sudo $0' ausführen."
        exit 1
    fi
}

# ─── Abhängigkeiten prüfen und installieren ──────────────────────────────────
check_dependencies() {
    echo -e "${YELLOW}Prüfe Abhängigkeiten...${NC}"
    local missing_cmds=()
    local missing_pkgs=()

    # Befehl → Paketname Zuordnung
    declare -A cmd_to_pkg=(
        [curl]="curl"
        [jq]="jq"
        [iptables]="iptables"
        [ip6tables]="iptables"
        [gawk]="gawk"
        [systemctl]="systemd"
        [sqlite3]="sqlite3"
    )

    for cmd in curl jq iptables ip6tables gawk systemctl sqlite3; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ✅ $cmd"
        else
            echo -e "  ❌ $cmd"
            missing_cmds+=("$cmd")
            local pkg="${cmd_to_pkg[$cmd]}"
            # Duplikate vermeiden
            if [[ ! " ${missing_pkgs[*]:-} " =~ " ${pkg} " ]]; then
                missing_pkgs+=("$pkg")
            fi
        fi
    done

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Installiere fehlende Pakete: ${missing_pkgs[*]}${NC}"

        if command -v apt &>/dev/null; then
            apt update -qq
            apt install -y -qq "${missing_pkgs[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${missing_pkgs[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing_pkgs[@]}"
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm "${missing_pkgs[@]}"
        else
            echo -e "${RED}Konnte Paketmanager nicht erkennen. Bitte installiere manuell: ${missing_pkgs[*]}${NC}"
            exit 1
        fi

        echo ""
        echo -e "${YELLOW}Prüfe erneut...${NC}"
        for cmd in "${missing_cmds[@]}"; do
            if command -v "$cmd" &>/dev/null; then
                echo -e "  ✅ $cmd (installiert)"
            else
                echo -e "  ❌ $cmd (Installation fehlgeschlagen!)"
                echo -e "${RED}FEHLER: $cmd konnte nicht installiert werden. Bitte manuell nachinstallieren.${NC}"
                exit 1
            fi
        done
    fi

    echo -e "  ${GREEN}Alle Abhängigkeiten erfüllt.${NC}"
    echo ""
}

install_files() {
    echo -e "${YELLOW}Installiere Dateien nach $INSTALL_DIR ...${NC}"

    mkdir -p "$INSTALL_DIR"
    mkdir -p /var/lib/adguard-shield
    mkdir -p /var/log

    # Scripts kopieren
    cp "$SCRIPT_DIR/adguard-shield.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/iptables-helper.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/unban-expired.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/external-blocklist-worker.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/external-whitelist-worker.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/report-generator.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/adguard-shield-watchdog.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/geoip-worker.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/offense-cleanup-worker.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/db.sh" "$INSTALL_DIR/"

    # Templates kopieren
    mkdir -p "$INSTALL_DIR/templates"
    cp "$SCRIPT_DIR/templates/report.html" "$INSTALL_DIR/templates/"
    cp "$SCRIPT_DIR/templates/report.txt" "$INSTALL_DIR/templates/"

    # Ausführbar machen
    chmod +x "$INSTALL_DIR/adguard-shield.sh"
    chmod +x "$INSTALL_DIR/iptables-helper.sh"
    chmod +x "$INSTALL_DIR/unban-expired.sh"
    chmod +x "$INSTALL_DIR/external-blocklist-worker.sh"
    chmod +x "$INSTALL_DIR/external-whitelist-worker.sh"
    chmod +x "$INSTALL_DIR/report-generator.sh"
    chmod +x "$INSTALL_DIR/adguard-shield-watchdog.sh"
    chmod +x "$INSTALL_DIR/uninstall.sh"
    chmod +x "$INSTALL_DIR/geoip-worker.sh"
    chmod +x "$INSTALL_DIR/offense-cleanup-worker.sh"
    chmod +x "$INSTALL_DIR/db.sh"

    echo -e "  ✅ Dateien installiert"
    echo ""
}

# ─── Konfigurations-Migration ────────────────────────────────────────────────
# Vergleicht die bestehende Konfiguration mit der neuen Version.
# - Bestehende Einstellungen des Benutzers bleiben IMMER erhalten
# - Neue Parameter (die in der alten Konfig fehlen) werden automatisch ergänzt
# - Die alte Konfiguration wird als .conf.old gesichert
migrate_config() {
    local existing_conf="$INSTALL_DIR/adguard-shield.conf"
    local new_conf="$SCRIPT_DIR/adguard-shield.conf"
    local backup_conf="$INSTALL_DIR/adguard-shield.conf.old"

    if [[ ! -f "$existing_conf" ]]; then
        # Keine bestehende Konfig → einfach kopieren
        cp "$new_conf" "$existing_conf"
        chmod 600 "$existing_conf"
        echo -e "  ✅ Konfiguration kopiert (Neuinstallation)"
        return 0
    fi

    echo -e "${YELLOW}Führe Konfigurations-Migration durch...${NC}"

    # Backup der aktuellen Konfiguration erstellen
    cp "$existing_conf" "$backup_conf"
    echo -e "  📦 Backup erstellt: adguard-shield.conf.old"

    # Alle Schlüssel aus der bestehenden Konfig extrahieren (nur KEY=... Zeilen)
    local existing_keys=()
    while IFS= read -r line; do
        # Zeilen mit KEY=VALUE extrahieren (keine Kommentare, keine leeren Zeilen)
        if [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]]; then
            local key="${line%%=*}"
            existing_keys+=("$key")
        fi
    done < "$existing_conf"

    # Neue Schlüssel finden die in der bestehenden Konfig fehlen
    local new_keys_added=0
    local current_comment_block=""

    while IFS= read -r line; do
        # Kommentarblock sammeln (für Kontext bei neuen Keys)
        if [[ "$line" =~ ^#.* ]] || [[ -z "$line" ]]; then
            current_comment_block+="$line"$'\n'
            continue
        fi

        # KEY=VALUE Zeile prüfen
        if [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]]; then
            local key="${line%%=*}"
            local found=false
            for existing_key in "${existing_keys[@]}"; do
                if [[ "$key" == "$existing_key" ]]; then
                    found=true
                    break
                fi
            done

            if [[ "$found" == "false" ]]; then
                # Neuer Parameter gefunden → mit Kommentarblock an bestehende Konfig anhängen
                if [[ $new_keys_added -eq 0 ]]; then
                    echo "" >> "$existing_conf"
                    echo "# ─── Neue Parameter (automatisch bei Update hinzugefügt) ───" >> "$existing_conf"
                fi
                echo -n "$current_comment_block" >> "$existing_conf"
                echo "$line" >> "$existing_conf"
                echo -e "  ➕ Neuer Parameter hinzugefügt: ${GREEN}$key${NC}"
                new_keys_added=$((new_keys_added + 1))
            fi
        fi

        current_comment_block=""
    done < "$new_conf"

    chmod 600 "$existing_conf"

    if [[ $new_keys_added -eq 0 ]]; then
        echo -e "  ✅ Konfiguration ist aktuell — keine neuen Parameter"
    else
        echo -e "  ✅ ${new_keys_added} neue Parameter zur Konfiguration hinzugefügt"
        echo -e "  ${YELLOW}ℹ️  Backup der alten Konfig: $backup_conf${NC}"
        echo -e "  ${YELLOW}ℹ️  Bitte prüfe die neuen Parameter in: $existing_conf${NC}"
    fi
    echo ""
}

install_service() {
    echo -e "${YELLOW}Installiere systemd Service...${NC}"

    cp "$SCRIPT_DIR/adguard-shield.service" "$SERVICE_FILE"
    cp "$SCRIPT_DIR/adguard-shield-watchdog.service" /etc/systemd/system/adguard-shield-watchdog.service
    cp "$SCRIPT_DIR/adguard-shield-watchdog.timer" /etc/systemd/system/adguard-shield-watchdog.timer
    systemctl daemon-reload

    echo -e "  ✅ Service-Dateien installiert (inkl. Watchdog)"
    echo ""

    # Interaktiv: Autostart beim Booten?
    read -rep "  Soll AdGuard Shield beim Booten automatisch starten? [J/n]: " autostart
    if [[ "${autostart,,}" != "n" ]]; then
        systemctl enable adguard-shield.service
        systemctl enable adguard-shield-watchdog.timer
        echo -e "  ✅ Autostart aktiviert (inkl. Watchdog-Timer)"
    else
        systemctl disable adguard-shield.service 2>/dev/null || true
        systemctl disable adguard-shield-watchdog.timer 2>/dev/null || true
        echo -e "  ℹ️  Autostart nicht aktiviert"
        echo -e "  ${YELLOW}Später aktivieren mit: sudo systemctl enable adguard-shield${NC}"
    fi
    echo ""
}

configure() {
    echo -e "${YELLOW}Konfiguration:${NC}"
    echo ""

    local conf="$INSTALL_DIR/adguard-shield.conf"

    # AdGuard URL
    read -rep "  AdGuard Home URL [http://127.0.0.1:3000]: " adguard_url
    adguard_url="${adguard_url:-http://127.0.0.1:3000}"
    sed -i "s|^ADGUARD_URL=.*|ADGUARD_URL=\"$adguard_url\"|" "$conf"

    # Benutzername
    read -rep "  AdGuard Home Benutzername [admin]: " adguard_user
    adguard_user="${adguard_user:-admin}"
    sed -i "s|^ADGUARD_USER=.*|ADGUARD_USER=\"$adguard_user\"|" "$conf"

    # Passwort
    read -resp "  AdGuard Home Passwort: " adguard_pass
    echo ""
    if [[ -n "$adguard_pass" ]]; then
        # Einfache Quotes damit $-Zeichen im Passwort nicht expandiert werden
        sed -i "s|^ADGUARD_PASS=.*|ADGUARD_PASS='$adguard_pass'|" "$conf"
    fi

    # Rate Limit
    read -rep "  Max. Anfragen pro Domain/Client pro Minute [30]: " rate_limit
    rate_limit="${rate_limit:-30}"
    sed -i "s|^RATE_LIMIT_MAX_REQUESTS=.*|RATE_LIMIT_MAX_REQUESTS=$rate_limit|" "$conf"

    # Sperrdauer
    read -rep "  Sperrdauer in Sekunden [3600]: " ban_duration
    ban_duration="${ban_duration:-3600}"
    sed -i "s|^BAN_DURATION=.*|BAN_DURATION=$ban_duration|" "$conf"

    # Whitelist
    read -rep "  Whitelist IPs (kommagetrennt) [127.0.0.1,::1]: " whitelist
    whitelist="${whitelist:-127.0.0.1,::1}"
    sed -i "s|^WHITELIST=.*|WHITELIST=\"$whitelist\"|" "$conf"

    echo ""
    echo -e "  ✅ Konfiguration gespeichert"
    echo ""
}

test_connection() {
    echo -e "${YELLOW}Teste Verbindung zur AdGuard Home API...${NC}"

    source "$INSTALL_DIR/adguard-shield.conf"

    # ── Schritt 1: Base-URL Erreichbarkeit prüfen ────────────────────────
    echo -e "  ${CYAN}1)${NC} Prüfe Erreichbarkeit von ${BOLD}${ADGUARD_URL}${NC} ..."

    local base_http_code
    local base_curl_exit
    base_http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 --max-time 10 \
        -k "${ADGUARD_URL}" 2>/dev/null) || base_curl_exit=$?
    base_curl_exit=${base_curl_exit:-0}

    if [[ "$base_curl_exit" -ne 0 ]]; then
        # curl konnte keine Verbindung aufbauen
        echo -e "  ❌ Base-URL nicht erreichbar! (curl Exit-Code: $base_curl_exit)"
        case "$base_curl_exit" in
            6)  echo -e "     ${YELLOW}→ DNS-Auflösung fehlgeschlagen. Hostname prüfen!${NC}" ;;
            7)  echo -e "     ${YELLOW}→ Verbindung abgelehnt. Läuft AdGuard Home? Port korrekt?${NC}" ;;
            28) echo -e "     ${YELLOW}→ Timeout. Host nicht erreichbar oder Firewall blockiert.${NC}" ;;
            35|51|60) echo -e "     ${YELLOW}→ SSL/TLS-Fehler. Zertifikat oder HTTPS-Konfiguration prüfen.${NC}" ;;
            *)  echo -e "     ${YELLOW}→ Unbekannter Fehler. Manuell testen: curl -v ${ADGUARD_URL}${NC}" ;;
        esac
        echo ""
        echo -e "  ${YELLOW}Troubleshooting:${NC}"
        echo -e "     curl -ikv ${ADGUARD_URL}"
        echo ""
        return 1
    fi

    if [[ "$base_http_code" == "000" ]]; then
        echo -e "  ❌ Base-URL nicht erreichbar (keine HTTP-Antwort)"
        echo -e "     ${YELLOW}→ Manuell testen: curl -ikv ${ADGUARD_URL}${NC}"
        echo ""
        return 1
    fi

    echo -e "  ✅ Base-URL erreichbar (HTTP $base_http_code)"

    # ── Schritt 2: API-Endpunkt mit Authentifizierung testen ─────────────
    echo -e "  ${CYAN}2)${NC} Teste API-Authentifizierung ..."

    local api_response
    api_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${ADGUARD_USER}:${ADGUARD_PASS}" \
        --connect-timeout 5 --max-time 10 \
        -k "${ADGUARD_URL}/control/querylog?limit=1" 2>/dev/null)

    if [[ "$api_response" == "200" ]]; then
        echo -e "  ✅ API-Authentifizierung erfolgreich! (HTTP $api_response)"
    elif [[ "$api_response" == "401" || "$api_response" == "403" ]]; then
        echo -e "  ❌ Authentifizierung fehlgeschlagen (HTTP $api_response)"
        echo -e "     ${YELLOW}→ Benutzername oder Passwort falsch!${NC}"
        echo -e "     ${YELLOW}→ Prüfe ADGUARD_USER und ADGUARD_PASS in: $INSTALL_DIR/adguard-shield.conf${NC}"
    else
        echo -e "  ❌ API-Verbindung fehlgeschlagen (HTTP $api_response)"
        echo -e "     ${YELLOW}→ Bitte prüfe URL und Zugangsdaten in: $INSTALL_DIR/adguard-shield.conf${NC}"
    fi
    echo ""
}

print_summary() {
    # Service-Status dynamisch ermitteln
    local svc_status="gestoppt"
    local autostart_status="deaktiviert"
    if systemctl is-active adguard-shield &>/dev/null 2>&1; then
        svc_status="läuft ✅"
    fi
    if systemctl is-enabled adguard-shield &>/dev/null 2>&1; then
        autostart_status="aktiviert ✅"
    fi

    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  AdGuard Shield - Installation abgeschlossen!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Installationspfad:  $INSTALL_DIR"
    echo "  Konfiguration:      $INSTALL_DIR/adguard-shield.conf"
    echo "  Service:            adguard-shield.service ($svc_status)"
    echo "  Autostart:          $autostart_status"

    # Watchdog-Status
    local watchdog_status="deaktiviert"
    if systemctl is-active adguard-shield-watchdog.timer &>/dev/null 2>&1; then
        watchdog_status="aktiv ✅"
    elif systemctl is-enabled adguard-shield-watchdog.timer &>/dev/null 2>&1; then
        watchdog_status="aktiviert (Timer nicht gestartet)"
    fi
    echo "  Watchdog:           $watchdog_status"
    echo "  Log-Datei:          /var/log/adguard-shield.log"
    echo ""
    echo "  Nützliche Befehle:"
    echo "  ──────────────────"
    echo "  Konfiguration bearbeiten:"
    echo "     sudo nano $INSTALL_DIR/adguard-shield.conf"
    echo ""
    echo "  Dry-Run testen (nur loggen, nichts sperren):"
    echo "     sudo $INSTALL_DIR/adguard-shield.sh dry-run"
    echo ""
    echo "  Service steuern:"
    echo "     sudo systemctl start|stop|restart adguard-shield"
    echo "     sudo systemctl status adguard-shield"
    echo ""
    echo "  Logs verfolgen:"
    echo "     sudo journalctl -u adguard-shield -f"
    echo "     sudo tail -f /var/log/adguard-shield.log"
    echo ""
    echo "  Weitere Befehle:"
    echo "     sudo $INSTALL_DIR/iptables-helper.sh status"
    echo "     sudo $INSTALL_DIR/adguard-shield.sh flush"
    echo "     sudo $INSTALL_DIR/adguard-shield.sh unban <IP>"
    echo ""
    echo "  E-Mail Report:"
    echo "     sudo $INSTALL_DIR/report-generator.sh status"
    echo "     sudo $INSTALL_DIR/report-generator.sh install"
    echo "     sudo $INSTALL_DIR/report-generator.sh send"
    echo ""
    echo "  Hilfe anzeigen:"
    echo "     sudo bash install.sh --help"
    echo ""
    echo "  Deinstallieren (auch ohne Installationsdateien):"
    echo "     sudo bash $INSTALL_DIR/uninstall.sh"
    echo ""
}

# ─── Status anzeigen ─────────────────────────────────────────────────────────
do_status() {
    check_root

    echo -e "${YELLOW}Installationsstatus:${NC}"
    echo ""

    # Installiert?
    if [[ -d "$INSTALL_DIR" ]]; then
        echo -e "  ✅ AdGuard Shield ist installiert in: $INSTALL_DIR"

        # Version aus installiertem Script lesen
        if [[ -f "$INSTALL_DIR/adguard-shield.sh" ]]; then
            local installed_version
            installed_version=$(grep -m1 '^VERSION=' "$INSTALL_DIR/adguard-shield.sh" 2>/dev/null | cut -d'"' -f2)
            echo -e "  📌 Installierte Version: ${GREEN}${installed_version:-unbekannt}${NC}"
        fi
    else
        echo -e "  ❌ AdGuard Shield ist NICHT installiert"
        echo ""
        return
    fi

    # Service-Status
    if systemctl is-enabled adguard-shield &>/dev/null 2>&1; then
        echo -e "  ✅ Autostart: aktiviert"
    else
        echo -e "  ❌ Autostart: deaktiviert"
    fi

    if systemctl is-active adguard-shield &>/dev/null 2>&1; then
        echo -e "  ✅ Service: läuft"
    else
        echo -e "  ❌ Service: gestoppt"
    fi

    # Konfig vorhanden?
    if [[ -f "$INSTALL_DIR/adguard-shield.conf" ]]; then
        echo -e "  ✅ Konfiguration: vorhanden"
    else
        echo -e "  ❌ Konfiguration: fehlt!"
    fi

    # Watchdog-Status
    if systemctl is-active adguard-shield-watchdog.timer &>/dev/null 2>&1; then
        echo -e "  ✅ Watchdog-Timer: aktiv"
    elif systemctl is-enabled adguard-shield-watchdog.timer &>/dev/null 2>&1; then
        echo -e "  ⚠️  Watchdog-Timer: aktiviert aber nicht gestartet"
    else
        echo -e "  ❌ Watchdog-Timer: nicht installiert/deaktiviert"
    fi

    echo ""
}

# ─── Installation ────────────────────────────────────────────────────────────
do_install() {
    check_root

    # Prüfen ob bereits installiert
    if [[ -d "$INSTALL_DIR" ]] && [[ -f "$INSTALL_DIR/adguard-shield.sh" ]]; then
        echo -e "${YELLOW}AdGuard Shield ist bereits installiert!${NC}"
        echo ""
        read -rep "  Möchtest du stattdessen ein Update durchführen? [j/N]: " do_upd
        if [[ "${do_upd,,}" == "j" ]]; then
            do_update
            return
        else
            echo -e "${RED}Installation abgebrochen.${NC}"
            exit 0
        fi
    fi

    check_dependencies
    install_files

    # Bei Neuinstallation Konfig kopieren
    cp "$SCRIPT_DIR/adguard-shield.conf" "$INSTALL_DIR/"
    chmod 600 "$INSTALL_DIR/adguard-shield.conf"
    echo -e "  ✅ Konfiguration kopiert"
    echo ""

    configure
    install_service
    test_connection

    # Interaktiv: Service jetzt starten?
    echo -e "${YELLOW}Service starten:${NC}"
    read -rep "  Soll der AdGuard Shield Service jetzt gestartet werden? [J/n]: " start_now
    if [[ "${start_now,,}" != "n" ]]; then
        systemctl start adguard-shield
        systemctl start adguard-shield-watchdog.timer 2>/dev/null || true
        echo -e "  ✅ Service gestartet (inkl. Watchdog-Timer)"
    else
        echo -e "  ℹ️  Service nicht gestartet"
        echo -e "  ${YELLOW}Später starten mit: sudo systemctl start adguard-shield${NC}"
    fi
    echo ""

    print_summary
}

# ─── SQLite-Datenbank-Migration ──────────────────────────────────────────────
# Migriert bestehende Flat-File-Daten (*.ban, *.offenses, History-Log) nach SQLite.
# Läuft synchron im Vordergrund mit sichtbarer Fortschrittsanzeige.
migrate_database() {
    echo -e "${YELLOW}Prüfe Datenbank-Migration...${NC}"

    # Konfiguration laden für STATE_DIR und BAN_HISTORY_FILE
    local conf="$INSTALL_DIR/adguard-shield.conf"
    if [[ ! -f "$conf" ]]; then
        echo -e "  ${RED}Konfiguration nicht gefunden — Migration übersprungen${NC}"
        echo ""
        return 0
    fi

    # Nur die benötigten Variablen aus der Konfig laden
    STATE_DIR=$(grep '^STATE_DIR=' "$conf" | cut -d= -f2 | tr -d '"')
    STATE_DIR="${STATE_DIR:-/var/lib/adguard-shield}"
    BAN_HISTORY_FILE=$(grep '^BAN_HISTORY_FILE=' "$conf" | cut -d= -f2 | tr -d '"')
    BAN_HISTORY_FILE="${BAN_HISTORY_FILE:-/var/log/adguard-shield-bans.log}"
    export STATE_DIR BAN_HISTORY_FILE

    # db.sh aus dem Installationsverzeichnis laden
    source "$INSTALL_DIR/db.sh"

    # Datenbank initialisieren (Schema anlegen falls nötig)
    db_init

    # Prüfen ob Migration bereits durchgeführt wurde
    if [[ -f "$_DB_MIGRATION_MARKER" ]]; then
        echo -e "  ✅ Datenbank ist aktuell — Migration bereits abgeschlossen"
        echo ""
        return 0
    fi

    # Prüfen ob überhaupt Flat-Files vorhanden sind
    local has_files=false
    for f in "${STATE_DIR}"/*.ban "${STATE_DIR}"/ext_*.ban "${STATE_DIR}"/*.offenses; do
        if [[ -f "$f" ]]; then
            has_files=true
            break
        fi
    done
    if [[ "$has_files" == "false" && ! -f "$BAN_HISTORY_FILE" ]]; then
        # Keine alten Daten vorhanden — Marker setzen und fertig
        echo "migrated_at=$(date '+%Y-%m-%d %H:%M:%S')" > "$_DB_MIGRATION_MARKER"
        echo "bans=0" >> "$_DB_MIGRATION_MARKER"
        echo "offenses=0" >> "$_DB_MIGRATION_MARKER"
        echo "history=0" >> "$_DB_MIGRATION_MARKER"
        echo "whitelist=0" >> "$_DB_MIGRATION_MARKER"
        echo -e "  ✅ Keine bestehenden Daten gefunden — Datenbank bereit"
        echo ""
        return 0
    fi

    echo -e "  ${CYAN}Migriere bestehende Daten nach SQLite...${NC}"
    echo ""

    local migrated
    migrated=$(db_migrate_from_files)

    if [[ "${migrated:-0}" -gt 0 ]]; then
        # Details aus dem Marker lesen
        local m_bans m_offenses m_history m_whitelist
        m_bans=$(grep '^bans=' "$_DB_MIGRATION_MARKER" 2>/dev/null | cut -d= -f2)
        m_offenses=$(grep '^offenses=' "$_DB_MIGRATION_MARKER" 2>/dev/null | cut -d= -f2)
        m_history=$(grep '^history=' "$_DB_MIGRATION_MARKER" 2>/dev/null | cut -d= -f2)
        m_whitelist=$(grep '^whitelist=' "$_DB_MIGRATION_MARKER" 2>/dev/null | cut -d= -f2)

        echo -e "  ${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "  ${GREEN}  SQLite-Migration erfolgreich abgeschlossen!${NC}"
        echo -e "  ${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  Migrierte Einträge gesamt: ${BOLD}${migrated}${NC}"
        [[ "${m_bans:-0}" -gt 0 ]]      && echo -e "    • Aktive Bans:       ${m_bans}"
        [[ "${m_offenses:-0}" -gt 0 ]]   && echo -e "    • Offense-Tracking:  ${m_offenses}"
        [[ "${m_history:-0}" -gt 0 ]]    && echo -e "    • Ban-History:       ${m_history}"
        [[ "${m_whitelist:-0}" -gt 0 ]]  && echo -e "    • Whitelist-Cache:   ${m_whitelist}"
        echo ""
        echo -e "  📦 Backup der alten Dateien: ${STATE_DIR}/.backup_pre_sqlite/"
        echo -e "  📂 Neue Datenbank: ${STATE_DIR}/adguard-shield.db"
    else
        echo -e "  ✅ Migration abgeschlossen — keine Daten zum Migrieren"
    fi
    echo ""
}

# ─── Update ──────────────────────────────────────────────────────────────────
do_update() {
    check_root

    # Prüfen ob installiert
    if [[ ! -d "$INSTALL_DIR" ]] || [[ ! -f "$INSTALL_DIR/adguard-shield.sh" ]]; then
        echo -e "${RED}AdGuard Shield ist nicht installiert!${NC}"
        echo "Bitte zuerst installieren: sudo bash $0 install"
        exit 1
    fi

    echo -e "${YELLOW}Starte Update von AdGuard Shield...${NC}"
    echo ""

    check_dependencies
    install_files

    # Konfigurations-Migration durchführen
    migrate_config

    # SQLite-Datenbank-Migration durchführen
    migrate_database

    # Service-Datei aktualisieren
    echo -e "${YELLOW}Aktualisiere systemd Service...${NC}"
    cp "$SCRIPT_DIR/adguard-shield.service" "$SERVICE_FILE"
    cp "$SCRIPT_DIR/adguard-shield-watchdog.service" /etc/systemd/system/adguard-shield-watchdog.service
    cp "$SCRIPT_DIR/adguard-shield-watchdog.timer" /etc/systemd/system/adguard-shield-watchdog.timer
    systemctl daemon-reload
    echo -e "  ✅ Service-Dateien aktualisiert (inkl. Watchdog)"
    echo ""

    # Interaktiv: Autostart beim Booten?
    if systemctl is-enabled adguard-shield &>/dev/null; then
        echo -e "  ℹ️  Autostart ist bereits aktiviert"
        # Watchdog-Timer auch aktivieren falls noch nicht aktiv
        if ! systemctl is-enabled adguard-shield-watchdog.timer &>/dev/null 2>&1; then
            systemctl enable adguard-shield-watchdog.timer
            systemctl start adguard-shield-watchdog.timer
            echo -e "  ✅ Watchdog-Timer aktiviert"
        fi
    else
        read -rep "  Soll AdGuard Shield beim Booten automatisch starten? [J/n]: " autostart
        if [[ "${autostart,,}" != "n" ]]; then
            systemctl enable adguard-shield.service
            systemctl enable adguard-shield-watchdog.timer
            systemctl start adguard-shield-watchdog.timer
            echo -e "  ✅ Autostart aktiviert (inkl. Watchdog-Timer)"
        else
            echo -e "  ℹ️  Autostart bleibt deaktiviert"
        fi
    fi
    echo ""

    # Interaktiv: Service neu starten?
    local service_was_active=false
    if systemctl is-active adguard-shield &>/dev/null; then
        service_was_active=true
    fi

    if [[ "$service_was_active" == "true" ]]; then
        read -rep "  Soll der Service jetzt neu gestartet werden? [J/n]: " restart_now
        if [[ "${restart_now,,}" != "n" ]]; then
            systemctl restart adguard-shield
            echo -e "  ✅ Service wurde neu gestartet"
        else
            echo -e "  ℹ️  Service wurde NICHT neu gestartet"
            echo -e "  ${YELLOW}Bitte manuell neustarten: sudo systemctl restart adguard-shield${NC}"
        fi
    else
        read -rep "  Soll der Service jetzt gestartet werden? [J/n]: " start_now
        if [[ "${start_now,,}" != "n" ]]; then
            systemctl start adguard-shield
            echo -e "  ✅ Service gestartet"
        else
            echo -e "  ℹ️  Service nicht gestartet"
            echo -e "  ${YELLOW}Später starten mit: sudo systemctl start adguard-shield${NC}"
        fi
    fi
    echo ""

    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  AdGuard Shield - Update abgeschlossen!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Bitte prüfe bei Bedarf die Konfiguration:"
    echo "     sudo nano $INSTALL_DIR/adguard-shield.conf"
    echo ""
    if [[ -f "$INSTALL_DIR/adguard-shield.conf.old" ]]; then
        echo "  Backup der vorherigen Konfiguration:"
        echo "     $INSTALL_DIR/adguard-shield.conf.old"
        echo ""
    fi
}

# ─── Deinstallation ─────────────────────────────────────────────────────────
do_uninstall() {
    check_root

    # Prüfen ob installiert
    if [[ ! -d "$INSTALL_DIR" ]]; then
        echo -e "${RED}AdGuard Shield ist nicht installiert!${NC}"
        exit 1
    fi

    # An den im Installationsverzeichnis liegenden Uninstaller delegieren
    if [[ -f "$INSTALL_DIR/uninstall.sh" ]]; then
        exec bash "$INSTALL_DIR/uninstall.sh"
    fi

    # Fallback für ältere Installationen ohne uninstall.sh
    echo -e "${YELLOW}Deinstalliere AdGuard Shield (Fallback-Modus)...${NC}"
    echo ""

    read -rep "  Wirklich deinstallieren? [j/N]: " confirm
    if [[ "${confirm,,}" != "j" ]]; then
        echo -e "${GREEN}Deinstallation abgebrochen.${NC}"
        exit 0
    fi
    echo ""

    if systemctl is-active adguard-shield &>/dev/null; then
        systemctl stop adguard-shield
        echo "  ✅ Service gestoppt"
    fi
    if systemctl is-enabled adguard-shield &>/dev/null; then
        systemctl disable adguard-shield
        echo "  ✅ Service deaktiviert"
    fi
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo "  ✅ Service-Datei entfernt"

    if [[ -f "$INSTALL_DIR/iptables-helper.sh" ]]; then
        bash "$INSTALL_DIR/iptables-helper.sh" remove || true
    fi

    read -rep "  Konfiguration und Logs behalten? [j/N]: " keep
    if [[ "${keep,,}" == "j" ]]; then
        rm -f "$INSTALL_DIR/adguard-shield.sh"
        rm -f "$INSTALL_DIR/iptables-helper.sh"
        rm -f "$INSTALL_DIR/unban-expired.sh"
        rm -f "$INSTALL_DIR/external-blocklist-worker.sh"
        rm -f "$INSTALL_DIR/external-whitelist-worker.sh"
        rm -f "$INSTALL_DIR/offense-cleanup-worker.sh"
        rm -f "$INSTALL_DIR/geoip-worker.sh"
        rm -f "$INSTALL_DIR/report-generator.sh"
        rm -f "$INSTALL_DIR/adguard-shield-watchdog.sh"
        rm -f "$INSTALL_DIR/db.sh"
        rm -f "$INSTALL_DIR/uninstall.sh"
        rm -rf "$INSTALL_DIR/templates"
        rm -rf "$INSTALL_DIR/geoip"
        echo "  ✅ Scripts entfernt (Konfiguration und Logs behalten)"
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

# ─── Hauptprogramm ──────────────────────────────────────────────────────────
main() {
    case "${1:-}" in
        install)
            print_header
            do_install
            ;;
        update)
            print_header
            do_update
            ;;
        uninstall)
            # print_header wird vom delegierten uninstall.sh übernommen
            do_uninstall
            ;;
        status)
            print_header
            do_status
            ;;
        --help|-h)
            print_header
            print_help
            ;;
        "")
            # Kein Argument → interaktives Menü anzeigen
            print_header
            show_menu
            ;;
        *)
            echo -e "${RED}Unbekannter Befehl: $1${NC}"
            echo ""
            print_help
            exit 1
            ;;
    esac
}

main "$@"
