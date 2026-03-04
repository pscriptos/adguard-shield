```
 ▄▄▄      ▓█████▄   ▄████  █    ██  ▄▄▄       ██▀███  ▓█████▄      ██████  ██░ ██  ██▓▓█████  ██▓    ▓█████▄ 
▒████▄    ▒██▀ ██▌ ██▒ ▀█▒ ██  ▓██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌   ▒██    ▒ ▓██░ ██▒▓██▒▓█   ▀ ▓██▒    ▒██▀ ██▌
▒██  ▀█▄  ░██   █▌▒██░▄▄▄░▓██  ▒██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌   ░ ▓██▄   ▒██▀▀██░▒██▒▒███   ▒██░    ░██   █▌
░██▄▄▄▄██ ░▓█▄   ▌░▓█  ██▓▓▓█  ░██░░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌     ▒   ██▒░▓█ ░██ ░██░▒▓█  ▄ ▒██░    ░▓█▄   ▌
 ▓█   ▓██▒░▒████▓ ░▒▓███▀▒▒▒█████▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▓    ▒██████▒▒░▓█▒░██▓░██░░▒████▒░██████▒░▒████▓ 
 ▒▒   ▓▒█░ ▒▒▓  ▒  ░▒   ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░░ ▒░ ░░ ▒░▓  ░ ▒▒▓  ▒ 
  ▒   ▒▒ ░ ░ ▒  ▒   ░   ░ ░░▒░ ░ ░   ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░ ░  ░░ ░ ▒  ░ ░ ▒  ▒ 
  ░   ▒    ░ ░  ░ ░ ░   ░  ░░░ ░ ░   ░   ▒     ░░   ░  ░ ░  ░    ░  ░  ░   ░  ░░ ░ ▒ ░   ░     ░ ░    ░ ░  ░ 
      ░  ░   ░          ░    ░           ░  ░   ░        ░             ░   ░  ░  ░ ░     ░  ░    ░  ░   ░    
           ░                                           ░                                              ░      
```

# AdGuard Shield

Automatischer Schutz für deinen AdGuard Home DNS-Server gegen übermäßige Anfragen einzelner Clients. Überwacht die AdGuard Home API, erkennt Rate-Limit-Verstöße und sperrt missbrauchende Clients per iptables — für alle DNS-Protokolle (DNS, DoH, DoT, DoQ).

## Was macht das Tool?

Wenn ein Client eine bestimmte Domain zu oft anfragt (z.B. >30x pro Minute), wird er automatisch auf Firewall-Ebene für alle DNS-Ports gesperrt. Nach einer konfigurierbaren Zeitspanne wird die Sperre automatisch aufgehoben.

## Features

- Automatische Erkennung und Sperre bei Rate-Limit-Verstößen
- **Subdomain-Flood-Erkennung** — erkennt Random-Subdomain-Attacken (z.B. `abc123.microsoft.com`, `xyz456.microsoft.com`, ...)
- **Progressive Sperren (Recidive)** — Wiederholungstäter werden stufenweise länger gesperrt (wie bei fail2ban)
- Unterstützt **alle DNS-Protokolle**: DNS (53), DoH (443), DoT (853), DoQ (784/853/8853)
- **IPv4 + IPv6**
- Eigene iptables Chain — greift nicht in bestehende Regeln ein
- Automatisches Entsperren nach konfigurierbarer Dauer
- **Externe Blocklisten** — IP-Adressen von externen Textdateien (URLs) laden und automatisch sperren
- **AbuseIPDB Reporting** — permanent gesperrte IPs automatisch an AbuseIPDB melden
- **Ban-History** — lückenlose Protokollierung aller Sperren/Entsperrungen mit Zeitstempel
- Whitelist für vertrauenswürdige IPs
- Dry-Run Modus zum gefahrlosen Testen
- Benachrichtigungen (Discord, Slack, Gotify, Ntfy)
- systemd Service für dauerhaften Betrieb

## Voraussetzungen

- Linux Server mit AdGuard Home (bare metal)
- Root-Zugriff (`sudo`)
- AdGuard Home Web-API erreichbar (Standard: Port 3000)
- Pakete: `curl`, `jq`, `iptables`, `gawk`, `systemd` — werden bei der Installation **automatisch** installiert

## Schnellstart

```bash
# 1. Repository klonen
git clone https://git.techniverse.net/scriptos/adguard-shield.git /tmp/adguard-shield
cd /tmp/adguard-shield

# 2. Installer aufrufen (interaktives Menü)
sudo bash install.sh

# Oder direkt installieren:
sudo bash install.sh install

# 3. Erst im Dry-Run testen (loggt nur, sperrt nichts)
sudo /opt/adguard-shield/adguard-shield.sh dry-run

# 4. Wenn alles passt — Service starten
sudo systemctl start adguard-shield
sudo systemctl status adguard-shield
```

> **Hinweis:** Bei der Installation werden alle benötigten Abhängigkeiten automatisch installiert und der Service wird für den Autostart beim Booten registriert.

[![asciicast](https://asciinema.techniverse.net/a/77.svg)](https://asciinema.techniverse.net/a/77)

## Wichtigste Befehle

```bash
# Installer-Menü
sudo bash install.sh                  # Interaktives Menü (Install/Update/Uninstall/Status)
sudo bash install.sh --help           # Hilfe anzeigen
sudo bash install.sh update           # Update mit automatischer Konfigurations-Migration
sudo bash install.sh status           # Installationsstatus prüfen

# Monitor
sudo /opt/adguard-shield/adguard-shield.sh status             # Aktive Sperren anzeigen
sudo /opt/adguard-shield/adguard-shield.sh history            # Ban-History anzeigen
sudo /opt/adguard-shield/adguard-shield.sh unban IP           # Einzelne IP entsperren
sudo /opt/adguard-shield/adguard-shield.sh flush              # Alle Sperren aufheben
sudo /opt/adguard-shield/adguard-shield.sh reset-offenses     # Offense-Zähler zurücksetzen
sudo /opt/adguard-shield/adguard-shield.sh test               # API-Verbindung testen
sudo /opt/adguard-shield/adguard-shield.sh blocklist-status   # Externe Blocklisten Status
sudo /opt/adguard-shield/adguard-shield.sh blocklist-sync     # Blocklisten manuell synchronisieren
sudo journalctl -u adguard-shield -f                             # Logs live verfolgen
```

## Projektstruktur

```
├── adguard-shield.sh              # Haupt-Monitor-Script
├── adguard-shield.conf            # Konfiguration
├── adguard-shield.service         # systemd Unit
├── external-blocklist-worker.sh   # Externer Blocklist-Worker
├── iptables-helper.sh             # Manuelle iptables-Verwaltung
├── unban-expired.sh               # Cron-basiertes Entsperren
├── install.sh                     # Installer / Updater / Uninstaller
├── README.md
└── doc/
    ├── architektur.md               # Architektur & Funktionsweise
    ├── konfiguration.md             # Alle Parameter erklärt + Konfig-Migration
    ├── befehle.md                   # Vollständige Befehlsreferenz inkl. Installer
    ├── benachrichtigungen.md        # Webhook-Setup (Discord, Slack, Gotify, Ntfy)
    └── tipps-und-troubleshooting.md
```

## Dokumentation

| Dokument | Inhalt |
|----------|--------|
| [Architektur](doc/architektur.md) | Wie das Tool funktioniert, iptables-Strategie, Konfig-Migration |
| [Konfiguration](doc/konfiguration.md) | Alle Parameter, Ports, Whitelist-Pflege, automatische Migration |
| [Befehle](doc/befehle.md) | Vollständige Befehlsreferenz für Installer, Monitor, iptables-Helper und systemd |
| [Benachrichtigungen](doc/benachrichtigungen.md) | Setup für Discord, Slack, Gotify, Ntfy |
| [Tipps & Troubleshooting](doc/tipps-und-troubleshooting.md) | Best Practices, häufige Probleme, Deinstallation |

## Lizenz

[MIT](LICENSE)

---

## 👥 Techniverse Community

Lust auf Austausch rund um Matrix, Selfhosting und andere smarte IT-Lösungen?
In der **Techniverse Community** triffst du Gleichgesinnte, kannst Fragen stellen oder einfach nerdigen Talk genießen. 🚀

👉 **[Jetzt der Gruppe auf Matrix beitreten](https://matrix.to/#/#community:techniverse.net)**
~ Direkte Raumadresse: `#community:techniverse.net`

👉 **[Für lockere Gespräche abseits der Kernthemen komm in den Talkraum](https://matrix.to/#/#talk:techniverse.net)**
~ Direkte Raumadresse: `#talk:techniverse.net`

Wir freuen uns, wenn du dabei bist!

---

📝 **Blog:** [www.cleveradmin.de](https://www.cleveradmin.de)
🌐 **Webseite:** [www.patrick-asmus.de](https://www.patrick-asmus.de)
📧 **E-Mail:** [support@techniverse.net](mailto:support@techniverse.net)

<p align="center">
  <img src="https://assets.techniverse.net/f1/git/graphics/gray0-catonline.svg" alt="">
</p>

<p align="center">
<img src="https://assets.techniverse.net/f1/logos/small/license.png" alt="License" width="15" height="15"> <a href="./LICENSE">License</a> | <img src="https://assets.techniverse.net/f1/logos/small/matrix2.svg" alt="Matrix" width="15" height="15"> <a href="https://matrix.to/#/#community:techniverse.net">Matrix</a> | <img src="https://assets.techniverse.net/f1/logos/small/mastodon2.svg" alt="Mastodon" width="15" height="15"> <a href="https://social.techniverse.net/@donnerwolke">Mastodon</a>
</p>
