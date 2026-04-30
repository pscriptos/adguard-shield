# Dokumentation

Willkommen in der Dokumentation von AdGuard Shield.

AdGuard Shield ist ein Go-Daemon, der das Query Log von AdGuard Home auswertet, auffällige DNS-Clients erkennt und diese über eine eigene Firewall-Struktur sperrt. Die Dokumentation ist bewusst ausführlich gehalten: Sie soll nicht nur Befehle auflisten, sondern erklären, was im Hintergrund passiert, welche Werte sinnvoll sind und wie du Fehler sauber eingrenzt.

## Schnellnavigation

| Dokument | Wofür es gedacht ist |
|---|---|
| [Architektur & Funktionsweise](architektur.md) | Erklärt den Aufbau, den Datenfluss, Firewall-Modell, SQLite-Schema, Hintergrundjobs und Sperrlogik |
| [Befehle & Nutzung](befehle.md) | Vollständige CLI-Referenz mit Beispielen und typischen Betriebsabläufen |
| [Konfiguration](konfiguration.md) | Alle Parameter aus `adguard-shield.conf` mit Beispielen, Empfehlungen und Beispielkonfigurationen |
| [Docker-Installationen](docker.md) | Firewall-Modi für klassische Installation, Docker Host Network und veröffentlichte Docker-Ports |
| [Benachrichtigungen](benachrichtigungen.md) | Einrichtung von Ntfy, Discord, Slack, Gotify und Generic Webhooks mit Beispielinhalten |
| [E-Mail Report](report.md) | Report-Inhalte, Formate, Mailversand, Cron-Job und manuelle Tests |
| [Update-Anleitung](update.md) | Update der Go-Version, Konfigurationsmigration und Migration von alten Shell-Installationen |
| [Tipps & Troubleshooting](tipps-und-troubleshooting.md) | Diagnosewege für API, Firewall, GeoIP, Reports, externe Listen und falsch gesetzte Sperren |

## Das Binary

Die Go-Version bündelt alle Aufgaben in einem einzelnen Binary:

```text
/opt/adguard-shield/adguard-shield
```

Dieses Binary ist gleichzeitig:

- **Daemon** für den produktiven Betrieb (Querylog-Polling, Erkennung, Sperren)
- **CLI** für Status, History, Logs, Firewall, Listen, GeoIP und Reports
- **Installer**, **Updater** und **Uninstaller**
- **Report-Generator** für HTML- und Text-Reports
- **Hintergrundprozess** für externe Whitelist, externe Blocklist, GeoIP und Offense-Cleanup

Die meisten Befehle beginnen daher mit:

```bash
sudo /opt/adguard-shield/adguard-shield <befehl>
```

Für Installation oder Update nutzt du das neue Binary aus dem Repository, Release oder Build-Verzeichnis:

```bash
sudo ./adguard-shield install
sudo ./adguard-shield update
```

## Empfohlener Lesefluss

### Neueinrichtung

1. Lies zuerst [Architektur & Funktionsweise](architektur.md), damit klar ist, was genau gesperrt wird und wie der Datenfluss aussieht.
2. Passe danach [Konfiguration](konfiguration.md) an, besonders API-Zugang, Whitelist und Rate-Limits.
3. Nutze [Befehle & Nutzung](befehle.md) für Installation, Dry-Run und Service-Start.
4. Richte optional [Benachrichtigungen](benachrichtigungen.md), [Reports](report.md), GeoIP oder externe Listen ein.
5. Bei Problemen hilft [Tipps & Troubleshooting](tipps-und-troubleshooting.md).

### Migration von der Shell-Version

Wenn du von der alten Shell-Version kommst, beginne mit [Update-Anleitung](update.md). Dort findest du den empfohlenen Migrationsablauf und Hinweise zu den erkannten Legacy-Artefakten.

### Docker-Setups

Wenn AdGuard Home in Docker läuft, lies [Docker-Installationen](docker.md) zusätzlich zur Grundkonfiguration. Der Firewall-Modus bestimmt, in welcher Chain die Sperren greifen.

## Wichtigster Unterschied zur alten Shell-Version

Die frühere Version bestand aus mehreren Shell-Skripten, Hilfs-Workern, Cron-Jobs und einem separaten Watchdog:

| Alte Shell-Version | Go-Version |
|---|---|
| `adguard-shield.sh` (Hauptskript) | Ein Binary für alles |
| `iptables-helper.sh` | Integriert im Binary |
| `external-blocklist-worker.sh` | Goroutine im Daemon |
| `external-whitelist-worker.sh` | Goroutine im Daemon |
| `geoip-worker.sh` | Goroutine im Daemon |
| `offense-cleanup-worker.sh` | Goroutine im Daemon |
| `report-generator.sh` | Integriert im Binary |
| `unban-expired.sh` | Integriert im Daemon |
| Watchdog-Service + Timer | `Restart=on-failure` in systemd |
| Mehrere Cron-Jobs | Ein optionaler Cron-Job für Reports |
