# Dokumentation

Willkommen in der Dokumentation von AdGuard Shield.

AdGuard Shield ist ein Go-Daemon, der das Query Log von AdGuard Home auswertet, auffällige DNS-Clients erkennt und diese über eine eigene Firewall-Struktur sperrt. Die Dokumentation ist bewusst ausführlich gehalten: Sie soll nicht nur Befehle auflisten, sondern erklären, was im Hintergrund passiert, welche Werte sinnvoll sind und wie du Fehler sauber eingrenzt.

## Schnellnavigation

| Dokument | Wofür es gedacht ist |
|---|---|
| [Architektur & Funktionsweise](architektur.md) | Erklärt den Aufbau, den Datenfluss, Firewall, SQLite, Hintergrundjobs und Sperrlogik |
| [Befehle & Nutzung](befehle.md) | Vollständige CLI-Referenz mit typischen Betriebsabläufen |
| [Konfiguration](konfiguration.md) | Alle Parameter aus `adguard-shield.conf` mit Beispielen und Empfehlungen |
| [Docker-Installationen](docker.md) | Firewall-Modi für klassische Installation, Docker Host Network und veröffentlichte Docker-Ports |
| [Benachrichtigungen](benachrichtigungen.md) | Einrichtung von Ntfy, Discord, Slack, Gotify und Generic Webhooks |
| [E-Mail Report](report.md) | Report-Inhalte, Mailversand, Cron-Job und manuelle Tests |
| [Update-Anleitung](update.md) | Update der Go-Version und Migration von alten Shell-Installationen |
| [Tipps & Troubleshooting](tipps-und-troubleshooting.md) | Diagnosewege für API, Firewall, GeoIP, Reports, Listen und falsch gesetzte Sperren |

## Wichtigster Unterschied zur alten Shell-Version

Die frühere Version bestand aus mehreren Shell-Skripten, Hilfs-Workern, Cron-Jobs und einem separaten Watchdog. Die Go-Version bündelt diese Aufgaben in einem einzelnen Binary:

```text
/opt/adguard-shield/adguard-shield
```

Dieses Binary ist gleichzeitig:

- Daemon für den produktiven Betrieb
- CLI für Status, History, Logs, Firewall, Listen, GeoIP und Reports
- Installer, Updater und Uninstaller
- Report-Generator
- Hintergrundprozess für externe Whitelist, externe Blocklist, GeoIP und Offense-Cleanup

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

Wenn du AdGuard Shield neu einrichtest:

1. Lies zuerst [Architektur & Funktionsweise](architektur.md), damit klar ist, was genau gesperrt wird.
2. Passe danach [Konfiguration](konfiguration.md) an, besonders API-Zugang, Whitelist und Rate-Limits.
3. Nutze [Befehle & Nutzung](befehle.md) für Installation, Dry-Run und Service-Start.
4. Richte optional [Benachrichtigungen](benachrichtigungen.md), [Reports](report.md), GeoIP oder externe Listen ein.
5. Bei Problemen hilft [Tipps & Troubleshooting](tipps-und-troubleshooting.md).

Wenn du von der alten Shell-Version kommst, beginne mit [Update-Anleitung](update.md).
