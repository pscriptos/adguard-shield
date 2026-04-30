# Befehle & Nutzung

AdGuard Shield wird in der Go-Version über ein einzelnes Binary bedient:

```bash
/opt/adguard-shield/adguard-shield
```

Dieses Binary ist Daemon, CLI, Installer, Updater, Uninstaller und Report-Generator. Dadurch gibt es keine getrennten Shell-Skripte mehr.

## Grundform

```bash
sudo /opt/adguard-shield/adguard-shield <befehl>
```

Wenn du eine andere Konfigurationsdatei verwenden möchtest, muss `-config` direkt vor dem Befehl stehen:

```bash
sudo /opt/adguard-shield/adguard-shield -config /pfad/zur/adguard-shield.conf status
```

Standardpfade:

```text
Konfiguration: /opt/adguard-shield/adguard-shield.conf
SQLite-State:  /var/lib/adguard-shield/adguard-shield.db
Logdatei:      /var/log/adguard-shield.log
PID-Datei:     /var/run/adguard-shield.pid
```

## Schnellübersicht

```bash
# Version
/opt/adguard-shield/adguard-shield version

# Installation und Update
sudo ./adguard-shield install
sudo ./adguard-shield update
sudo ./adguard-shield install-status
sudo /opt/adguard-shield/adguard-shield uninstall --keep-config

# Service
sudo systemctl start adguard-shield
sudo systemctl stop adguard-shield
sudo systemctl restart adguard-shield
sudo systemctl status adguard-shield

# Diagnose
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield live
sudo /opt/adguard-shield/adguard-shield history 100
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100

# Manuelle Eingriffe
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
sudo /opt/adguard-shield/adguard-shield ban 192.168.1.100
sudo /opt/adguard-shield/adguard-shield flush
```

## Installation

Das installierte Binary landet standardmäßig unter:

```text
/opt/adguard-shield/adguard-shield
```

Typischer Ablauf:

```bash
# Binary ausführbar machen
chmod +x ./adguard-shield

# Standardinstallation
sudo ./adguard-shield install

# Bestehende Konfigurationsdatei als Vorlage übernehmen
sudo ./adguard-shield install --config-source ./adguard-shield.conf
```

Am Ende fragt der Installer, ob AdGuard Shield direkt gestartet oder neu gestartet werden soll.

Weitere Optionen:

```bash
# Paketprüfung überspringen
sudo ./adguard-shield install --skip-deps

# systemd-Autostart nicht aktivieren
sudo ./adguard-shield install --no-enable

# abweichendes Installationsverzeichnis
sudo ./adguard-shield install --install-dir /opt/adguard-shield-test
```

Der Installer erledigt:

1. Linux- und root-Prüfung
2. Prüfung auf alte Shell-Artefakte
3. Installation fehlender Abhängigkeiten über `apt-get`, sofern möglich
4. Anlage von Installations- und State-Verzeichnissen
5. Kopieren des laufenden Binarys
6. Anlage oder Migration der Konfiguration
7. Schreiben der systemd-Unit
8. `systemctl daemon-reload`
9. optional Autostart aktivieren
10. fragen, ob der Service direkt gestartet oder neu gestartet werden soll

Benötigte Systembefehle:

```text
iptables
ip6tables
ipset
systemctl
```

Auf Debian/Ubuntu installiert der Installer passende Pakete automatisch, sofern `apt-get` verfügbar ist und `--skip-deps` nicht gesetzt wurde.

## Update

Ein Update wird mit dem neuen Binary ausgeführt, nicht mit dem bereits installierten alten Binary.

```bash
chmod +x ./adguard-shield
sudo ./adguard-shield update
```

Am Ende fragt der Updater, ob AdGuard Shield direkt neu gestartet werden soll.

Mit expliziter Konfigurationsquelle:

```bash
sudo ./adguard-shield update --config-source ./adguard-shield.conf
```

Beim Update:

- wird die Installation wie bei `install` aktualisiert
- bleibt die vorhandene Konfiguration erhalten
- werden neue Konfigurationsparameter ergänzt
- wird bei einer Migration `adguard-shield.conf.old` geschrieben
- wird die systemd-Unit neu geschrieben
- wird systemd neu geladen

## Installationsstatus

```bash
sudo ./adguard-shield install-status
```

Für ein anderes Installationsverzeichnis:

```bash
sudo ./adguard-shield install-status --install-dir /opt/adguard-shield-test
```

`install-status` zeigt:

- Installationspfad
- Binary vorhanden
- installierte Version
- Konfiguration vorhanden
- systemd-Service vorhanden
- Autostart aktiv
- Service aktiv
- gefundene Legacy-Artefakte

## Deinstallation

```bash
# Alles entfernen
sudo /opt/adguard-shield/adguard-shield uninstall

# Konfiguration behalten
sudo /opt/adguard-shield/adguard-shield uninstall --keep-config
```

Bei der Deinstallation wird:

1. der Service gestoppt
2. der Autostart deaktiviert
3. die Shield-Firewall-Struktur entfernt
4. die systemd-Unit gelöscht
5. systemd neu geladen
6. je nach Option Installationsverzeichnis, State und Log entfernt

Mit `--keep-config` bleiben Konfigurationsdaten erhalten. Das ist sinnvoll, wenn du neu installieren oder migrieren möchtest.

## Alte Shell-Installation

Die Go-Version darf nicht parallel zur alten Shell-Version laufen. Der Installer bricht ab, wenn er alte Artefakte findet, zum Beispiel:

```text
/opt/adguard-shield/adguard-shield.sh
/opt/adguard-shield/iptables-helper.sh
/opt/adguard-shield/external-blocklist-worker.sh
/opt/adguard-shield/geoip-worker.sh
/etc/systemd/system/adguard-shield-watchdog.timer
```

Empfohlener Ablauf:

1. Bestehende `/opt/adguard-shield/adguard-shield.conf` sichern.
2. Alte Shell-Version mit deren Uninstaller entfernen und die Konfiguration behalten.
3. Go-Binary erneut installieren.
4. Konfiguration prüfen.
5. Zuerst `dry-run`, dann produktiven Service starten.

## systemd-Service

Im produktiven Betrieb sollte AdGuard Shield über systemd laufen:

```bash
sudo systemctl start adguard-shield
sudo systemctl stop adguard-shield
sudo systemctl restart adguard-shield
sudo systemctl status adguard-shield
```

Autostart:

```bash
sudo systemctl enable adguard-shield
sudo systemctl disable adguard-shield
```

Nach manuellen Änderungen an der Unit:

```bash
sudo systemctl daemon-reload
```

Die Unit startet:

```bash
/opt/adguard-shield/adguard-shield -config /opt/adguard-shield/adguard-shield.conf run
```

Die Go-Version nutzt `Restart=on-failure`. Einen separaten Watchdog-Service oder Watchdog-Timer gibt es nicht mehr.

## Daemon direkt starten

Für Debugging oder Dry-Run kann der Daemon im Vordergrund gestartet werden:

```bash
# normaler Vordergrundlauf
sudo /opt/adguard-shield/adguard-shield run

# Alias für run
sudo /opt/adguard-shield/adguard-shield start

# analysieren ohne echte Sperren
sudo /opt/adguard-shield/adguard-shield dry-run
```

Stop über PID-Datei:

```bash
sudo /opt/adguard-shield/adguard-shield stop
```

Für den Alltag gilt: Nutze `systemctl`. Der direkte Vordergrundlauf endet, sobald die Shell beendet wird oder du `Strg+C` drückst.

## API-Test

```bash
sudo /opt/adguard-shield/adguard-shield test
```

Der Test ruft `/control/querylog` auf und prüft damit:

- ist `ADGUARD_URL` erreichbar?
- funktionieren HTTP/TLS und Netzwerk?
- stimmen `ADGUARD_USER` und `ADGUARD_PASS`?
- liefert AdGuard Home Querylog-Daten?

Bei Erfolg erscheint sinngemäß:

```text
Verbindung erfolgreich. 123 Querylog-Einträge gefunden.
```

Wenn der Test fehlschlägt, zuerst die Konfiguration und die AdGuard-Home-Weboberfläche prüfen.

## Status

```bash
sudo /opt/adguard-shield/adguard-shield status
```

`status` zeigt:

- verwendete Konfigurationsdatei
- Firewall-Backend und Chain
- GeoIP-Aktivierung, Modus und Länder
- externe Blocklist und Anzahl der URLs
- externe Whitelist und Anzahl der URLs
- aktive Sperren mit IP, Quelle, Grund und Ablaufzeit

Bei sehr vielen aktiven Sperren werden nur die ersten 50 angezeigt. Details stehen in der History oder direkt in SQLite.

## Live-Ansicht

```bash
sudo /opt/adguard-shield/adguard-shield live
```

`live` ist die beste Ansicht, wenn du verstehen möchtest, was gerade passiert.

Sie zeigt:

- Query-Poller, API-Einträge, Zeitfenster und Rate-Limit
- Top Client/Domain-Kombinationen
- Subdomain-Flood-Kandidaten
- letzte Querylog-Einträge
- aktive Sperren
- externe Listen
- GeoIP-Status
- Offense-Cleanup-Status
- Systemereignisse aus der Logdatei

Optionen:

```bash
# alle 2 Sekunden aktualisieren
sudo /opt/adguard-shield/adguard-shield live --interval 2

# Top 20 anzeigen
sudo /opt/adguard-shield/adguard-shield live --top 20

# mehr letzte Queries und Logs anzeigen
sudo /opt/adguard-shield/adguard-shield live --recent 25

# DEBUG-Logs einblenden
sudo /opt/adguard-shield/adguard-shield live --logs debug

# Logbereich ausblenden
sudo /opt/adguard-shield/adguard-shield live --logs off

# nur einmaligen Snapshot ausgeben
sudo /opt/adguard-shield/adguard-shield live --once
```

Alias:

```bash
sudo /opt/adguard-shield/adguard-shield watch
```

## History

```bash
# letzte 50 Einträge
sudo /opt/adguard-shield/adguard-shield history

# letzte 200 Einträge
sudo /opt/adguard-shield/adguard-shield history 200
```

Die History kommt aus der SQLite-Tabelle `ban_history`. Sie enthält:

- `BAN`: echte Sperre
- `UNBAN`: Freigabe
- `DRY`: im Dry-Run erkannt, aber nicht gesperrt

Format:

```text
Zeit | Aktion | Client-IP | Domain | Anzahl | Dauer | Protokoll | Grund
```

Typische Gründe:

| Grund | Bedeutung |
|---|---|
| `rate-limit` | gleiche Domain zu oft angefragt |
| `subdomain-flood` | zu viele eindeutige Subdomains einer Basisdomain |
| `dns-flood-watchlist` | Watchlist-Treffer mit Permanent-Ban |
| `external-blocklist` | Sperre aus externer Blocklist |
| `geoip` | GeoIP-Länderfilter |
| `manual` | manuelle Freigabe |
| `manual-flush` | Freigabe durch `flush` |
| `expired` | temporäre Sperre abgelaufen |
| `external-whitelist` | Freigabe durch externe Whitelist |

## Logs

AdGuard Shield schreibt Daemon-Ereignisse in `LOG_FILE`, standardmäßig:

```text
/var/log/adguard-shield.log
```

CLI:

```bash
# letzte INFO/WARN/ERROR-Einträge
sudo /opt/adguard-shield/adguard-shield logs

# letzte 100 Warnungen und Fehler
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100

# Kurzform
sudo /opt/adguard-shield/adguard-shield logs debug

# laufende Ansicht
sudo /opt/adguard-shield/adguard-shield logs-follow --level info
```

Erlaubte Level:

```text
DEBUG
INFO
WARN
ERROR
```

systemd-Journal:

```bash
sudo journalctl -u adguard-shield -f
sudo journalctl -u adguard-shield --no-pager -n 100
```

Hinweis: Query-Inhalte werden nicht dauerhaft in die Logdatei geschrieben. Für Query-nahe Diagnose ist `live` gedacht.

## Manuelle Sperren und Freigaben

```bash
# IP permanent sperren
sudo /opt/adguard-shield/adguard-shield ban 192.168.1.100

# IP entsperren
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100

# alle aktiven Sperren aufheben
sudo /opt/adguard-shield/adguard-shield flush
```

`ban` legt eine manuelle permanente Sperre an. `unban` entfernt die IP aus Firewall und Datenbank. `flush` hebt alle aktiven Sperren auf.

Whitelist-Regeln gelten auch für manuelle Sperren. Eine IP aus `WHITELIST` oder externer Whitelist wird nicht gesperrt.

Bulk-Kommandos senden bei aktivierten Benachrichtigungen eine zusammenfassende Freigabe-Meldung, nicht eine Nachricht pro IP.

## Progressive Sperren und Offenses

```bash
# Offense-Zähler anzeigen
sudo /opt/adguard-shield/adguard-shield offense-status

# abgelaufene Zähler entfernen
sudo /opt/adguard-shield/adguard-shield offense-cleanup

# alle Offense-Zähler zurücksetzen
sudo /opt/adguard-shield/adguard-shield reset-offenses

# Zähler für eine IP zurücksetzen
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

Nützlich nach Fehlkonfigurationen:

```bash
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

## Firewall-Befehle

```bash
# Chain und ipsets anlegen
sudo /opt/adguard-shield/adguard-shield firewall-create

# Status anzeigen
sudo /opt/adguard-shield/adguard-shield firewall-status

# ipsets leeren
sudo /opt/adguard-shield/adguard-shield firewall-flush

# Chain, Regeln und ipsets entfernen
sudo /opt/adguard-shield/adguard-shield firewall-remove

# aktuelle iptables-Regeln sichern
sudo /opt/adguard-shield/adguard-shield firewall-save

# gespeicherte Regeln wiederherstellen
sudo /opt/adguard-shield/adguard-shield firewall-restore
```

Normalerweise musst du diese Befehle nicht manuell ausführen. Der Daemon erstellt die Firewall beim Start und schreibt aktive Sperren aus SQLite wieder hinein.

Welche Host-Chain genutzt wird, hängt von `FIREWALL_MODE` ab. Klassische Installationen und Docker Host Network nutzen `INPUT`; Docker mit veröffentlichten Ports nutzt `DOCKER-USER`. Details stehen in [Docker-Installationen](docker.md).

Gespeicherte Regeln:

```text
/var/lib/adguard-shield/iptables-rules.v4
/var/lib/adguard-shield/iptables-rules.v6
```

## Externe Whitelist

```bash
# Status anzeigen
sudo /opt/adguard-shield/adguard-shield whitelist-status

# sofort synchronisieren
sudo /opt/adguard-shield/adguard-shield whitelist-sync

# aufgelöste externe Whitelist entfernen
sudo /opt/adguard-shield/adguard-shield whitelist-flush
```

Die externe Whitelist kann IPs, CIDR-Netze und Hostnamen enthalten. Hostnamen werden per DNS aufgelöst und als IPs in SQLite gespeichert.

Wichtig:

- Eine gewhitelistete IP wird nicht gesperrt.
- Wird eine bereits gesperrte IP später gewhitelistet, wird sie freigegeben.
- Die dauerhafte Synchronisation läuft im Daemon.
- `whitelist-sync` erzwingt nur einen einzelnen Lauf.

## Externe Blocklist

```bash
# Status anzeigen
sudo /opt/adguard-shield/adguard-shield blocklist-status

# sofort synchronisieren
sudo /opt/adguard-shield/adguard-shield blocklist-sync

# alle Sperren aus externer Blocklist aufheben
sudo /opt/adguard-shield/adguard-shield blocklist-flush
```

Die externe Blocklist kann IPs, CIDR-Netze und Hostnamen enthalten. Hostnamen werden aufgelöst. Einträge aus der Whitelist werden übersprungen.

Wenn `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` gesetzt ist, hebt der Daemon Blocklist-Sperren wieder auf, sobald sie nicht mehr in der externen Liste vorkommen.

## GeoIP

```bash
# Status anzeigen
sudo /opt/adguard-shield/adguard-shield geoip-status

# aktuelle Clients aus dem Querylog einmalig prüfen
sudo /opt/adguard-shield/adguard-shield geoip-sync

# alle GeoIP-Sperren aufheben
sudo /opt/adguard-shield/adguard-shield geoip-flush

# Cache leeren
sudo /opt/adguard-shield/adguard-shield geoip-flush-cache

# einzelne IP nachschlagen
sudo /opt/adguard-shield/adguard-shield geoip-lookup 8.8.8.8
```

GeoIP-Sperren sind permanent, werden aber bei Konfigurationsänderungen automatisch neu bewertet.

## Reports

```bash
# Konfiguration und Cron-Status anzeigen
sudo /opt/adguard-shield/adguard-shield report-status

# HTML-Report in Datei schreiben
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html

# Text-Report auf stdout ausgeben
sudo /opt/adguard-shield/adguard-shield report-generate txt

# Testmail senden
sudo /opt/adguard-shield/adguard-shield report-test

# aktuellen Report senden
sudo /opt/adguard-shield/adguard-shield report-send

# Cron-Job installieren
sudo /opt/adguard-shield/adguard-shield report-install

# Cron-Job entfernen
sudo /opt/adguard-shield/adguard-shield report-remove
```

Der Cron-Job liegt hier:

```text
/etc/cron.d/adguard-shield-report
```

## Dry-Run

```bash
sudo /opt/adguard-shield/adguard-shield dry-run
```

Der Dry-Run ist der sicherste Weg, neue Konfigurationen zu prüfen.

Im Dry-Run:

- werden Querylogs normal gelesen
- Rate-Limit, Subdomain-Flood, Watchlist, externe Blocklist und GeoIP werden ausgewertet
- mögliche Sperren landen als `DRY` in der History
- es werden keine aktiven Bans angelegt
- es werden keine Firewall-Regeln gesetzt

Typischer Ablauf nach größeren Änderungen:

```bash
sudo /opt/adguard-shield/adguard-shield dry-run
sudo /opt/adguard-shield/adguard-shield history 50
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 80
```

## Typische Betriebsabläufe

### Nach Konfigurationsänderung

```bash
sudo systemctl restart adguard-shield
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield logs --level info --limit 80
```

### Falsch gesperrte IP freigeben

```bash
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

Danach die IP dauerhaft in `WHITELIST` oder eine externe Whitelist aufnehmen.

### Externe Listen neu laden

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-sync
sudo /opt/adguard-shield/adguard-shield blocklist-sync
sudo /opt/adguard-shield/adguard-shield status
```

### Firewall neu aufbauen

```bash
sudo /opt/adguard-shield/adguard-shield firewall-remove
sudo /opt/adguard-shield/adguard-shield firewall-create
sudo systemctl restart adguard-shield
```

Nach dem Neustart schreibt der Daemon aktive Sperren aus SQLite wieder in die Firewall.

### Service-Problem eingrenzen

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield logs --level debug --limit 100
```

## DNS-Abfragen zum Testen

Die folgenden Befehle sind ausschließlich für kontrollierte Tests gegen deinen eigenen DNS-Server gedacht. Ersetze `203.0.113.50` durch deine eigene DNS-Server-IP und `example.com` durch eine Testdomain.

Nicht gegen fremde DNS-Server, fremde Dienste oder fremde Infrastruktur verwenden.

### Voraussetzungen auf dem Testclient

```bash
# klassisches DNS
sudo apt install dnsutils

# DoH
sudo apt install curl

# DoT
sudo apt install knot-dnsutils
```

### Klassisches DNS

Gleiche Domain mehrfach abfragen:

```bash
for i in {1..40}; do \
  dig @203.0.113.50 example.com +short +cookie=$(openssl rand -hex 8) > /dev/null & \
done; wait
```

Viele zufällige Subdomains:

```bash
for i in {1..60}; do \
  dig @203.0.113.50 $(openssl rand -hex 6).example.com +short > /dev/null & \
done; wait
```

### DNS over HTTPS

```bash
for i in {1..40}; do \
  curl -s -H "accept: application/dns-json" \
    "https://203.0.113.50/dns-query?name=example.com&type=A" > /dev/null & \
done; wait
```

Bei selbstsigniertem Zertifikat auf dem eigenen Testserver kann für diesen lokalen Test `-k` ergänzt werden.

### DNS over TLS

```bash
for i in {1..40}; do \
  kdig @203.0.113.50 example.com +tls +short > /dev/null & \
done; wait
```

Die Beispielzahlen liegen bewusst nahe an den Standardlimits `RATE_LIMIT_MAX_REQUESTS=30` und `SUBDOMAIN_FLOOD_MAX_UNIQUE=50`.

## Eingebaute Hilfe

```bash
/opt/adguard-shield/adguard-shield --help
```

Bei unbekannten Befehlen gibt das Binary die Usage-Ausgabe aus. Der wichtigste Merksatz für die Go-Version:

```bash
sudo /opt/adguard-shield/adguard-shield <befehl>
```

Nicht mehr:

```bash
sudo /opt/adguard-shield/adguard-shield.sh <befehl>
```
