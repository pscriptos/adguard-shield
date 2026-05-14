# Befehle & Nutzung

AdGuard Shield wird in der Go-Version über ein einzelnes Binary bedient:

```bash
/opt/adguard-shield/adguard-shield
```

Bei Installation und Update registriert der Installer zusätzlich den globalen Befehl:

```bash
/usr/local/bin/adguard-shield
```

Dieser Symlink zeigt auf das installierte Binary. Dadurch gibt es keine getrennten Shell-Skripte mehr, und du kannst AdGuard Shield nach der Installation ohne vollständigen Pfad aufrufen.

## Grundform

```bash
sudo adguard-shield <befehl>
```

Wenn du eine andere Konfigurationsdatei verwenden möchtest, muss `-config` direkt vor dem Befehl stehen:

```bash
sudo adguard-shield -config /pfad/zur/adguard-shield.conf status
```

### Standardpfade

| Datei | Pfad |
|---|---|
| Binary | `/opt/adguard-shield/adguard-shield` |
| CLI-Befehl | `/usr/local/bin/adguard-shield` |
| Konfiguration | `/opt/adguard-shield/adguard-shield.conf` |
| SQLite-Datenbank | `/var/lib/adguard-shield/adguard-shield.db` |
| Logdatei | `/var/log/adguard-shield.log` |
| PID-Datei | `/var/run/adguard-shield.pid` |

## Schnellübersicht

```bash
# Version anzeigen
adguard-shield version

# Installation und Update
sudo ./adguard-shield install
sudo ./adguard-shield update
sudo adguard-shield install-status
sudo adguard-shield uninstall --keep-config

# Service-Management über systemd
sudo systemctl start adguard-shield
sudo systemctl stop adguard-shield
sudo systemctl restart adguard-shield
sudo systemctl status adguard-shield

# Diagnose und Monitoring
sudo adguard-shield test
sudo adguard-shield status
sudo adguard-shield live
sudo adguard-shield history 100
sudo adguard-shield logs --level warn --limit 100

# Manuelle Eingriffe
sudo adguard-shield ban 192.168.1.100
sudo adguard-shield unban 192.168.1.100
sudo adguard-shield flush
```

---

## Installation

Das installierte Binary landet standardmäßig unter:

```text
/opt/adguard-shield/adguard-shield
```

Zusätzlich wird standardmäßig dieser CLI-Befehl angelegt:

```text
/usr/local/bin/adguard-shield -> /opt/adguard-shield/adguard-shield
```

### Standardinstallation

```bash
chmod +x ./adguard-shield
sudo ./adguard-shield install
```

Am Ende fragt der Installer, ob AdGuard Shield direkt gestartet oder neu gestartet werden soll.

### Installationsoptionen

| Option | Beschreibung |
|---|---|
| `--config-source <pfad>` | Bestehende Konfigurationsdatei als Vorlage übernehmen |
| `--skip-deps` | Automatische Paketprüfung und -installation überspringen |
| `--no-enable` | systemd-Autostart nicht aktivieren |
| `--no-register` | Globalen CLI-Befehl `/usr/local/bin/adguard-shield` nicht anlegen |
| `--install-dir <pfad>` | Abweichendes Installationsverzeichnis verwenden |

**Beispiele:**

```bash
# Konfiguration aus anderem Pfad übernehmen
sudo ./adguard-shield install --config-source ./adguard-shield.conf

# Ohne Paketprüfung installieren
sudo ./adguard-shield install --skip-deps

# Ohne globalen CLI-Befehl installieren
sudo ./adguard-shield install --no-register

# In anderes Verzeichnis installieren
sudo ./adguard-shield install --install-dir /opt/adguard-shield-test
```

### Was der Installer macht

Der Installer führt diese Schritte automatisch durch:

| Schritt | Beschreibung |
|---:|---|
| 1 | Linux- und Root-Prüfung |
| 2 | Prüfung auf alte Shell-Artefakte |
| 3 | Installation fehlender Abhängigkeiten über `apt-get` (sofern möglich) |
| 4 | Anlage von Installations- und State-Verzeichnissen |
| 5 | Kopieren des Binarys nach `/opt/adguard-shield/` |
| 6 | CLI-Befehl `/usr/local/bin/adguard-shield` registrieren (sofern nicht `--no-register`) |
| 7 | Report-Templates installieren |
| 8 | Anlage oder Migration der Konfiguration |
| 9 | Schreiben der systemd-Unit |
| 10 | `systemctl daemon-reload` und optional Autostart aktivieren |
| 11 | Nachfrage: Service direkt starten oder neu starten |

### Benötigte Systembefehle

| Befehl | Paket (Debian/Ubuntu) | Zweck |
|---|---|---|
| `iptables` | `iptables` | IPv4-Firewall |
| `ip6tables` | `iptables` | IPv6-Firewall |
| `ipset` | `ipset` | IP-Set-Verwaltung für performante Sperren |
| `systemctl` | `systemd` | Service-Management |

Auf Debian/Ubuntu installiert der Installer passende Pakete automatisch, sofern `apt-get` verfügbar ist und `--skip-deps` nicht gesetzt wurde.

---

## Update

Ein Update wird immer mit dem **neuen** Binary ausgeführt, nicht mit dem bereits installierten alten Binary:

```bash
chmod +x ./adguard-shield
sudo ./adguard-shield update
```

Am Ende fragt der Updater, ob AdGuard Shield direkt neu gestartet werden soll.

### Update mit expliziter Konfigurationsquelle

```bash
sudo ./adguard-shield update --config-source ./adguard-shield.conf
```

### Update ohne CLI-Registrierung

```bash
sudo ./adguard-shield update --no-register
```

### Was beim Update passiert

- Die Installation wird wie bei `install` aktualisiert
- Der CLI-Befehl `/usr/local/bin/adguard-shield` wird angelegt oder bestätigt, sofern `--no-register` nicht gesetzt ist
- Vorhandene Konfiguration bleibt erhalten
- Neue Konfigurationsparameter werden ergänzt
- Bei einer Migration wird `adguard-shield.conf.old` geschrieben
- Die systemd-Unit wird neu geschrieben und systemd neu geladen

Weitere Details stehen in der [Update-Anleitung](update.md).

---

## Installationsstatus

```bash
sudo adguard-shield install-status
```

Zeigt eine Übersicht mit:

- Installationspfad und Binary-Status
- Installierte Version
- CLI-Befehl in `/usr/local/bin` vorhanden
- Konfiguration vorhanden
- systemd-Service vorhanden und Status
- Autostart aktiv
- Gefundene Legacy-Artefakte

Für ein anderes Installationsverzeichnis:

```bash
sudo ./adguard-shield install-status --install-dir /opt/adguard-shield-test
```

---

## Deinstallation

```bash
# Vollständige Deinstallation
sudo adguard-shield uninstall

# Deinstallation mit Konfigurationserhalt
sudo adguard-shield uninstall --keep-config
```

**Was bei der Deinstallation passiert:**

| Schritt | Beschreibung |
|---:|---|
| 1 | Service stoppen |
| 2 | Autostart deaktivieren |
| 3 | Shield-Firewall-Struktur entfernen (Chain, ipsets) |
| 4 | systemd-Unit löschen |
| 5 | systemd neu laden |
| 6 | Installationsverzeichnis, State und Log entfernen |

Mit `--keep-config` bleiben Konfigurationsdaten erhalten. Das ist sinnvoll, wenn du neu installieren oder migrieren möchtest.

---

## Alte Shell-Installation

Die Go-Version darf nicht parallel zur alten Shell-Version laufen. Der Installer bricht ab, wenn er alte Artefakte findet, zum Beispiel:

```text
/opt/adguard-shield/adguard-shield.sh
/opt/adguard-shield/iptables-helper.sh
/opt/adguard-shield/external-blocklist-worker.sh
/opt/adguard-shield/geoip-worker.sh
/etc/systemd/system/adguard-shield-watchdog.timer
```

**Empfohlener Ablauf:**

1. Bestehende `/opt/adguard-shield/adguard-shield.conf` sichern.
2. Alte Shell-Version mit deren Uninstaller entfernen und die Konfiguration behalten.
3. Go-Binary erneut installieren.
4. Konfiguration prüfen.
5. Zuerst `dry-run`, dann produktiven Service starten.

Weitere Details stehen in der [Update-Anleitung](update.md).

---

## systemd-Service

Im produktiven Betrieb sollte AdGuard Shield über systemd laufen:

```bash
sudo systemctl start adguard-shield      # Service starten
sudo systemctl stop adguard-shield       # Service stoppen
sudo systemctl restart adguard-shield    # Service neu starten
sudo systemctl status adguard-shield     # Status anzeigen
```

### Autostart

```bash
sudo systemctl enable adguard-shield     # Autostart aktivieren
sudo systemctl disable adguard-shield    # Autostart deaktivieren
```

### Nach manuellen Änderungen an der Unit

```bash
sudo systemctl daemon-reload
```

### Startbefehl der Unit

Die systemd-Unit startet den Daemon mit:

```bash
/opt/adguard-shield/adguard-shield -config /opt/adguard-shield/adguard-shield.conf run
```

Die Go-Version nutzt `Restart=on-failure` mit `RestartSec=30s`. Einen separaten Watchdog-Service oder Watchdog-Timer gibt es nicht mehr.

---

## Daemon direkt starten

Für Debugging oder Dry-Run kann der Daemon im Vordergrund gestartet werden:

```bash
# Normaler Vordergrundlauf
sudo adguard-shield run

# Alias für run
sudo adguard-shield start

# Analysieren ohne echte Sperren
sudo adguard-shield dry-run
```

### Daemon über PID-Datei stoppen

```bash
sudo adguard-shield stop
```

Für den Alltag gilt: Nutze `systemctl`. Der direkte Vordergrundlauf endet, sobald die Shell beendet wird oder du `Strg+C` drückst.

---

## API-Test

```bash
sudo adguard-shield test
```

Der `test`-Befehl prüft die Verbindung zur AdGuard-Home-API:

| Prüfung | Was getestet wird |
|---|---|
| Netzwerk | Ist `ADGUARD_URL` erreichbar? |
| TLS | Funktioniert HTTPS/TLS? |
| Authentifizierung | Stimmen `ADGUARD_USER` und `ADGUARD_PASS`? |
| Querylog | Liefert AdGuard Home Querylog-Daten? |

**Bei Erfolg:**

```text
Verbindung erfolgreich. 123 Querylog-Einträge gefunden.
```

Wenn der Test fehlschlägt, zuerst die Konfiguration und die AdGuard-Home-Weboberfläche prüfen.

---

## Status

```bash
sudo adguard-shield status
```

Zeigt eine Übersicht des aktuellen Zustands:

- Verwendete Konfigurationsdatei
- Firewall-Backend, -Modus und Chain
- GeoIP-Aktivierung, Modus und Länderliste
- Externe Blocklist (aktiv/inaktiv, Anzahl URLs)
- Externe Whitelist (aktiv/inaktiv, Anzahl URLs)
- Aktive Sperren mit IP, Quelle, Grund und Ablaufzeit

Bei sehr vielen aktiven Sperren werden nur die ersten 50 angezeigt. Für Details nutze `history` oder frage SQLite direkt ab.

---

## Live-Ansicht

```bash
sudo adguard-shield live
```

Die `live`-Ansicht ist das beste Werkzeug, wenn du verstehen möchtest, was gerade passiert. Sie zeigt in Echtzeit:

| Bereich | Inhalt |
|---|---|
| Query-Poller | API-Einträge, Zeitfenster und Rate-Limit-Status |
| Top-Kombinationen | Häufigste Client/Domain-Paare |
| Subdomain-Flood | Aktuelle Subdomain-Flood-Kandidaten |
| Letzte Queries | Die neuesten Querylog-Einträge |
| Aktive Sperren | Alle derzeit gesperrten IPs |
| Externe Listen | Status von Blocklist und Whitelist |
| GeoIP | GeoIP-Konfiguration und Status |
| Offense-Cleanup | Progressive-Ban-Status |
| Systemereignisse | Aktuelle Logeinträge |

### Optionen

| Option | Beschreibung | Beispiel |
|---|---|---|
| `--interval <sek>` | Aktualisierungsintervall in Sekunden | `live --interval 2` |
| `--top <n>` | Anzahl der Top-Einträge | `live --top 20` |
| `--recent <n>` | Anzahl letzter Queries und Logs | `live --recent 25` |
| `--logs <level>` | Log-Level anzeigen (`debug`, `info`, `warn`, `error`, `off`) | `live --logs debug` |
| `--once` | Einmaligen Snapshot ausgeben, nicht fortlaufend | `live --once` |

### Alias

```bash
sudo adguard-shield watch
```

---

## History

```bash
# Letzte 50 Einträge (Standard)
sudo adguard-shield history

# Letzte 200 Einträge
sudo adguard-shield history 200
```

Die History kommt aus der SQLite-Tabelle `ban_history`.

### Ausgabeformat

```text
Zeit | Aktion | Client-IP | Domain | Anzahl | Dauer | Protokoll | Grund
```

### Aktionstypen

| Aktion | Bedeutung |
|---|---|
| `BAN` | Echte Sperre gesetzt |
| `UNBAN` | Sperre aufgehoben |
| `DRY` | Im Dry-Run erkannt, aber nicht gesperrt |

### Sperrgründe

| Grund | Bedeutung |
|---|---|
| `rate-limit` | Gleiche Domain zu oft angefragt |
| `subdomain-flood` | Zu viele eindeutige Subdomains einer Basisdomain |
| `dns-flood-watchlist` | Watchlist-Treffer mit sofortigem Permanent-Ban |
| `external-blocklist` | Sperre aus externer Blocklist |
| `geoip` | GeoIP-Länderfilter |
| `manual` | Manueller Ban oder Unban |
| `manual-flush` | Freigabe durch `flush` |
| `expired` | Temporäre Sperre abgelaufen |
| `external-whitelist` | Freigabe durch externe Whitelist |
| `geoip-flush` | Freigabe aller GeoIP-Sperren |
| `external-blocklist-flush` | Freigabe aller Blocklist-Sperren |

---

## Logs

AdGuard Shield schreibt Daemon-Ereignisse in `LOG_FILE`, standardmäßig:

```text
/var/log/adguard-shield.log
```

### CLI-Befehle

```bash
# Letzte INFO/WARN/ERROR-Einträge
sudo adguard-shield logs

# Letzte 100 Warnungen und Fehler
sudo adguard-shield logs --level warn --limit 100

# Kurzform (Level als Argument)
sudo adguard-shield logs debug

# Laufende Ansicht (wie tail -f)
sudo adguard-shield logs-follow --level info
```

### Erlaubte Log-Level

| Level | Beschreibung |
|---|---|
| `DEBUG` | Detaillierte Informationen für Fehlersuche |
| `INFO` | Normale Betriebsmeldungen (Start, Sperren, Freigaben) |
| `WARN` | Warnungen (z.B. API-Fehler, fehlende Dateien) |
| `ERROR` | Fehler, die den Betrieb beeinträchtigen |

### systemd-Journal

```bash
sudo journalctl -u adguard-shield -f
sudo journalctl -u adguard-shield --no-pager -n 100
```

**Hinweis:** Query-Inhalte werden nicht dauerhaft in die Logdatei geschrieben. Für Query-nahe Diagnose ist die `live`-Ansicht gedacht.

---

## Manuelle Sperren und Freigaben

### IP permanent sperren

```bash
sudo adguard-shield ban 192.168.1.100
```

Legt eine manuelle permanente Sperre an. Die IP wird sofort in die Firewall eingetragen.

### IP entsperren

```bash
sudo adguard-shield unban 192.168.1.100
```

Entfernt die IP aus Firewall und Datenbank. Funktioniert für alle Sperrtypen (automatisch, manuell, GeoIP, Blocklist).

### Alle Sperren aufheben

```bash
sudo adguard-shield flush
```

Hebt alle aktiven Sperren auf. Bei aktivierten Benachrichtigungen wird eine zusammenfassende Meldung gesendet, nicht eine Nachricht pro IP.

**Wichtig:** Whitelist-Regeln gelten auch für manuelle Sperren. Eine IP aus `WHITELIST` oder externer Whitelist wird nicht gesperrt.

---

## Progressive Sperren und Offenses

### Offense-Status anzeigen

```bash
sudo adguard-shield offense-status
```

Zeigt die Gesamtzahl der Offense-Zähler, davon abgelaufene, und die Konfiguration.

### Abgelaufene Zähler entfernen

```bash
sudo adguard-shield offense-cleanup
```

### Alle Offense-Zähler zurücksetzen

```bash
sudo adguard-shield reset-offenses
```

### Zähler für eine IP zurücksetzen

```bash
sudo adguard-shield reset-offenses 192.168.1.100
```

### Typischer Ablauf nach Fehlkonfiguration

Wenn ein Client fälschlicherweise eskaliert wurde:

```bash
# Sperre aufheben
sudo adguard-shield unban 192.168.1.100

# Offense-Zähler zurücksetzen
sudo adguard-shield reset-offenses 192.168.1.100

# IP dauerhaft in Whitelist aufnehmen (in adguard-shield.conf)
# WHITELIST="127.0.0.1,::1,192.168.1.100"
sudo systemctl restart adguard-shield
```

---

## Firewall-Befehle

### Chain und ipsets anlegen

```bash
sudo adguard-shield firewall-create
```

### Status anzeigen

```bash
sudo adguard-shield firewall-status
```

Zeigt die aktuelle Firewall-Struktur: Chain, ipsets und eingehängte Regeln.

### ipsets leeren

```bash
sudo adguard-shield firewall-flush
```

Entfernt alle IPs aus den ipsets. Die Firewall-Struktur (Chain, Regeln) bleibt bestehen.

### Chain und ipsets vollständig entfernen

```bash
sudo adguard-shield firewall-remove
```

### Firewall-Regeln sichern

```bash
sudo adguard-shield firewall-save
```

Speichert die aktuellen Regeln nach:

```text
/var/lib/adguard-shield/iptables-rules.v4
/var/lib/adguard-shield/iptables-rules.v6
```

### Gesicherte Regeln wiederherstellen

```bash
sudo adguard-shield firewall-restore
```

**Hinweis:** Normalerweise musst du diese Befehle nicht manuell ausführen. Der Daemon erstellt die Firewall beim Start und schreibt aktive Sperren aus SQLite wieder hinein. Welche Host-Chain genutzt wird, hängt von `FIREWALL_MODE` ab. Details stehen in [Docker-Installationen](docker.md).

---

## Externe Whitelist

### Status anzeigen

```bash
sudo adguard-shield whitelist-status
```

### Sofort synchronisieren

```bash
sudo adguard-shield whitelist-sync
```

### Aufgelöste externe Whitelist entfernen

```bash
sudo adguard-shield whitelist-flush
```

### Hinweise

- Die externe Whitelist kann IPs, CIDR-Netze und Hostnamen enthalten.
- Hostnamen werden per DNS aufgelöst und als IPs in SQLite gespeichert.
- Eine gewhitelistete IP wird nicht gesperrt.
- Wird eine bereits gesperrte IP später gewhitelistet, wird sie automatisch freigegeben.
- Die dauerhafte Synchronisation läuft im Daemon im konfigurierten Intervall.
- `whitelist-sync` erzwingt nur einen einzelnen, sofortigen Lauf.

---

## Externe Blocklist

### Status anzeigen

```bash
sudo adguard-shield blocklist-status
```

### Sofort synchronisieren

```bash
sudo adguard-shield blocklist-sync
```

### Alle Sperren aus externer Blocklist aufheben

```bash
sudo adguard-shield blocklist-flush
```

### Hinweise

- Die externe Blocklist kann IPs, CIDR-Netze und Hostnamen enthalten.
- Hostnamen werden per DNS aufgelöst.
- IPs aus der Whitelist werden übersprungen.
- Bei `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` hebt der Daemon Blocklist-Sperren automatisch auf, sobald sie nicht mehr in der externen Liste vorkommen.

---

## GeoIP

### Status anzeigen

```bash
sudo adguard-shield geoip-status
```

### Einzelne IP nachschlagen

```bash
sudo adguard-shield geoip-lookup 8.8.8.8
```

**Ausgabe:**

```text
IP: 8.8.8.8 -> Land: US
```

### Aktuelle Clients prüfen

```bash
sudo adguard-shield geoip-sync
```

Liest das aktuelle Querylog und prüft alle darin enthaltenen Client-IPs einmalig gegen die GeoIP-Regeln.

### Alle GeoIP-Sperren aufheben

```bash
sudo adguard-shield geoip-flush
```

### Cache leeren

```bash
sudo adguard-shield geoip-flush-cache
```

### Hinweise

- GeoIP-Sperren sind permanent, werden aber bei Konfigurationsänderungen automatisch neu bewertet.
- Die Ländercodes verwenden ISO 3166-1 Alpha-2 (siehe [ISO-3166-1-Kodierliste auf Wikipedia](https://de.wikipedia.org/wiki/ISO-3166-1-Kodierliste)).

---

## Reports

### Konfiguration und Cron-Status anzeigen

```bash
sudo adguard-shield report-status
```

### HTML-Report in Datei schreiben

```bash
sudo adguard-shield report-generate html /tmp/adguard-shield-report.html
```

### Text-Report auf stdout ausgeben

```bash
sudo adguard-shield report-generate txt
```

### Testmail senden

```bash
sudo adguard-shield report-test
```

Sendet eine einfache Testmail. Erst wenn diese funktioniert, lohnt sich die Fehlersuche am eigentlichen Report.

### Aktuellen Report erzeugen und versenden

```bash
sudo adguard-shield report-send
```

### Cron-Job installieren

```bash
sudo adguard-shield report-install
```

Erstellt die Datei `/etc/cron.d/adguard-shield-report` mit dem konfigurierten Intervall und der Versandzeit. Wenn der globale CLI-Befehl vorhanden ist, verwendet der Cron-Job `/usr/local/bin/adguard-shield`; sonst fällt er auf das installierte Binary unter `/opt/adguard-shield/adguard-shield` zurück.

### Cron-Job entfernen

```bash
sudo adguard-shield report-remove
```

Details zum Report-System stehen in [E-Mail Report](report.md).

---

## Dry-Run

```bash
sudo adguard-shield dry-run
```

Der Dry-Run ist der sicherste Weg, neue Konfigurationen zu prüfen, bevor sie produktiv gehen.

### Verhalten im Dry-Run

| Was passiert | Was nicht passiert |
|---|---|
| Querylogs werden normal gelesen | Keine aktiven Bans werden angelegt |
| Rate-Limit, Subdomain-Flood, Watchlist werden ausgewertet | Keine Firewall-Regeln werden gesetzt |
| GeoIP und externe Blocklist werden geprüft | Keine Benachrichtigungen werden gesendet |
| Mögliche Sperren werden als `DRY` in die History geschrieben | |

### Typischer Ablauf nach größeren Änderungen

```bash
# Dry-Run starten (Strg+C zum Beenden)
sudo adguard-shield dry-run

# Ergebnisse prüfen
sudo adguard-shield history 50
sudo adguard-shield logs --level warn --limit 80
```

---

## Version

```bash
adguard-shield version
```

Zeigt die installierte Version an. Aliase: `--version`, `-v`.

---

## Typische Betriebsabläufe

### Nach Konfigurationsänderung

```bash
sudo systemctl restart adguard-shield
sudo adguard-shield status
sudo adguard-shield logs --level info --limit 80
```

### Falsch gesperrte IP freigeben

```bash
sudo adguard-shield unban 192.168.1.100
sudo adguard-shield reset-offenses 192.168.1.100
```

Danach die IP dauerhaft in `WHITELIST` oder eine externe Whitelist aufnehmen.

### Externe Listen neu laden

```bash
sudo adguard-shield whitelist-sync
sudo adguard-shield blocklist-sync
sudo adguard-shield status
```

### Firewall neu aufbauen

```bash
sudo adguard-shield firewall-remove
sudo adguard-shield firewall-create
sudo systemctl restart adguard-shield
```

Nach dem Neustart schreibt der Daemon aktive Sperren aus SQLite wieder in die Firewall.

### Service-Problem eingrenzen

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
sudo adguard-shield test
sudo adguard-shield logs --level debug --limit 100
```

---

## DNS-Abfragen zum Testen

Die folgenden Befehle sind **ausschließlich für kontrollierte Tests gegen deinen eigenen DNS-Server** gedacht. Ersetze `203.0.113.50` durch deine eigene DNS-Server-IP und `example.com` durch eine Testdomain.

**Nicht gegen fremde DNS-Server, fremde Dienste oder fremde Infrastruktur verwenden.**

### Voraussetzungen auf dem Testclient

| Protokoll | Paket | Installationsbefehl |
|---|---|---|
| Klassisches DNS | `dnsutils` | `sudo apt install dnsutils` |
| DNS-over-HTTPS | `curl` | `sudo apt install curl` |
| DNS-over-TLS | `knot-dnsutils` | `sudo apt install knot-dnsutils` |

### Klassisches DNS: Rate-Limit testen

Gleiche Domain mehrfach abfragen (40 parallele Anfragen):

```bash
for i in {1..40}; do \
  dig @203.0.113.50 example.com +short +cookie=$(openssl rand -hex 8) > /dev/null & \
done; wait
```

### Klassisches DNS: Subdomain-Flood testen

Viele zufällige Subdomains abfragen (60 parallele Anfragen):

```bash
for i in {1..60}; do \
  dig @203.0.113.50 $(openssl rand -hex 6).example.com +short > /dev/null & \
done; wait
```

### DNS-over-HTTPS testen

```bash
for i in {1..40}; do \
  curl -s -H "accept: application/dns-json" \
    "https://203.0.113.50/dns-query?name=example.com&type=A" > /dev/null & \
done; wait
```

Bei selbstsigniertem Zertifikat auf dem eigenen Testserver kann für diesen lokalen Test `-k` ergänzt werden.

### DNS-over-TLS testen

```bash
for i in {1..40}; do \
  kdig @203.0.113.50 example.com +tls +short > /dev/null & \
done; wait
```

Die Beispielzahlen liegen bewusst nahe an den Standardlimits `RATE_LIMIT_MAX_REQUESTS=30` und `SUBDOMAIN_FLOOD_MAX_UNIQUE=50`.

---

## Eingebaute Hilfe

```bash
adguard-shield --help
```

Bei unbekannten Befehlen gibt das Binary die Usage-Ausgabe aus.
