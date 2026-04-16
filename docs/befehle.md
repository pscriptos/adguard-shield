# Befehle & Nutzung

## Installer / Updater

Der Installer bietet ein interaktives Menü wenn er ohne Argumente aufgerufen wird:

```bash
# Interaktives Menü anzeigen
sudo bash install.sh

# Neuinstallation
sudo bash install.sh install

# Update (mit automatischer Konfigurations-Migration)
sudo bash install.sh update

# Deinstallation (delegiert automatisch an den installierten Uninstaller)
sudo bash install.sh uninstall

# Installationsstatus anzeigen
sudo bash install.sh status

# Hilfe anzeigen
sudo bash install.sh --help
```

## Uninstaller (eigenständig)

Ab Version 0.5.2 wird bei der Installation ein eigenständiger Uninstaller nach `/opt/adguard-shield/uninstall.sh` kopiert. Die Deinstallation kann damit **ohne die originalen Installationsdateien** durchgeführt werden:

```bash
# Direkt aus dem Installationsverzeichnis — kein install.sh benötigt
sudo bash /opt/adguard-shield/uninstall.sh
```

Der Uninstaller kennt seinen Speicherort und leitet daraus automatisch das Installationsverzeichnis ab. `install.sh uninstall` delegiert intern ebenfalls dorthin — beide Wege führen zum selben Ergebnis.

### Update-Verhalten

Beim Update passiert automatisch:
1. Alle Scripts werden aktualisiert
2. Die bestehende Konfiguration wird als `adguard-shield.conf.old` gesichert
3. Neue Konfigurationsparameter werden automatisch zur bestehenden Konfig hinzugefügt
4. Bestehende Einstellungen bleiben **immer** erhalten
5. Der systemd Service und Watchdog-Timer werden per `daemon-reload` neu geladen
6. Der Watchdog-Timer wird automatisch aktiviert (falls noch nicht aktiv)
7. Der Service wird automatisch neu gestartet (falls er lief)

### API-Verbindungstest nach Installation

Nach der Installation wird automatisch ein **zweistufiger Verbindungstest** durchgeführt:

1. **Base-URL Erreichbarkeit** — Prüft ob die konfigurierte `ADGUARD_URL` erreichbar ist (DNS, TCP, HTTP). Bei Fehlern werden spezifische Hinweise angezeigt (z.B. DNS-Fehler, Timeout, SSL-Problem).
2. **API-Authentifizierung** — Testet ob die hinterlegten Zugangsdaten (`ADGUARD_USER` / `ADGUARD_PASS`) korrekt sind, indem der API-Endpunkt `/control/querylog` abgefragt wird.

> **Hinweis:** Dieser Test kann auch jederzeit manuell ausgeführt werden:
> ```bash
> sudo /opt/adguard-shield/adguard-shield.sh test
> ```

### Voraussetzungen

Folgende Pakete werden bei der Installation automatisch installiert (via `apt`):
- `curl` — API-Kommunikation mit AdGuard Home
- `jq` — JSON-Verarbeitung der API-Antworten
- `iptables` — Firewall-Regeln für IP-Sperren
- `gawk` — Textverarbeitung
- `systemd` — Service-Management

## systemd Service

AdGuard Shield wird als systemd Service betrieben. **Zum Starten, Stoppen und Neustarten immer `systemctl` verwenden:**

```bash
# Start / Stop / Restart
sudo systemctl start adguard-shield
sudo systemctl stop adguard-shield
sudo systemctl restart adguard-shield

# Status
sudo systemctl status adguard-shield

# Autostart aktivieren / deaktivieren
sudo systemctl enable adguard-shield
sudo systemctl disable adguard-shield
```

> **Hinweis:** Der Service wird bei der Installation automatisch für den Autostart beim Booten aktiviert. Nach einem Update wird der Service automatisch neu gestartet — ein manueller Neustart ist nicht nötig.

## Watchdog (automatischer Health Check)

Der Watchdog prüft alle 5 Minuten ob der Hauptservice läuft und startet ihn bei Bedarf automatisch neu. Er wird als systemd Timer betrieben und bei der Installation automatisch aktiviert.

```bash
# Watchdog-Status
sudo systemctl status adguard-shield-watchdog.timer

# Nächste geplante Ausführung anzeigen
sudo systemctl list-timers adguard-shield-watchdog.timer

# Watchdog aktivieren / deaktivieren
sudo systemctl enable adguard-shield-watchdog.timer
sudo systemctl disable adguard-shield-watchdog.timer

# Watchdog starten / stoppen
sudo systemctl start adguard-shield-watchdog.timer
sudo systemctl stop adguard-shield-watchdog.timer

# Watchdog-Logs anzeigen
sudo journalctl -u adguard-shield-watchdog.service --no-pager -n 20
```

> **Hinweis:** Der Watchdog sendet automatisch Benachrichtigungen (falls `NOTIFY_ENABLED=true`), wenn er den Service wiederbeleben muss oder die Recovery fehlschlägt.

## Monitor — Verwaltungsbefehle

Die folgenden Befehle dienen der **Verwaltung und Diagnose** und können jederzeit ausgeführt werden, auch während der Service läuft:

```bash
# Status + aktive Sperren anzeigen
sudo /opt/adguard-shield/adguard-shield.sh status

# Ban-History anzeigen (letzte 50 Einträge)
sudo /opt/adguard-shield/adguard-shield.sh history

# Ban-History anzeigen (letzte 100 Einträge)
sudo /opt/adguard-shield/adguard-shield.sh history 100

# Alle Sperren aufheben
sudo /opt/adguard-shield/adguard-shield.sh flush

# Einzelne IP entsperren
sudo /opt/adguard-shield/adguard-shield.sh unban 192.168.1.100

# API-Verbindung testen
sudo /opt/adguard-shield/adguard-shield.sh test

# Dry-Run (nur loggen, nichts sperren — läuft im Vordergrund!)
sudo /opt/adguard-shield/adguard-shield.sh dry-run

# Offense-Zähler für alle IPs zurücksetzen (Progressive Sperren)
sudo /opt/adguard-shield/adguard-shield.sh reset-offenses

# Offense-Zähler für eine bestimmte IP zurücksetzen
sudo /opt/adguard-shield/adguard-shield.sh reset-offenses 192.168.1.100

# Externe Blocklist - Status anzeigen
sudo /opt/adguard-shield/adguard-shield.sh blocklist-status

# Externe Blocklist - Einmalige Synchronisation
sudo /opt/adguard-shield/adguard-shield.sh blocklist-sync

# Externe Blocklist - Alle Sperren der externen Liste aufheben
sudo /opt/adguard-shield/adguard-shield.sh blocklist-flush
```

> **⚠ Wichtig:** Zum Starten und Stoppen des Monitors **nicht** `adguard-shield.sh start` bzw. `stop` verwenden! Diese Befehle starten den Prozess im **Vordergrund** — die Ausgabe wird live angezeigt und `Strg+C` beendet den gesamten Prozess. Stattdessen immer `sudo systemctl start/stop/restart adguard-shield` nutzen.

## iptables Helper

Für die manuelle Verwaltung der Firewall-Regeln:

```bash
# Chain erstellen
sudo /opt/adguard-shield/iptables-helper.sh create

# Alle Regeln anzeigen
sudo /opt/adguard-shield/iptables-helper.sh status

# IP manuell sperren
sudo /opt/adguard-shield/iptables-helper.sh ban 192.168.1.100

# IP entsperren
sudo /opt/adguard-shield/iptables-helper.sh unban 192.168.1.100

# Alle Regeln leeren
sudo /opt/adguard-shield/iptables-helper.sh flush

# Chain komplett entfernen
sudo /opt/adguard-shield/iptables-helper.sh remove

# Regeln speichern / wiederherstellen
sudo /opt/adguard-shield/iptables-helper.sh save
sudo /opt/adguard-shield/iptables-helper.sh restore
```

## Externer Whitelist-Worker

Der Whitelist-Worker löst Domains aus externen Listen regelmäßig per DNS auf und stellt die IPs als dynamische Whitelist bereit:

```bash
# Status anzeigen (aufgelöste IPs, konfigurierte Listen)
sudo /opt/adguard-shield/adguard-shield.sh whitelist-status

# Einmalige Synchronisation (z.B. nach Konfigurationsänderung)
sudo /opt/adguard-shield/adguard-shield.sh whitelist-sync

# Alle aufgelösten Whitelist-IPs entfernen
sudo /opt/adguard-shield/adguard-shield.sh whitelist-flush
```

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-shield/external-whitelist-worker.sh start

# Worker stoppen
sudo /opt/adguard-shield/external-whitelist-worker.sh stop

# Einmalige Synchronisation
sudo /opt/adguard-shield/external-whitelist-worker.sh sync

# Status anzeigen
sudo /opt/adguard-shield/external-whitelist-worker.sh status

# Aufgelöste IPs entfernen
sudo /opt/adguard-shield/external-whitelist-worker.sh flush
```

## Externer Blocklist-Worker

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-shield/external-blocklist-worker.sh start

# Worker stoppen
sudo /opt/adguard-shield/external-blocklist-worker.sh stop

# Einmalige Synchronisation (z.B. nach Konfigurationsänderung)
sudo /opt/adguard-shield/external-blocklist-worker.sh sync

# Status anzeigen
sudo /opt/adguard-shield/external-blocklist-worker.sh status

# Alle externen Sperren aufheben
sudo /opt/adguard-shield/external-blocklist-worker.sh flush
```

## GeoIP-Worker (Länderfilter)

Der GeoIP-Worker prüft Client-IPs auf ihr Herkunftsland und sperrt/erlaubt sie basierend auf der Konfiguration:

```bash
# GeoIP-Status anzeigen (Modus, Länder, aktive Sperren, verfügbare Tools)
sudo /opt/adguard-shield/adguard-shield.sh geoip-status

# Einmalige GeoIP-Prüfung aller aktiven Clients
sudo /opt/adguard-shield/adguard-shield.sh geoip-sync

# Alle GeoIP-Sperren aufheben
sudo /opt/adguard-shield/adguard-shield.sh geoip-flush

# GeoIP-Lookup für eine einzelne IP
sudo /opt/adguard-shield/adguard-shield.sh geoip-lookup 8.8.8.8
```

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-shield/geoip-worker.sh start

# Worker stoppen
sudo /opt/adguard-shield/geoip-worker.sh stop

# Einmalige Synchronisation
sudo /opt/adguard-shield/geoip-worker.sh sync

# Status anzeigen
sudo /opt/adguard-shield/geoip-worker.sh status

# IP nachschlagen
sudo /opt/adguard-shield/geoip-worker.sh lookup 1.2.3.4

# Alle GeoIP-Sperren aufheben
sudo /opt/adguard-shield/geoip-worker.sh flush

# GeoIP-Lookup-Cache leeren
sudo /opt/adguard-shield/geoip-worker.sh flush-cache
```

## Offense-Cleanup-Worker

Der Offense-Cleanup-Worker räumt abgelaufene Offense-Zähler (progressive Sperren) automatisch auf. Er startet automatisch mit dem Hauptservice, wenn progressive Sperren aktiviert sind, und prüft stündlich ob Zähler aufgeräumt werden können. Der Worker läuft mit niedrigster CPU- und I/O-Priorität (`nice 19`, `ionice idle`), um den DNS-Dienst nicht zu beeinträchtigen.

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-shield/offense-cleanup-worker.sh start

# Worker stoppen
sudo /opt/adguard-shield/offense-cleanup-worker.sh stop

# Einmaliger Cleanup-Durchlauf
sudo /opt/adguard-shield/offense-cleanup-worker.sh run-once

# Status anzeigen (aktive/abgelaufene Zähler)
sudo /opt/adguard-shield/offense-cleanup-worker.sh status
```

## E-Mail Report

```bash
# Report sofort generieren und per E-Mail versenden
sudo /opt/adguard-shield/report-generator.sh send

# Test-E-Mail senden (prüft alle Voraussetzungen + Mailversand)
sudo /opt/adguard-shield/report-generator.sh test

# Report als Datei generieren (Ausgabe auf stdout)
sudo /opt/adguard-shield/report-generator.sh generate

# Report im HTML-Format in Datei speichern
sudo /opt/adguard-shield/report-generator.sh generate html > report.html

# Report im TXT-Format in Datei speichern
sudo /opt/adguard-shield/report-generator.sh generate txt > report.txt

# Cron-Job für automatischen Versand einrichten
sudo /opt/adguard-shield/report-generator.sh install

# Cron-Job entfernen
sudo /opt/adguard-shield/report-generator.sh remove

# Report-Konfiguration und Cron-Status anzeigen
sudo /opt/adguard-shield/report-generator.sh status
```

> Voraussetzung: Ein funktionierender Mail-Transport (z.B. msmtp). Anleitung: [Linux: Einfach E-Mails versenden mit msmtp](https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/)

## Logs

```bash
# systemd Journal
sudo journalctl -u adguard-shield -f

# Log-Datei direkt
sudo tail -f /var/log/adguard-shield.log

# Nur Sperr-Einträge
sudo grep "SPERRE" /var/log/adguard-shield.log

# Nur Entsperr-Einträge
sudo grep "ENTSPERRE" /var/log/adguard-shield.log
```

## Cron-basiertes Entsperren

Als Alternative oder Ergänzung zum Haupt-Monitor:

```bash
# Crontab bearbeiten
sudo crontab -e

# Alle 5 Minuten abgelaufene Sperren prüfen
*/5 * * * * /opt/adguard-shield/unban-expired.sh
```

## DNS-Abfragen zum Testen (von einem Linux-Client)

> **⚠ WARNUNG — Bitte unbedingt lesen:**
>
> Die folgenden Befehle dienen **ausschließlich zu Testzwecken**, um die eigene AdGuard-Shield-Installation zu überprüfen. Sie simulieren erhöhtes DNS-Aufkommen und können dazu genutzt werden, die Erkennungs- und Sperrmechanismen zu validieren.
>
> **DNS-Flooding ist illegal!** Das massenhafte Senden von DNS-Anfragen an fremde Server oder Infrastruktur ohne ausdrückliche Genehmigung kann als **Denial-of-Service-Angriff (DoS)** gewertet werden und ist in den meisten Ländern **strafbar**. Die Konsequenzen reichen von Abmahnungen über Strafanzeigen bis hin zu empfindlichen Geld- und Freiheitsstrafen.
>
> **Diese Befehle dürfen nur gegen den eigenen DNS-Server in einer kontrollierten Testumgebung eingesetzt werden.** Die Nutzung gegen fremde Server ist ausdrücklich untersagt. Jede Verantwortung liegt beim Anwender.

### Voraussetzungen

Die folgenden Tools müssen auf dem **Linux-Client** installiert sein (nicht auf dem Server):

```bash
# Für DNS-Abfragen (dig)
sudo apt install dnsutils

# Für DoH-Abfragen (curl)
sudo apt install curl

# Für DoT-Abfragen (knotc)
sudo apt install knot-dnsutils

# Für DoQ-Abfragen
# https://github.com/natesales/q — Releases herunterladen oder via Go installieren:
go install github.com/natesales/q@latest
```

> **Hinweis:** In den folgenden Befehlen muss die IP-Adresse `203.0.113.50` durch die **eigene DNS-Server-IP** und `microsoft.com` durch die gewünschte **Ziel-Domain** ersetzt werden.

---

### Klassisches DNS (Port 53/UDP)

#### Direkte Abfragen (gleiche Domain, viele Anfragen)

200 parallele DNS-Anfragen für dieselbe Domain — jede mit einem zufälligen DNS-Cookie, um Caching zu umgehen:

```bash
for i in {1..200}; do \
  dig @203.0.113.50 microsoft.com +short +cookie=$(openssl rand -hex 8) > /dev/null & \
done; wait
```

#### Zufällige Subdomain-Abfragen (NXDOMAIN-Flood)

200 parallele Anfragen mit zufällig generierten Subdomains — simuliert typisches Verhalten von DNS-basierten Angriffen:

```bash
for i in {1..200}; do \
  dig @203.0.113.50 $(openssl rand -hex 6).microsoft.com +short > /dev/null & \
done; wait
```

---

### DNS over HTTPS (DoH)

DoH-Anfragen werden über HTTPS (Port 443) gesendet. Die meisten AdGuard-Home-Instanzen bieten DoH unter `/dns-query` an:

#### Direkte Abfragen via DoH

```bash
for i in {1..200}; do \
  curl -s -H "accept: application/dns-json" \
    "https://203.0.113.50/dns-query?name=microsoft.com&type=A" > /dev/null & \
done; wait
```

#### Zufällige Subdomain-Abfragen via DoH

```bash
for i in {1..200}; do \
  curl -s -H "accept: application/dns-json" \
    "https://203.0.113.50/dns-query?name=$(openssl rand -hex 6).microsoft.com&type=A" > /dev/null & \
done; wait
```

> **Hinweis:** Falls der Server ein selbstsigniertes Zertifikat verwendet, muss `-k` (unsicherer Modus) an `curl` angehängt werden.

---

### DNS over TLS (DoT)

DoT verwendet TLS über Port 853. Mit `kdig` (aus dem Paket `knot-dnsutils`):

#### Direkte Abfragen via DoT

```bash
for i in {1..200}; do \
  kdig @203.0.113.50 microsoft.com +tls +short > /dev/null & \
done; wait
```

#### Zufällige Subdomain-Abfragen via DoT

```bash
for i in {1..200}; do \
  kdig @203.0.113.50 $(openssl rand -hex 6).microsoft.com +tls +short > /dev/null & \
done; wait
```

---

### DNS over QUIC (DoQ)

DoQ verwendet das QUIC-Protokoll über Port 853/UDP. Mit dem Tool [`q`](https://github.com/natesales/q):

#### Direkte Abfragen via DoQ

```bash
for i in {1..200}; do \
  q microsoft.com A @quic://203.0.113.50 --short > /dev/null & \
done; wait
```

#### Zufällige Subdomain-Abfragen via DoQ

```bash
for i in {1..200}; do \
  q $(openssl rand -hex 6).microsoft.com A @quic://203.0.113.50 --short > /dev/null & \
done; wait
```

---

> **⚠ Abschließender Hinweis:** Alle oben genannten Befehle sind **ausschließlich für das Testen der eigenen Infrastruktur** gedacht. Wer diese Befehle gegen fremde DNS-Server oder Dienste einsetzt, macht sich unter Umständen **strafbar**. Sei verantwortungsvoll — teste nur, was dir gehört.

## Hilfe

Alle verfügbaren Befehle und Optionen des Installers anzeigen:

```bash
sudo bash install.sh --help
sudo bash install.sh -h
```
