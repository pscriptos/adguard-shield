# E-Mail Report

AdGuard Shield kann Statistik-Reports direkt aus der SQLite-Datenbank erzeugen und per E-Mail versenden. Es gibt in der Go-Version keinen separaten `report-generator.sh` mehr.

## Was der Report enthält

Der Report basiert auf der SQLite-Datenbank:

```text
/var/lib/adguard-shield/adguard-shield.db
```

### Ausgewertete Daten

| Bereich | Inhalt |
|---|---|
| Zeitraum | Start- und Enddatum des Berichtszeitraums |
| Sperren | Anzahl der Sperren im Zeitraum |
| Freigaben | Anzahl der Freigaben im Zeitraum |
| Aktive Sperren | Derzeit aktive Sperren zum Zeitpunkt der Report-Erstellung |
| Top-Clients | Die am häufigsten gesperrten Client-IPs |
| Sperrgründe | Aufschlüsselung nach Grund (Rate-Limit, Subdomain-Flood, GeoIP usw.) |
| Sperrquellen | Aufschlüsselung nach Quelle (Monitor, GeoIP, Blocklist, manuell) |
| Letzte Ereignisse | Die letzten 20 Einträge aus der Ban-History |

---

## Konfiguration

| Parameter | Standard | Beschreibung |
|---|---|---|
| `REPORT_ENABLED` | `false` | Report-Funktion logisch aktivieren |
| `REPORT_INTERVAL` | `weekly` | Versandintervall |
| `REPORT_TIME` | `08:00` | Versandzeit im Format `HH:MM` |
| `REPORT_EMAIL_TO` | `admin@example.com` | Empfängeradresse |
| `REPORT_EMAIL_FROM` | `adguard-shield@example.com` | Absenderadresse |
| `REPORT_FORMAT` | `html` | Report-Format (`html` oder `txt`) |
| `REPORT_MAIL_CMD` | `msmtp` | Mailprogramm für den Versand |
| `REPORT_BUSIEST_DAY_RANGE` | `30` | Kompatibilitätsparameter für den Zeitraum "Aktivster Tag" |

### Versandintervalle

| Intervall | Versandzeitpunkt |
|---|---|
| `daily` | Täglich zur Uhrzeit aus `REPORT_TIME` |
| `weekly` | Montags zur Uhrzeit aus `REPORT_TIME` |
| `biweekly` | Am 1. und 15. des Monats zur Uhrzeit aus `REPORT_TIME` |
| `monthly` | Am 1. des Monats zur Uhrzeit aus `REPORT_TIME` |

### Formate

| Format | Beschreibung | Empfehlung |
|---|---|---|
| `html` | HTML-formatierte E-Mail mit Tabellen und Formatierung | Standard-Mail-Clients |
| `txt` | Reiner Text ohne Formatierung | Einfache Mail-Setups, Log-Ablage |

### Beispielkonfiguration

```bash
REPORT_ENABLED=true
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
```

---

## Befehle

### Konfiguration und Cron-Status anzeigen

```bash
sudo /opt/adguard-shield/adguard-shield report-status
```

### HTML-Report in Datei schreiben

```bash
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html
```

Die Datei kann im Browser geöffnet werden, um das Ergebnis zu prüfen.

### Text-Report auf stdout ausgeben

```bash
sudo /opt/adguard-shield/adguard-shield report-generate txt
```

### Testmail senden

```bash
sudo /opt/adguard-shield/adguard-shield report-test
```

Sendet eine einfache Testmail. Erst wenn diese ankommt, lohnt sich die Fehlersuche am eigentlichen Report.

### Aktuellen Report erzeugen und versenden

```bash
sudo /opt/adguard-shield/adguard-shield report-send
```

### Cron-Job installieren

```bash
sudo /opt/adguard-shield/adguard-shield report-install
```

### Cron-Job entfernen

```bash
sudo /opt/adguard-shield/adguard-shield report-remove
```

---

## Mailversand

AdGuard Shield übergibt die fertige Mail an ein lokales Mailprogramm. Der Standard ist:

```bash
REPORT_MAIL_CMD="msmtp"
```

### Einrichtung mit msmtp

```bash
# msmtp installieren
sudo apt install msmtp msmtp-mta

# Testmail senden
sudo /opt/adguard-shield/adguard-shield report-test
```

### Eigene Mailprogramm-Argumente

Wenn dein Mailprogramm zusätzliche Argumente braucht, können sie in `REPORT_MAIL_CMD` stehen. AdGuard Shield hängt intern `-t` an, damit Empfänger und Header aus der generierten Mail gelesen werden.

```bash
REPORT_MAIL_CMD="msmtp --account=default"
```

### Alternativen zu msmtp

| Programm | `REPORT_MAIL_CMD` |
|---|---|
| msmtp | `msmtp` |
| sendmail | `sendmail` |
| ssmtp | `ssmtp` |
| Benutzerdefiniert | Vollständiger Pfad zum Programm |

---

## Automatischer Versand

### Cron-Job installieren

```bash
sudo /opt/adguard-shield/adguard-shield report-install
```

Dadurch wird diese Datei geschrieben:

```text
/etc/cron.d/adguard-shield-report
```

Der Cron-Eintrag ruft das installierte Binary mit der installierten Konfiguration auf:

```text
/opt/adguard-shield/adguard-shield -config /opt/adguard-shield/adguard-shield.conf report-send
```

### Zeitplan nach Intervall

| Intervall | Cron-Verhalten |
|---|---|
| `daily` | Täglich zur Uhrzeit aus `REPORT_TIME` |
| `weekly` | Montags zur Uhrzeit aus `REPORT_TIME` |
| `biweekly` | Am 1. und 15. des Monats |
| `monthly` | Am 1. des Monats |

### Cron-Job entfernen

```bash
sudo /opt/adguard-shield/adguard-shield report-remove
```

---

## Manuelle Prüfung

### Schritt 1: Status prüfen

```bash
sudo /opt/adguard-shield/adguard-shield report-status
```

### Schritt 2: Report lokal erzeugen

```bash
# HTML-Report zum Ansehen im Browser
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html

# Text-Report in der Konsole
sudo /opt/adguard-shield/adguard-shield report-generate txt
```

### Schritt 3: Versand testen

```bash
# Einfache Testmail
sudo /opt/adguard-shield/adguard-shield report-test

# Vollständigen Report senden
sudo /opt/adguard-shield/adguard-shield report-send
```

### Schritt 4: Logs prüfen

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo journalctl -u cron --no-pager -n 100
```

Je nach Distribution heißt der Cron-Service `cron`, `crond` oder wird über das allgemeine Syslog protokolliert.

---

## Häufige Probleme

### `REPORT_EMAIL_TO ist leer`

Setze einen Empfänger in der Konfiguration:

```bash
REPORT_EMAIL_TO="admin@example.com"
```

### Mailprogramm nicht gefunden

Prüfe, ob das Mailprogramm installiert ist:

```bash
which msmtp
```

Installiere es bei Bedarf:

```bash
sudo apt install msmtp msmtp-mta
```

Oder setze `REPORT_MAIL_CMD` auf dein vorhandenes Mailprogramm.

### Cron läuft, aber keine Mail kommt an

Prüfe die Konfiguration und den Cron-Job:

```bash
sudo /opt/adguard-shield/adguard-shield report-send
sudo cat /etc/cron.d/adguard-shield-report
```

**Checkliste:**

| Prüfpunkt | Beschreibung |
|---|---|
| Empfänger | `REPORT_EMAIL_TO` korrekt gesetzt? |
| Mailprogramm | `REPORT_MAIL_CMD` im Cron-PATH verfügbar? |
| Root-Konfiguration | Mailer für root konfiguriert? (msmtp benötigt `/root/.msmtprc` oder `/etc/msmtprc`) |
| Spam | Spam-Ordner geprüft? |
| SMTP | Ausgehende SMTP-Verbindungen erlaubt? (Port 587/465) |

### Format beim Generieren überschreiben

Du kannst das Format unabhängig von der Konfiguration wählen:

```bash
sudo /opt/adguard-shield/adguard-shield report-generate txt
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/report.html
```
