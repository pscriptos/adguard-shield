# E-Mail Report

AdGuard Shield kann Statistik-Reports direkt aus der SQLite-Datenbank erzeugen und per E-Mail versenden. Es gibt in der Go-Version keinen separaten `report-generator.sh` mehr.

## Was der Report enthält

Der Report basiert auf:

```text
/var/lib/adguard-shield/adguard-shield.db
```

Ausgewertet werden vor allem:

- `ban_history`
- `active_bans`

Inhalte:

- Zeitraum des Reports
- Anzahl Sperren im Zeitraum
- Anzahl Freigaben im Zeitraum
- aktuell aktive Sperren
- Top-Clients
- Gründe der Sperren
- Quellen aktiver Sperren
- letzte Ereignisse aus der History

## Konfiguration

```bash
REPORT_ENABLED=false
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
REPORT_BUSIEST_DAY_RANGE=30
```

Parameter:

| Parameter | Bedeutung |
|---|---|
| `REPORT_ENABLED` | dokumentiert, ob Reports gewünscht sind; der Cron-Job wird über `report-install` angelegt |
| `REPORT_INTERVAL` | `daily`, `weekly`, `biweekly` oder `monthly` |
| `REPORT_TIME` | Uhrzeit im Format `HH:MM` |
| `REPORT_EMAIL_TO` | Empfängeradresse |
| `REPORT_EMAIL_FROM` | Absenderadresse |
| `REPORT_FORMAT` | `html` oder `txt` |
| `REPORT_MAIL_CMD` | Mailprogramm, z.B. `msmtp` |
| `REPORT_BUSIEST_DAY_RANGE` | Kompatibilitätsparameter für den Zeitraum "Aktivster Tag" |

Beispiel:

```bash
REPORT_ENABLED=true
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
```

## Befehle

```bash
# Konfiguration und Cron-Status anzeigen
sudo /opt/adguard-shield/adguard-shield report-status

# HTML-Report in Datei schreiben
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html

# Text-Report auf stdout ausgeben
sudo /opt/adguard-shield/adguard-shield report-generate txt

# Testmail senden
sudo /opt/adguard-shield/adguard-shield report-test

# aktuellen Report erzeugen und versenden
sudo /opt/adguard-shield/adguard-shield report-send

# Cron-Job installieren
sudo /opt/adguard-shield/adguard-shield report-install

# Cron-Job entfernen
sudo /opt/adguard-shield/adguard-shield report-remove
```

## Mailversand

AdGuard Shield übergibt die fertige Mail an ein lokales Mailprogramm. Der Standard ist:

```bash
REPORT_MAIL_CMD="msmtp"
```

Minimaler Ablauf mit `msmtp`:

```bash
sudo apt install msmtp msmtp-mta
sudo /opt/adguard-shield/adguard-shield report-test
```

`report-test` sendet eine einfache Testmail. Erst wenn diese funktioniert, lohnt sich die Fehlersuche am eigentlichen Report.

Wenn dein Mailprogramm zusätzliche Argumente braucht, können sie in `REPORT_MAIL_CMD` stehen. AdGuard Shield hängt intern `-t` an, damit Empfänger und Header aus der generierten Mail gelesen werden.

Beispiel:

```bash
REPORT_MAIL_CMD="msmtp --account=default"
```

## Automatischer Versand

Cron installieren:

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

Zeitplan nach `REPORT_INTERVAL`:

| Intervall | Cron-Verhalten |
|---|---|
| `daily` | täglich zur Uhrzeit aus `REPORT_TIME` |
| `weekly` | montags zur Uhrzeit aus `REPORT_TIME` |
| `biweekly` | am 1. und 15. des Monats |
| `monthly` | am 1. des Monats |

Cron entfernen:

```bash
sudo /opt/adguard-shield/adguard-shield report-remove
```

## Manuelle Prüfung

Status:

```bash
sudo /opt/adguard-shield/adguard-shield report-status
```

Report lokal erzeugen:

```bash
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html
sudo /opt/adguard-shield/adguard-shield report-generate txt
```

Versand testen:

```bash
sudo /opt/adguard-shield/adguard-shield report-test
sudo /opt/adguard-shield/adguard-shield report-send
```

Logs:

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo journalctl -u cron --no-pager -n 100
```

Je nach Distribution heißt der Cron-Service auch `cron`, `crond` oder wird über das allgemeine Syslog protokolliert.

## Häufige Probleme

### `REPORT_EMAIL_TO ist leer`

Setze einen Empfänger:

```bash
REPORT_EMAIL_TO="admin@example.com"
```

### Mailprogramm nicht gefunden

Prüfen:

```bash
which msmtp
```

Installieren:

```bash
sudo apt install msmtp msmtp-mta
```

Oder `REPORT_MAIL_CMD` auf dein vorhandenes Mailprogramm setzen.

### Cron läuft, aber keine Mail kommt an

Prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield report-send
sudo cat /etc/cron.d/adguard-shield-report
```

Achte darauf, dass:

- `REPORT_EMAIL_TO` stimmt
- `REPORT_MAIL_CMD` im Cron-PATH verfügbar ist
- der lokale Mailer für root konfiguriert ist
- Spam-Ordner geprüft wurde
- ausgehende SMTP-Verbindungen erlaubt sind

## HTML und TXT

HTML ist für normale E-Mail-Clients angenehmer zu lesen:

```bash
REPORT_FORMAT="html"
```

TXT ist robuster für sehr einfache Mail-Setups oder Log-Ablage:

```bash
REPORT_FORMAT="txt"
```

Du kannst das Format beim manuellen Generieren überschreiben:

```bash
sudo /opt/adguard-shield/adguard-shield report-generate txt
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/report.html
```
