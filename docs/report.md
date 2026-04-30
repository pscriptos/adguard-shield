# E-Mail Report

AdGuard Shield kann regelmäßig einen Statistik-Report per E-Mail versenden. Der Report enthält eine Übersicht über alle Sperren, die auffälligsten IPs, meistbetroffene Domains und weitere Statistiken.

## Voraussetzungen

Der Server muss E-Mails versenden können. Empfohlen wird **msmtp** als leichtgewichtiger SMTP-Client.

**Anleitung zur Einrichtung von msmtp:**
👉 [Linux: Einfach E-Mails versenden mit msmtp](https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/)

Alternativ funktioniert auch `sendmail`, `mail` oder ein anderer Befehl, der E-Mails über stdin entgegennimmt.

## Aktivierung

In der Konfiguration (`adguard-shield.conf`):

```bash
REPORT_ENABLED=true
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
```

Anschließend den Cron-Job einrichten:

```bash
sudo /opt/adguard-shield/report-generator.sh install
```

## Konfigurationsparameter

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `REPORT_ENABLED` | `false` | Report-Funktion aktivieren |
| `REPORT_INTERVAL` | `weekly` | Versandintervall (siehe unten) |
| `REPORT_TIME` | `08:00` | Uhrzeit für den Versand (HH:MM, 24h) |
| `REPORT_EMAIL_TO` | *(leer)* | E-Mail-Empfänger |
| `REPORT_EMAIL_FROM` | `adguard-shield@hostname` | E-Mail-Absender |
| `REPORT_FORMAT` | `html` | Format: `html` oder `txt` |
| `REPORT_MAIL_CMD` | `msmtp` | Mail-Befehl (`msmtp`, `sendmail`, `mail`) |
| `REPORT_BUSIEST_DAY_RANGE` | `30` | Zeitraum in Tagen für „Aktivster Tag“ (0 = Berichtszeitraum) |

### Versandintervalle

| Wert | Beschreibung |
|------|-------------|
| `daily` | Täglich zur konfigurierten Uhrzeit |
| `weekly` | Wöchentlich am Montag |
| `biweekly` | Alle zwei Wochen am Montag |
| `monthly` | Monatlich am 1. des Monats |

## Report-Inhalte

Der Report enthält folgende Statistiken:

### Zeitraum-Schnellübersicht *(immer ganz oben)*

Eine Vergleichstabelle mit Live-Zahlen für vier feste Zeitfenster – unabhängig vom konfigurierten `REPORT_INTERVAL`:

| Zeitraum | Sperren | Entsperrungen | Eindeutige IPs | Permanent gebannt |
|----------|---------|---------------|----------------|-------------------|
| Heute *(nur nach 20:00 Uhr)* | … | … | … | … |
| Gestern | … | … | … | … |
| Letzte 7 Tage | … | … | … | … |
| Letzte 14 Tage | … | … | … | … |
| Letzte 30 Tage | … | … | … | … |

Im HTML-Format wird **Gestern** grün hervorgehoben, **Heute** blau (erscheint nur ab 20:00 Uhr).  
- **Gestern** umfasst exakt 00:00:00 – 23:59:59 des gestrigen Tages.  
- **Heute** umfasst den laufenden Tag von 00:00:00 bis zum Zeitpunkt der Reportgenerierung und wird nur eingeblendet, wenn der Report nach 20:00 Uhr erstellt wird.  
Die übrigen Zeiträume laufen vom Starttag 00:00 Uhr bis zum Zeitpunkt der Reportgenerierung.

> **Hinweis:** Die AbuseIPDB-Meldungen werden in der Schnellübersicht nicht mehr separat ausgewiesen, da sie immer mit einer Permanentsperre korrelieren – der Wert „Permanent gebannt" ist daher ausreichend. Die Gesamtanzahl der AbuseIPDB-Reports im Berichtszeitraum ist weiterhin in der allgemeinen Übersicht sichtbar.

### Übersicht (Berichtszeitraum)
- Gesamtzahl der Sperren und Entsperrungen
- Anzahl eindeutiger gesperrter IPs
- Permanente Sperren
- Aktuell aktive Sperren
- AbuseIPDB-Reports

### Angriffsarten
- Rate-Limit Sperren
- Subdomain-Flood Sperren
- Externe Blocklist Sperren
- Aktivster Tag – wird über einen konfigurierbaren Zeitraum ermittelt (Standard: letzte 30 Tage, `REPORT_BUSIEST_DAY_RANGE`). Zeigt zusätzlich die Anzahl der Sperren an diesem Tag. Bei `REPORT_BUSIEST_DAY_RANGE=0` wird nur der Berichtszeitraum betrachtet.

### Top 10 Listen
- **Auffälligste IPs** — Die 10 IPs mit den meisten Sperren (mit Balkendiagramm im HTML-Format)
- **Meistbetroffene Domains** — Die 10 am häufigsten betroffenen Domains

### Weitere Details
- **Protokoll-Verteilung** — Aufschlüsselung nach DNS, DoH, DoT, DoQ
- **Letzte 10 Sperren** — Die aktuellsten Sperrereignisse mit Zeitstempel, IP, Domain und Grund

## Befehle

```bash
# Report sofort generieren und versenden
sudo /opt/adguard-shield/report-generator.sh send

# Test-E-Mail senden (prüft alle Voraussetzungen + Mailversand)
sudo /opt/adguard-shield/report-generator.sh test

# Report als Datei generieren (auf stdout ausgeben)
sudo /opt/adguard-shield/report-generator.sh generate

# Report im spezifischen Format generieren
sudo /opt/adguard-shield/report-generator.sh generate html > report.html
sudo /opt/adguard-shield/report-generator.sh generate txt > report.txt

# Cron-Job für automatischen Versand einrichten
sudo /opt/adguard-shield/report-generator.sh install

# Cron-Job entfernen
sudo /opt/adguard-shield/report-generator.sh remove

# Report-Konfiguration und Cron-Status anzeigen
sudo /opt/adguard-shield/report-generator.sh status
```

## Report-Intervall ändern

Um das Intervall, die Uhrzeit oder andere Einstellungen zu ändern:

```bash
# 1. Konfiguration bearbeiten
sudo nano /opt/adguard-shield/adguard-shield.conf
# → z.B. REPORT_INTERVAL="weekly" auf "daily" ändern
# → z.B. REPORT_TIME="09:00"

# 2. Cron-Job neu einrichten (überschreibt den alten automatisch)
sudo /opt/adguard-shield/report-generator.sh install
```

> **Hinweis:** Der `install`-Befehl überschreibt den bestehenden Cron-Job mit den aktuellen Werten aus der Konfiguration. Ein vorheriges `remove` ist nicht nötig, schadet aber auch nicht.

Alternativ in zwei Schritten:

```bash
# Alten Cron-Job erst entfernen, dann neu anlegen
sudo /opt/adguard-shield/report-generator.sh remove
sudo nano /opt/adguard-shield/adguard-shield.conf
sudo /opt/adguard-shield/report-generator.sh install
```

## Templates

Die Report-Templates liegen unter:

```
/opt/adguard-shield/templates/report.html   # HTML-Template
/opt/adguard-shield/templates/report.txt    # TXT-Template
```

Die Templates verwenden Platzhalter (z.B. `{{TOTAL_BANS}}`, `{{TOP10_IPS_TABLE}}`), die beim Generieren durch die tatsächlichen Werte ersetzt werden. Die Templates können nach Bedarf angepasst werden.

### Verfügbare Platzhalter

| Platzhalter | Beschreibung |
|-------------|-------------|
| `{{REPORT_PERIOD}}` | Berichtszeitraum mit Label |
| `{{REPORT_DATE}}` | Erstellungsdatum des Reports |
| `{{HOSTNAME}}` | Server-Hostname |
| `{{VERSION}}` | AdGuard Shield Version |
| `{{TOTAL_BANS}}` | Gesamtzahl Sperren |
| `{{TOTAL_UNBANS}}` | Gesamtzahl Entsperrungen |
| `{{UNIQUE_IPS}}` | Anzahl eindeutiger IPs |
| `{{PERMANENT_BANS}}` | Permanente Sperren |
| `{{ACTIVE_BANS}}` | Aktuell aktive Sperren |
| `{{ABUSEIPDB_REPORTS}}` | Anzahl AbuseIPDB-Reports |
| `{{RATELIMIT_BANS}}` | Rate-Limit Sperren |
| `{{SUBDOMAIN_FLOOD_BANS}}` | Subdomain-Flood Sperren |
| `{{EXTERNAL_BLOCKLIST_BANS}}` | Externe Blocklist Sperren |
| `{{BUSIEST_DAY}}` | Aktivster Tag (Datum + Anzahl Sperren) |
| `{{BUSIEST_DAY_LABEL}}` | Dynamisches Label für den aktivsten Tag (z.B. „Aktivster Tag (30 Tage)“) |
| `{{TOP10_IPS_TABLE}}` | Top 10 IPs (HTML-Tabelle) |
| `{{TOP10_IPS_TEXT}}` | Top 10 IPs (Text-Tabelle) |
| `{{TOP10_DOMAINS_TABLE}}` | Top 10 Domains (HTML-Tabelle) |
| `{{TOP10_DOMAINS_TEXT}}` | Top 10 Domains (Text-Tabelle) |
| `{{PROTOCOL_TABLE}}` | Protokoll-Verteilung (HTML) |
| `{{PROTOCOL_TEXT}}` | Protokoll-Verteilung (Text) |
| `{{RECENT_BANS_TABLE}}` | Letzte Sperren (HTML) |
| `{{RECENT_BANS_TEXT}}` | Letzte Sperren (Text) |

## Beispiel: Schnellstart

```bash
# 1. msmtp installieren und konfigurieren
sudo apt install msmtp msmtp-mta
# Anleitung: https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/

# 2. Report-Konfiguration anpassen
sudo nano /opt/adguard-shield/adguard-shield.conf
# → REPORT_ENABLED=true
# → REPORT_EMAIL_TO="deine@email.de"

# 3. Test-Mail senden (prüft alle Voraussetzungen)
sudo /opt/adguard-shield/report-generator.sh test

# 4. Wenn die Test-Mail angekommen ist: echten Report testen
sudo /opt/adguard-shield/report-generator.sh send

# 5. Automatischen Versand einrichten
sudo /opt/adguard-shield/report-generator.sh install

# 6. Status prüfen
sudo /opt/adguard-shield/report-generator.sh status
```

## Test-Mail

Bevor du den automatischen Versand einrichtest, kannst du mit dem `test`-Befehl prüfen, ob alles funktioniert:

```bash
sudo /opt/adguard-shield/report-generator.sh test
```

Der Test prüft Schritt für Schritt:

1. **E-Mail-Empfänger** — Ist `REPORT_EMAIL_TO` konfiguriert?
2. **E-Mail-Absender** — Zeigt den konfigurierten Absender an
3. **Mail-Befehl** — Ist `msmtp` (oder der konfigurierte Befehl) installiert?
4. **Report-Template** — Existiert das HTML/TXT-Template?
5. **Ban-History** — Gibt es vorhandene Daten?
6. **Test-Versand** — Sendet eine Test-E-Mail und prüft den Exit-Code

Die Test-Mail enthält eine Übersicht der aktuellen Konfiguration und bestätigt, dass der Mailversand funktioniert.

## Troubleshooting

### E-Mail wird nicht versendet

1. Prüfe ob der Mail-Befehl installiert ist:
   ```bash
   which msmtp
   ```

2. Teste den Mailversand manuell:
   ```bash
   echo "Test" | msmtp -t deine@email.de
   ```

3. Prüfe die msmtp-Konfiguration:
   ```bash
   cat ~/.msmtprc
   # oder
   cat /etc/msmtprc
   ```

4. Prüfe die Report-Konfiguration:
   ```bash
   sudo /opt/adguard-shield/report-generator.sh status
   ```

### Report enthält keine Daten

Der Report basiert auf der Ban-History in der SQLite-Datenbank (`/var/lib/adguard-shield/adguard-shield.db`). Wenn keine Sperren im Berichtszeitraum vorhanden sind, zeigt der Report „Keine Daten" an.

### Cron-Job wird nicht ausgeführt

1. Prüfe ob der Cron-Job angelegt wurde:
   ```bash
   cat /etc/cron.d/adguard-shield-report
   ```

2. Prüfe die Cron-Logs:
   ```bash
   grep adguard-shield /var/log/syslog
   # oder
   journalctl -u cron
   ```
