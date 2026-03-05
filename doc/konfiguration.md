# Konfiguration

Die Konfigurationsdatei liegt nach der Installation unter:

```
/opt/adguard-shield/adguard-shield.conf
```

## Automatische Konfigurations-Migration

Bei einem **Update** (`sudo bash install.sh update`) wird die Konfiguration automatisch migriert:

1. Die aktuelle Konfiguration wird als **Backup** gespeichert: `adguard-shield.conf.old`
2. Neue Parameter (die in der alten Konfig noch nicht existieren) werden **automatisch** zur bestehenden Konfiguration hinzugefügt
3. Alle bestehenden Einstellungen bleiben **unverändert** erhalten

Dadurch muss der Benutzer bei Updates die Konfiguration nicht manuell austauschen oder vergleichen.

> **Hinweis:** Nach einem Update empfiehlt es sich, die eventuell neu hinzugefügten Parameter zu prüfen und bei Bedarf anzupassen.

## Alle Parameter

### AdGuard Home API

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `ADGUARD_URL` | `http://127.0.0.1:3000` | AdGuard Home Web-UI URL |
| `ADGUARD_USER` | `admin` | API Benutzername |
| `ADGUARD_PASS` | `changeme` | API Passwort |

### Rate-Limit

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `RATE_LIMIT_MAX_REQUESTS` | `30` | Max. Anfragen pro Domain/Client innerhalb des Zeitfensters |
| `RATE_LIMIT_WINDOW` | `60` | Zeitfenster in Sekunden |
| `CHECK_INTERVAL` | `10` | Wie oft die Logs geprüft werden (Sekunden) |
| `API_QUERY_LIMIT` | `500` | Anzahl API-Einträge pro Abfrage (max 5000) |

### Subdomain-Flood-Erkennung (Random Subdomain Attack)

Erkennt Bot-Angriffe, bei denen massenhaft zufällige Subdomains einer Domain abgefragt werden (z.B. `abc123.microsoft.com`, `xyz456.microsoft.com`, ...). Dabei wird pro Client gezählt, wie viele **eindeutige** Subdomains einer Basisdomain (z.B. `microsoft.com`) im Zeitfenster aufgerufen werden.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `SUBDOMAIN_FLOOD_ENABLED` | `true` | Subdomain-Flood-Erkennung aktivieren |
| `SUBDOMAIN_FLOOD_MAX_UNIQUE` | `50` | Max. eindeutige Subdomains pro Basisdomain/Client im Zeitfenster |
| `SUBDOMAIN_FLOOD_WINDOW` | `60` | Zeitfenster in Sekunden |

#### Wie funktioniert die Erkennung?

1. Aus jeder DNS-Anfrage wird die **Basisdomain** extrahiert (z.B. `microsoft.com` aus `abc.microsoft.com`)
2. Pro Client wird gezählt, wie viele **verschiedene** Subdomains einer Basisdomain im Zeitfenster abgefragt wurden
3. Überschreitet die Anzahl eindeutiger Subdomains den Schwellwert, wird der Client gesperrt

#### Beispiel

Ein Bot fragt innerhalb von 60 Sekunden folgende Domains ab:

```
hbidcw.microsoft.com
ftdzewf.microsoft.com
xk9z3a.microsoft.com
... (50+ verschiedene Subdomains)
```

→ Alle Anfragen haben die gleiche Basisdomain `microsoft.com`. Sobald mehr als 50 eindeutige Subdomains erkannt werden, wird der Client gesperrt.

> **Hinweis:** Nur echte Subdomains werden gezählt. Anfragen direkt an `microsoft.com` (ohne Subdomain) lösen diese Erkennung nicht aus. Multi-Part-TLDs wie `.co.uk`, `.com.au` etc. werden korrekt behandelt.

> **Tipp:** Der Schwellwert `SUBDOMAIN_FLOOD_MAX_UNIQUE` sollte hoch genug sein, um legitime Clients nicht zu stören (z.B. CDNs nutzen oft viele Subdomains). Ein Wert von 50–100 ist in den meisten Fällen sinnvoll.

### Sperr-Einstellungen

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `BAN_DURATION` | `3600` | Basis-Sperrdauer in Sekunden (3600 = 1 Stunde) |
| `IPTABLES_CHAIN` | `ADGUARD_SHIELD` | Name der iptables Chain |
| `BLOCKED_PORTS` | `53 443 853` | Ports die gesperrt werden (IPv4 + IPv6) |
| `WHITELIST` | `127.0.0.1,::1` | IPs die nie gesperrt werden (kommagetrennt) |

### Progressive Sperren (Recidive)

Wiederholungstäter werden wie bei fail2ban stufenweise länger gesperrt. Wird eine IP nach dem Ablauf ihrer Sperre erneut auffällig, steigt die Sperrdauer exponentiell.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `PROGRESSIVE_BAN_ENABLED` | `true` | Progressive Sperren aktivieren |
| `PROGRESSIVE_BAN_MULTIPLIER` | `2` | Multiplikator pro Stufe (2 = Verdopplung) |
| `PROGRESSIVE_BAN_MAX_LEVEL` | `5` | Ab dieser Stufe wird permanent gesperrt (0 = nie) |
| `PROGRESSIVE_BAN_RESET_AFTER` | `86400` | Zähler-Reset nach X Sekunden ohne Vergehen (86400 = 24h) |

#### Beispiel bei Standardwerten

| Vergehen | Stufe | Sperrdauer | Berechnung |
|----------|-------|------------|------------|
| 1. Mal   | 1     | 1 Stunde   | 3600 × 1   |
| 2. Mal   | 2     | 2 Stunden  | 3600 × 2   |
| 3. Mal   | 3     | 4 Stunden  | 3600 × 4   |
| 4. Mal   | 4     | 8 Stunden  | 3600 × 8   |
| 5. Mal   | 5     | **PERMANENT** | Max-Stufe erreicht |

> **Hinweis:** Der Offense-Zähler wird automatisch zurückgesetzt, wenn eine IP für den konfigurierten Zeitraum (`PROGRESSIVE_BAN_RESET_AFTER`) kein erneutes Vergehen begeht. Permanente Sperren werden **nicht** automatisch aufgehoben – sie müssen manuell mit `unban` oder `flush` entfernt werden.

### Logging

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `LOG_FILE` | `/var/log/adguard-shield.log` | Pfad zur Log-Datei |
| `LOG_LEVEL` | `INFO` | Log-Level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `LOG_MAX_SIZE_MB` | `50` | Max. Log-Größe bevor rotiert wird |
| `BAN_HISTORY_FILE` | `/var/log/adguard-shield-bans.log` | Datei für die Ban-History (alle Sperren/Entsperrungen) |
| `BAN_HISTORY_RETENTION_DAYS` | `0` | Aufbewahrungsdauer der Ban-History in Tagen. `0` = unbegrenzt (niemals löschen). Alte Einträge werden beim nächsten Report automatisch entfernt. |

### Benachrichtigungen

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `NOTIFY_ENABLED` | `false` | Benachrichtigungen aktivieren |
| `NOTIFY_TYPE` | `ntfy` | Typ: `ntfy`, `discord`, `slack`, `gotify`, `generic` |
| `NOTIFY_WEBHOOK_URL` | *(leer)* | Webhook-URL (nur für discord, slack, gotify, generic) |
| `NTFY_SERVER_URL` | `https://ntfy.sh` | Ntfy Server-URL |
| `NTFY_TOPIC` | *(leer)* | Ntfy Topic-Name |
| `NTFY_TOKEN` | *(leer)* | Optionaler Ntfy Access-Token |
| `NTFY_PRIORITY` | `4` | Ntfy Priorität (1–5) |

### E-Mail Report

Regelmäßige Statistik-Reports per E-Mail. Voraussetzung ist ein funktionierender Mail-Transport (z.B. msmtp).

> **Anleitung für msmtp:** [Linux: Einfach E-Mails versenden mit msmtp](https://www.cleveradmin.de/blog/2024/12/linux-einfach-emails-versenden-mit-msmtp/)

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `REPORT_ENABLED` | `false` | Report-Funktion aktivieren |
| `REPORT_INTERVAL` | `weekly` | Intervall: `daily`, `weekly`, `biweekly`, `monthly` |
| `REPORT_TIME` | `08:00` | Versanduhrzeit (HH:MM, 24h) |
| `REPORT_EMAIL_TO` | *(leer)* | E-Mail-Empfänger |
| `REPORT_EMAIL_FROM` | `adguard-shield@hostname` | E-Mail-Absender |
| `REPORT_FORMAT` | `html` | Format: `html` oder `txt` |
| `REPORT_MAIL_CMD` | `msmtp` | Mail-Befehl (`msmtp`, `sendmail`, `mail`) |

> Siehe [E-Mail Report Dokumentation](report.md) für Details zu Inhalten, Templates und Befehlen.

### Erweitert

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `STATE_DIR` | `/var/lib/adguard-shield` | Verzeichnis für State-Dateien |
| `PID_FILE` | `/var/run/adguard-shield.pid` | PID-Datei |
| `DRY_RUN` | `false` | Testmodus — nur loggen, nicht sperren |
### Externe Blocklist

Ermöglicht das Einbinden externer IP-Blocklisten (z.B. gehostete Textdateien mit einer IP pro Zeile). Der Worker läuft als Hintergrundprozess und prüft periodisch auf Änderungen.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `EXTERNAL_BLOCKLIST_ENABLED` | `false` | Aktiviert den externen Blocklist-Worker |
| `EXTERNAL_BLOCKLIST_URLS` | *(leer)* | URL(s) zu Textdateien mit IPs (kommagetrennt) |
| `EXTERNAL_BLOCKLIST_INTERVAL` | `300` | Prüfintervall in Sekunden (300 = 5 Min.) |
| `EXTERNAL_BLOCKLIST_BAN_DURATION` | `0` | Sperrdauer in Sekunden (0 = permanent bis IP aus Liste entfernt) |
| `EXTERNAL_BLOCKLIST_AUTO_UNBAN` | `true` | IPs automatisch entsperren wenn aus Liste entfernt |
| `EXTERNAL_BLOCKLIST_CACHE_DIR` | `/var/lib/adguard-shield/external-blocklist` | Lokaler Cache für heruntergeladene Listen |
### AbuseIPDB Reporting

Meldet permanent gesperrte IPs automatisch an [AbuseIPDB](https://www.abuseipdb.com/). Damit wird die IP in einer öffentlichen Datenbank als missbräuchlich markiert und andere Administratoren können davon profitieren.

> **Wichtig:** Es werden **nur permanent gesperrte IPs** gemeldet — also erst wenn die maximale Progressive-Ban-Stufe erreicht ist. Einzelne temporäre Sperren lösen keinen AbuseIPDB-Report aus.

| Parameter | Standard | Beschreibung |
|-----------|----------|---------------|
| `ABUSEIPDB_ENABLED` | `false` | AbuseIPDB-Reporting aktivieren |
| `ABUSEIPDB_API_KEY` | *(leer)* | API-Key von [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `ABUSEIPDB_CATEGORIES` | `4` | Report-Kategorien (4 = DDoS Attack). Siehe [Kategorien](https://www.abuseipdb.com/categories) |

#### AbuseIPDB einrichten

1. Erstelle einen kostenlosen Account auf [abuseipdb.com](https://www.abuseipdb.com/)
2. Erstelle einen API-Key unter [Account → API](https://www.abuseipdb.com/account/api)
3. Aktiviere das Reporting in der Konfiguration:

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="dein-api-key-hier"
ABUSEIPDB_CATEGORIES="4"
```

4. Service neustarten:

```bash
sudo systemctl restart adguard-shield
```

#### Was wird gemeldet?

Der Report an AbuseIPDB enthält (auf Englisch):

- **Bei Rate-Limit:** `DNS flooding on our DNS server: 100x microsoft.com in 60s. Banned by Adguard Shield 🔗 https://tnvs.de/as`
- **Bei Subdomain-Flood:** `DNS flooding on our DNS server: 85x *.microsoft.com in 60s (random subdomain attack). Banned by Adguard Shield 🔗 https://tnvs.de/as`

Die Kategorie `4` (DDoS Attack) wird standardmäßig verwendet. Weitere Kategorien können kommagetrennt angegeben werden (z.B. `"4,15"`).
#### Externe Blocklist einrichten

1. Erstelle eine Textdatei auf einem Webserver mit einer IP pro Zeile:

```text
# Kommentare werden ignoriert
192.168.100.50
10.0.0.99
2001:db8::dead:beef
```

2. Aktiviere die Blocklist in der Konfiguration:

```bash
EXTERNAL_BLOCKLIST_ENABLED=true
EXTERNAL_BLOCKLIST_URLS="https://example.com/blocklist.txt"
EXTERNAL_BLOCKLIST_INTERVAL=300
```

3. Mehrere Listen können kommagetrennt angegeben werden:

```bash
EXTERNAL_BLOCKLIST_URLS="https://example.com/list1.txt,https://other.com/list2.txt"
```

4. Service neustarten:

```bash
sudo systemctl restart adguard-shield
```
## Gesperrte Ports im Detail

Bei einem Rate-Limit-Verstoß werden **alle** DNS-Protokoll-Ports für den Client gesperrt (IPv4 via `iptables` und IPv6 via `ip6tables`):

| Port | Protokoll | Beschreibung |
|------|-----------|-------------|
| 53   | UDP/TCP   | Standard DNS |
| 443  | TCP       | DNS-over-HTTPS (DoH) |
| 853  | TCP       | DNS-over-TLS (`tls://dns1.techniverse.net:853`) |
| 853  | UDP       | DNS-over-QUIC (`quic://dns1.techniverse.net:853`) |

## Protokoll-Erkennung

AdGuard Shield erkennt **automatisch**, welches DNS-Protokoll ein Client verwendet. Diese Information wird aus dem Feld `client_proto` der AdGuard Home Query Log API extrahiert und an folgenden Stellen angezeigt:

- **Log-Datei**: Jede Anfrage wird mit dem verwendeten Protokoll geloggt
- **Ban-History**: Die Protokoll-Spalte zeigt, über welches Protokoll die Anfragen kamen
- **Status-Anzeige**: Aktive Sperren zeigen das verwendete Protokoll an
- **Benachrichtigungen**: Push-Nachrichten enthalten das Protokoll

### Unterstützte Protokolle

| API-Wert | Anzeige | Beschreibung |
|----------|---------|-------------|
| *(leer)* | `DNS` | Klassisches DNS über UDP/TCP (Port 53) |
| `doh` | `DoH` | DNS-over-HTTPS (Port 443) |
| `dot` | `DoT` | DNS-over-TLS (Port 853) |
| `doq` | `DoQ` | DNS-over-QUIC (Port 853/UDP) |
| `dnscrypt` | `DNSCrypt` | DNSCrypt-Protokoll |

Verwendet ein Client mehrere Protokolle gleichzeitig (z.B. DoH und DNS), werden alle erkannten Protokolle kommagetrennt angezeigt (z.B. `DNS,DoH`).

> **Wichtig:** Alle Protokolle werden gleichermaßen überwacht und gegen das Rate-Limit geprüft. Ein DoH-Flood wird genauso erkannt und gesperrt wie ein klassischer DNS-Flood – die Erkennung basiert auf den AdGuard Home Logdaten, nicht auf Netzwerk-Traffic.

## Whitelist richtig pflegen

Die Whitelist sollte mindestens enthalten:

- `127.0.0.1` und `::1` (Localhost)
- Die IP deines Routers / Gateways
- Deine eigenen Management-IPs
- Andere vertrauenswürdige DNS-Clients

Beispiel:

```
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.10,fd00::1"
```
