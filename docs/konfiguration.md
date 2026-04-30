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

### DNS-Flood-Watchlist

Domains bei denen eine Rate-Limit-Überschreitung **sofort** zu einer **permanenten Sperre** und einer **AbuseIPDB-Meldung** führt — ohne progressive Eskalation. Ideal für bekannte Angriffsziele, die regelmäßig geflutet werden (z.B. `microsoft.com`, `google.com`).

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `DNS_FLOOD_WATCHLIST_ENABLED` | `false` | DNS-Flood-Watchlist aktivieren |
| `DNS_FLOOD_WATCHLIST` | *(leer)* | Überwachte Domains, kommagetrennt (z.B. `"microsoft.com,google.com"`) |

#### Wie funktioniert die Watchlist?

1. Die reguläre Rate-Limit-Prüfung erkennt, dass ein Client mehr als `RATE_LIMIT_MAX_REQUESTS` Anfragen für eine Domain gestellt hat
2. Zusätzlich wird geprüft, ob die angefragte Domain in der Watchlist steht (inkl. Subdomains: `foo.microsoft.com` matcht `microsoft.com`)
3. Trifft beides zu → **sofortige permanente Sperre** + **AbuseIPDB-Meldung** (falls aktiviert)

Die Watchlist greift sowohl bei normalen Rate-Limit-Verstößen als auch bei Subdomain-Flood-Erkennungen.

#### Beispiel

```bash
DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com,apple.com"
```

→ Ein Client der `35x foo.microsoft.com` in 60s abfragt (bei `RATE_LIMIT_MAX_REQUESTS=30`) wird **sofort permanent** gesperrt und an AbuseIPDB gemeldet.

> **Hinweis:** Damit die AbuseIPDB-Meldung funktioniert, muss `ABUSEIPDB_ENABLED=true` und ein gültiger `ABUSEIPDB_API_KEY` konfiguriert sein. Ohne AbuseIPDB-Konfiguration wird nur permanent gesperrt.

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

> **Hinweis:** Abgelaufene Offense-Zähler werden automatisch vom **Offense-Cleanup-Worker** aufgeräumt, der stündlich prüft, ob das letzte Vergehen einer IP länger als `PROGRESSIVE_BAN_RESET_AFTER` zurückliegt. Der Worker startet automatisch zusammen mit dem Hauptservice, wenn progressive Sperren aktiviert sind. Er läuft mit niedrigster CPU- und I/O-Priorität (`nice 19`, `ionice idle`), sodass andere Dienste nicht beeinträchtigt werden. Manuelles Zurücksetzen ist jederzeit mit `reset-offenses` möglich. Permanente Sperren werden **nicht** automatisch aufgehoben – sie müssen manuell mit `unban` oder `flush` entfernt werden.

### Logging

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `LOG_FILE` | `/var/log/adguard-shield.log` | Pfad zur Log-Datei |
| `LOG_LEVEL` | `INFO` | Log-Level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `LOG_MAX_SIZE_MB` | `50` | Max. Log-Größe bevor rotiert wird |
| `BAN_HISTORY_FILE` | `/var/log/adguard-shield-bans.log` | Legacy: Pfad zur alten Ban-History-Datei (wird bei der SQLite-Migration als Quelle verwendet). Neue Einträge werden direkt in die SQLite-Datenbank geschrieben. |
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
| `REPORT_BUSIEST_DAY_RANGE` | `30` | Zeitraum in Tagen für „Aktivster Tag“. `30` = letzte 30 Tage. `0` = nur Berichtszeitraum (altes Verhalten) |

> Siehe [E-Mail Report Dokumentation](report.md) für Details zu Inhalten, Templates und Befehlen.

### Erweitert

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `STATE_DIR` | `/var/lib/adguard-shield` | Verzeichnis für die SQLite-Datenbank (`adguard-shield.db`) und Caches |
| `PID_FILE` | `/var/run/adguard-shield.pid` | PID-Datei |
| `DRY_RUN` | `false` | Testmodus — nur loggen, nicht sperren |

### Externe Whitelist

Ermöglicht das Einbinden externer Whitelist-Dateien mit Domains und IP-Adressen. Der Worker löst Domains regelmäßig per DNS auf — ideal für DynDNS-Einträge mit wechselnden IP-Adressen. Aufgelöste IPs werden automatisch zur Whitelist hinzugefügt und bei jeder Prüfung aktualisiert.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `EXTERNAL_WHITELIST_ENABLED` | `false` | Aktiviert den externen Whitelist-Worker |
| `EXTERNAL_WHITELIST_URLS` | *(leer)* | URL(s) zu Whitelist-Textdateien (kommagetrennt). Unterstützt IPv4, IPv6, CIDR und Hostnamen |
| `EXTERNAL_WHITELIST_INTERVAL` | `300` | Prüfintervall in Sekunden (300 = 5 Min.). Bei DynDNS-Einträgen ggf. kürzer wählen |
| `EXTERNAL_WHITELIST_CACHE_DIR` | `/var/lib/adguard-shield/external-whitelist` | Lokaler Cache für heruntergeladene Listen und aufgelöste IPs |

#### Externe Whitelist einrichten

1. Erstelle eine Textdatei auf einem Webserver. Pro Zeile ein Eintrag — Domain, IPv4, IPv6 oder CIDR:

```text
# Domains (werden regelmäßig per DNS aufgelöst — ideal für DynDNS)
mein-router.dyndns.org
homeserver.example.com

# Feste IPs
192.168.1.100
10.0.0.0/24
2001:db8::1

# Kommentare und Inline-Kommentare werden unterstützt
192.168.1.200 # Backup-Server
```

2. Aktiviere die Whitelist in der Konfiguration:

```bash
EXTERNAL_WHITELIST_ENABLED=true
EXTERNAL_WHITELIST_URLS="https://example.com/whitelist.txt"
EXTERNAL_WHITELIST_INTERVAL=300
```

3. Mehrere Listen können kommagetrennt angegeben werden:

```bash
EXTERNAL_WHITELIST_URLS="https://example.com/trusted.txt,https://other.com/whitelist.txt"
```

4. Service neustarten:

```bash
sudo systemctl restart adguard-shield
```

> **Hinweis:** Da Domains bei jedem Prüfintervall neu aufgelöst werden, eignet sich diese Funktion besonders für DynDNS-Einträge. Ändert sich die IP eines DynDNS-Hostnamens, wird die neue IP beim nächsten Sync automatisch erkannt und in die Whitelist aufgenommen.

> **Wichtig:** Wird eine bereits gesperrte IP durch eine Whitelist-Aktualisierung gewhitelistet, wird sie **automatisch entsperrt**.

### Externe Blocklist

Ermöglicht das Einbinden externer Blocklisten, die IPv4-Adressen, IPv6-Adressen und Hostnamen enthalten können. Der Worker läuft als Hintergrundprozess, prüft periodisch auf Änderungen und löst Hostnamen automatisch über den lokalen DNS-Resolver auf.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `EXTERNAL_BLOCKLIST_ENABLED` | `false` | Aktiviert den externen Blocklist-Worker |
| `EXTERNAL_BLOCKLIST_URLS` | *(leer)* | URL(s) zu Blocklist-Textdateien (kommagetrennt). Unterstützt IPv4, IPv6, CIDR und Hostnamen |
| `EXTERNAL_BLOCKLIST_INTERVAL` | `300` | Prüfintervall in Sekunden (300 = 5 Min.) |
| `EXTERNAL_BLOCKLIST_BAN_DURATION` | `0` | Sperrdauer in Sekunden (0 = permanent bis IP aus Liste entfernt) |
| `EXTERNAL_BLOCKLIST_AUTO_UNBAN` | `true` | IPs automatisch entsperren wenn aus Liste entfernt |
| `EXTERNAL_BLOCKLIST_NOTIFY` | `false` | Webhook-Benachrichtigungen bei Blocklist-Sperren senden. Bei großen Listen unbedingt auf `false` lassen — beim ersten Sync kommen sonst hunderte Nachrichten auf einmal. |
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

- **Bei Rate-Limit / DNS-Flood-Watchlist:** `DNS flooding on our DNS server: 100x microsoft.com in 60s. Banned by Adguard Shield 🔗 https://tnvs.de/as`
- **Bei Subdomain-Flood:** `DNS flooding on our DNS server: 85x *.microsoft.com in 60s (random subdomain attack). Banned by Adguard Shield 🔗 https://tnvs.de/as`

Die Kategorie `4` (DDoS Attack) wird standardmäßig verwendet. Weitere Kategorien können kommagetrennt angegeben werden (z.B. `"4,15"`).

### GeoIP-basierte Länderfilter

Ermöglicht das Sperren oder Erlauben von DNS-Anfragen basierend auf dem Herkunftsland der Client-IP. Unterstützt zwei Modi:

- **Blocklist-Modus:** Nur die gelisteten Länder werden gesperrt (alle anderen erlaubt)
- **Allowlist-Modus:** Nur die gelisteten Länder werden erlaubt (alle anderen gesperrt)

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `GEOIP_ENABLED` | `false` | GeoIP-Filter aktivieren |
| `GEOIP_MODE` | `blocklist` | Modus: `blocklist` oder `allowlist` |
| `GEOIP_COUNTRIES` | *(leer)* | ISO 3166-1 Alpha-2 Ländercodes (kommagetrennt), z.B. `CN,RU,KP,IR` |
| `GEOIP_CHECK_INTERVAL` | `0` | Prüfintervall in Sekunden (`0` = nutzt `CHECK_INTERVAL`) |
| `GEOIP_NOTIFY` | `true` | Benachrichtigungen bei GeoIP-Sperren senden |
| `GEOIP_SKIP_PRIVATE` | `true` | Private/lokale IPs von der GeoIP-Prüfung ausnehmen |
| `GEOIP_LICENSE_KEY` | *(leer)* | MaxMind License-Key für automatischen DB-Download (kostenlos) |
| `GEOIP_MMDB_PATH` | *(leer)* | Manueller Pfad zur MaxMind GeoLite2 Datenbank (überschreibt Auto-Download) |

#### Voraussetzungen

Es muss mindestens eines der folgenden GeoIP-Tools installiert sein:

1. **Automatischer MaxMind-Download** (empfohlen):
   ```bash
   # Kostenlosen Account erstellen: https://www.maxmind.com/en/geolite2/signup
   # License-Key generieren und in adguard-shield.conf eintragen:
   GEOIP_LICENSE_KEY="dein_license_key_hier"
   ```
   Die GeoLite2-Country-Datenbank wird automatisch heruntergeladen und alle 24 Stunden aktualisiert.
   Es wird zusätzlich `mmdbinspect` oder `mmdblookup` benötigt:
   ```bash
   sudo apt install mmdb-bin    # für mmdblookup
   ```

2. **geoiplookup** (einfachster Einstieg, weniger genau):
   ```bash
   sudo apt install geoip-bin geoip-database
   ```

3. **Manueller MaxMind-Pfad** (eigene Datenbank):
   ```bash
   # mmdbinspect oder mmdblookup installieren
   # Datenbank manuell herunterladen: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
   GEOIP_MMDB_PATH="/usr/share/GeoIP/GeoLite2-Country.mmdb"
   ```

> **Priorität:** `GEOIP_MMDB_PATH` (manuell) → Auto-Download-DB → `geoiplookup` (Legacy-Fallback)

#### Beispiel: Bestimmte Länder sperren (Blocklist)

```bash
GEOIP_ENABLED=true
GEOIP_MODE="blocklist"
GEOIP_COUNTRIES="CN,RU,KP,IR"
GEOIP_LICENSE_KEY="dein_maxmind_license_key"   # optional, für Auto-Download
```

→ Alle Anfragen aus China, Russland, Nordkorea und Iran werden permanent gesperrt.

#### Beispiel: Nur bestimmte Länder erlauben (Allowlist)

```bash
GEOIP_ENABLED=true
GEOIP_MODE="allowlist"
GEOIP_COUNTRIES="DE,AT,CH"
```

→ Nur Anfragen aus Deutschland, Österreich und der Schweiz werden erlaubt. Alle anderen Länder werden gesperrt.

> **Hinweis:** Private IP-Adressen (10.x.x.x, 192.168.x.x, etc.) und Whitelist-IPs werden niemals durch GeoIP gesperrt. GeoIP-Sperren sind **immer permanent**.

> **Auto-Unban:** Wird ein Land aus `GEOIP_COUNTRIES` entfernt oder der Modus (`GEOIP_MODE`) geändert, werden die nicht mehr zutreffenden Sperren beim nächsten Sync **automatisch aufgehoben**. Dasselbe gilt, wenn GeoIP komplett deaktiviert wird (`GEOIP_ENABLED=false`).

> **Tipp:** GeoIP-Lookups werden für 24 Stunden gecacht. Mit `geoip-flush-cache` kann der Cache manuell geleert werden.

> **Auto-Download:** Ist `GEOIP_LICENSE_KEY` gesetzt, wird die GeoLite2-Country-Datenbank automatisch nach `<INSTALL_DIR>/geoip/` heruntergeladen und alle 24 Stunden aktualisiert. Bei einem Update wird der Download im Hintergrund durchgeführt — der Worker läuft während des Downloads normal weiter. Ein manuell gesetzter `GEOIP_MMDB_PATH` hat immer Vorrang vor der automatisch heruntergeladenen Datenbank.

#### GeoIP-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `adguard-shield.sh geoip-status` | Zeigt GeoIP-Status, aktive Sperren und verfügbare Tools |
| `adguard-shield.sh geoip-sync` | Einmalige GeoIP-Prüfung aller aktiven Clients |
| `adguard-shield.sh geoip-flush` | Alle GeoIP-Sperren aufheben |
| `adguard-shield.sh geoip-lookup <IP>` | GeoIP-Lookup einer einzelnen IP-Adresse |

#### Externe Blocklist einrichten

1. Erstelle eine Textdatei auf einem Webserver. Pro Zeile ein Eintrag — IPv4, IPv6, CIDR oder Hostname:

```text
# Kommentare werden ignoriert
# Inline-Kommentare ebenfalls: 1.2.3.4 # dieser Kommentar wird entfernt

# IPv4
192.168.100.50
10.0.0.0/8

# IPv6
2001:db8::dead:beef
2001:db8::/32

# Hostnamen (werden über den lokalen DNS-Resolver aufgelöst)
# Liefert ein Hostname mehrere IPs, werden alle gesperrt
bad-actor.example.com
malware.example.net

# Hosts-Datei-Format wird ebenfalls erkannt (Routing-IP wird ignoriert, Hostname aufgelöst)
0.0.0.0 bad-actor.example.com
127.0.0.1 malware.example.net
```

> **Hinweis zur Hostname-Auflösung:** Da AdGuard Shield idealerweise auf demselben Host wie der DNS-Resolver läuft, verwendet der Worker automatisch den lokalen Resolver. Hostnamen die bereits von AdGuard geblockt werden (Antwort `0.0.0.0`) werden übersprungen und nicht importiert.

#### Dateiformat der Blocklist

Beim Erstellen eigener Blocklisten müssen zwei Dinge beachtet werden:

- **Zeichenkodierung:** Datei in **UTF-8 ohne BOM** speichern. Dateien mit BOM (z.B. Standard-Einstellung in Notepad++) führen dazu, dass der erste Eintrag als ungültig erkannt wird.
- **Zeilenenden:** Datei mit **Unix-Zeilenenden (LF)** speichern, nicht Windows (CRLF). CRLF-Zeilenenden führen dazu, dass alle Einträge als ungültig abgelehnt werden.

In **Notepad++:** Kodierung → „UTF-8 (ohne BOM)" und Bearbeiten → Zeilenende-Konvertierung → Unix (LF).  
In **VS Code:** Unten rechts auf `CRLF` klicken → `LF` auswählen; Zeichenkodierung ebenfalls unten rechts prüfen.

> **Empfehlung:** IP-Adressen und Hostnamen in **getrennten Listen** pflegen. Bei Hostname-Listen löst der Worker jeden Eintrag per DNS auf — das ist langsamer als direkte IP-Listen und liefert je nach DNS-Antwort mehrere IPs pro Eintrag. Getrennte Listen sind außerdem übersichtlicher und einfacher zu pflegen.

#### Synchronisierungsverhalten

Der Worker synchronisiert die Blocklisten:

- **Beim Service-Start:** Der erste Sync läuft **sofort** beim Start — ohne Wartezeit. Danach beginnt erst das periodische Intervall (`EXTERNAL_BLOCKLIST_INTERVAL`).
- **Automatisch im Hintergrund:** Alle `EXTERNAL_BLOCKLIST_INTERVAL` Sekunden (Standard: 300s = 5 Min.) wird geprüft, ob sich die Liste geändert hat. Unveränderte Listen (HTTP 304 oder gleicher Inhalt) werden nicht erneut verarbeitet.
- **Manuell:** `sudo adguard-shield.sh blocklist-sync` erzwingt sofort einen Sync, unabhängig vom laufenden Worker.

> **Nach einem Neustart** (Server oder Service) werden fehlende iptables-Regeln beim nächsten Sync automatisch nachgezogen.

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

#### Unterstützte Eintragsformate

| Format | Beispiel | Verhalten |
|--------|----------|----------|
| IPv4 | `1.2.3.4` | direkt gesperrt |
| IPv4-CIDR | `10.0.0.0/8` | direkt gesperrt |
| IPv6 | `2001:db8::1` | direkt gesperrt |
| IPv6-CIDR | `2001:db8::/32` | direkt gesperrt |
| Hostname | `bad.example.com` | per lokalem DNS aufgelöst, alle IPs (IPv4 + IPv6) gesperrt |
| Hosts-Format | `0.0.0.0 bad.example.com` | Hostname extrahiert und aufgelöst |
| Kommentar | `# Text` | übersprungen |
| Inline-Kommentar | `1.2.3.4 # Text` | Kommentar entfernt, IP gesperrt |

Folgende Einträge werden mit einer Warnung im Log übersprungen:

- URLs (`https://...`, `http://...`)
- IP:Port-Kombinationen (`1.2.3.4:8080`)
- Hostnamen mit ungültigen Zeichen oder ohne Punkt
- Einträge mit nicht auflösbarem Hostnamen
- `0.0.0.0` und `::` (AdGuard-Blocking-Antwort)
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

### Externe Whitelist für dynamische IPs

Für Clients mit wechselnden IP-Adressen (z.B. DynDNS) kann eine **externe Whitelist** genutzt werden. Der Whitelist-Worker löst Domains regelmäßig per DNS auf und fügt die aktuellen IPs automatisch zur Whitelist hinzu. Siehe [Externe Whitelist](#externe-whitelist) für die Konfiguration.
