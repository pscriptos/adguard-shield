# Konfiguration

Die zentrale Konfigurationsdatei liegt nach der Installation hier:

```text
/opt/adguard-shield/adguard-shield.conf
```

Die Datei ist eine einfache Shell-ähnliche Key-Value-Datei. Kommentare beginnen mit `#`. Werte können ohne Anführungszeichen, mit doppelten Anführungszeichen oder mit einfachen Anführungszeichen geschrieben werden.

Beispiel:

```bash
ADGUARD_URL="https://dns1.example.com"
RATE_LIMIT_MAX_REQUESTS=30
WHITELIST="127.0.0.1,::1,192.168.1.1"
```

Nach Änderungen solltest du den Service neu starten:

```bash
sudo systemctl restart adguard-shield
sudo /opt/adguard-shield/adguard-shield status
```

## Automatische Migration

Beim Installieren oder Aktualisieren wird eine vorhandene Konfiguration nicht überschrieben. Der Installer vergleicht vorhandene Schlüssel mit der aktuellen Standardkonfiguration.

Wenn neue Parameter fehlen:

1. Die alte Datei wird als `adguard-shield.conf.old` gesichert.
2. Fehlende Schlüssel werden am Ende ergänzt.
3. Vorhandene Werte bleiben erhalten.
4. Dateirechte werden auf `0600` gesetzt.

Das ist besonders wichtig beim Umstieg von der Shell-Version auf die Go-Version. Prüfe nach einem Update trotzdem die neu ergänzten Parameter.

## Empfohlene Startprüfung

Nach dem Bearbeiten der Konfiguration:

```bash
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield dry-run
```

`test` prüft die AdGuard-Home-API. `dry-run` zeigt, was AdGuard Shield sperren würde, ohne die Firewall zu verändern.

## AdGuard Home API

| Parameter | Standard | Beschreibung |
|---|---|---|
| `ADGUARD_URL` | `https://dns1.domain.com` | URL der AdGuard-Home-Weboberfläche/API |
| `ADGUARD_USER` | `admin` | Benutzername für die API |
| `ADGUARD_PASS` | `changeme` | Passwort für die API |

Beispiel lokal:

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="sehr-geheim"
```

Beispiel mit HTTPS:

```bash
ADGUARD_URL="https://dns.example.com"
```

AdGuard Shield ruft intern diesen Endpunkt ab:

```text
/control/querylog?limit=<API_QUERY_LIMIT>&response_status=all
```

Hinweis: Der HTTP-Client akzeptiert auch selbstsignierte TLS-Zertifikate. Das erleichtert lokale Setups, ersetzt aber keine saubere Absicherung der AdGuard-Home-Oberfläche.

## Querylog und Polling

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `CHECK_INTERVAL` | `10` | Abstand zwischen Querylog-Abfragen in Sekunden |
| `API_QUERY_LIMIT` | `500` | Anzahl der Querylog-Einträge pro API-Abfrage |

Empfehlung:

- `CHECK_INTERVAL=10` ist ein guter Standard.
- Bei sehr hohem DNS-Aufkommen kann `API_QUERY_LIMIT` erhöht werden.
- Wenn `API_QUERY_LIMIT` zu niedrig ist, können Spitzen im Querylog zwischen zwei Polls teilweise verpasst werden.
- Sehr kurze Intervalle erzeugen mehr API-Last auf AdGuard Home.

## Rate-Limit

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `RATE_LIMIT_MAX_REQUESTS` | `30` | maximale Anfragen pro Client und Domain im Zeitfenster |
| `RATE_LIMIT_WINDOW` | `60` | Zeitfenster in Sekunden |

Beispiel:

```bash
RATE_LIMIT_MAX_REQUESTS=30
RATE_LIMIT_WINDOW=60
```

Das bedeutet: Wenn ein Client dieselbe Domain mehr als 30-mal innerhalb von 60 Sekunden abfragt, wird er auffällig.

Gute Startwerte:

| Umgebung | Vorschlag |
|---|---|
| kleines Heimnetz | `30` in `60s` |
| viele Clients | `60` bis `120` in `60s` |
| sehr aktive Resolver/Forwarder | zuerst Whitelist prüfen, dann höher setzen |

Wichtig: Wenn ein Router, Reverse Proxy oder lokaler DNS-Forwarder stellvertretend für viele Clients fragt, sollte dieser Client in die Whitelist. Sonst sieht AdGuard Shield nur eine sehr aktive IP.

## Subdomain-Flood-Erkennung

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `SUBDOMAIN_FLOOD_ENABLED` | `true` | aktiviert die Erkennung zufälliger Subdomains |
| `SUBDOMAIN_FLOOD_MAX_UNIQUE` | `50` | maximale Anzahl eindeutiger Subdomains pro Client und Basisdomain |
| `SUBDOMAIN_FLOOD_WINDOW` | `60` | Zeitfenster in Sekunden |

Diese Erkennung zielt auf Muster wie:

```text
a1b2.example.com
f8x9.example.com
zz12.example.com
```

Dabei zählt AdGuard Shield nicht die Gesamtzahl der Anfragen, sondern die Anzahl unterschiedlicher Subdomains unter derselben Basisdomain.

Beispiel:

```bash
SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=50
SUBDOMAIN_FLOOD_WINDOW=60
```

Wenn ein Client innerhalb von 60 Sekunden mehr als 50 unterschiedliche Subdomains von `example.com` abfragt, wird er gesperrt.

Hinweise:

- Direkte Anfragen an `example.com` zählen hier nicht.
- Multi-Part-TLDs wie `.co.uk` werden berücksichtigt.
- CDNs und manche Apps nutzen viele Subdomains. Wenn legitime Clients betroffen sind, den Grenzwert erhöhen oder passende Clients whitelisten.

## DNS-Flood-Watchlist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `DNS_FLOOD_WATCHLIST_ENABLED` | `false` | aktiviert die Watchlist |
| `DNS_FLOOD_WATCHLIST` | leer | kommagetrennte Domainliste |

Die Watchlist ist für Domains gedacht, bei denen eine Überschreitung sofort hart behandelt werden soll.

Beispiel:

```bash
DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com,apple.com"
```

Wenn ein Client dann `login.microsoft.com` über das Rate-Limit bringt, wird sofort permanent gesperrt, weil `login.microsoft.com` zur Watchlist-Domain `microsoft.com` gehört.

Folgen:

- Grund: `dns-flood-watchlist`
- Sperrdauer: permanent
- Progressive-Ban-Dauer wird übersprungen
- AbuseIPDB-Reporting kann ausgelöst werden, wenn aktiviert

## Sperrdauer und Firewall

| Parameter | Standard | Beschreibung |
|---|---|---|
| `BAN_DURATION` | `3600` | Basisdauer temporärer Monitor-Sperren in Sekunden |
| `IPTABLES_CHAIN` | `ADGUARD_SHIELD` | Name der eigenen Firewall-Chain |
| `BLOCKED_PORTS` | `53 443 853` | Ports, die für gesperrte Clients blockiert werden |
| `FIREWALL_BACKEND` | `ipset` | Firewall-Backend der Go-Version |
| `FIREWALL_MODE` | `host` | Verkehrsweg der AdGuard-Home-Installation |
| `DRY_RUN` | `false` | Konfigurationsweiter Testmodus ohne echte Sperren |

Standardports:

| Port | Zweck |
|---:|---|
| `53` | klassisches DNS über UDP/TCP |
| `443` | DNS-over-HTTPS, sofern AdGuard Home darüber erreichbar ist |
| `853` | DNS-over-TLS und DNS-over-QUIC |

Die Firewall wird über `ipset` und `iptables`/`ip6tables` gesteuert. Für IPv4 und IPv6 gibt es getrennte Sets:

```text
adguard_shield_v4
adguard_shield_v6
```

`FIREWALL_MODE` legt fest, in welche Host-Chain AdGuard Shield die Schutzregeln einhängt:

| Modus | Einsatz |
|---|---|
| `host` | klassische AdGuard-Home-Installation direkt auf dem Host |
| `docker-host` | AdGuard Home läuft in Docker mit `network_mode: host`; Alias von `host` |
| `docker-bridge` | AdGuard Home läuft in Docker mit veröffentlichten Ports, z.B. `53:53` |
| `hybrid` | schützt Host-Ports und Docker-Forwarding gleichzeitig |

Bei `host`/`docker-host` wird die eigene Chain aus `INPUT` angesprungen. Bei `docker-bridge` wird sie aus `DOCKER-USER` angesprungen, weil Docker veröffentlichte Ports über NAT und `FORWARD` verarbeitet. Details stehen in [Docker-Installationen](docker.md).

## Whitelist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `WHITELIST` | `127.0.0.1,::1` | IPs, die nie gesperrt werden |

Beispiel:

```bash
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.10,fd00::1"
```

Empfohlen sind:

- Localhost: `127.0.0.1`, `::1`
- Router/Gateway
- Admin- oder Management-IPs
- Monitoring-Systeme
- interne Resolver oder Forwarder
- eigene VPN-Endpunkte, falls sie viele Anfragen bündeln

Wichtig: Die Whitelist wird vor jeder Sperre geprüft. Das gilt für automatische, manuelle, GeoIP- und externe Blocklist-Sperren.

## Progressive Sperren

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `PROGRESSIVE_BAN_ENABLED` | `true` | Wiederholungstäter stufenweise länger sperren |
| `PROGRESSIVE_BAN_MULTIPLIER` | `2` | Multiplikator pro Stufe |
| `PROGRESSIVE_BAN_MAX_LEVEL` | `5` | ab dieser Stufe permanent sperren, `0` bedeutet nie permanent durch Stufe |
| `PROGRESSIVE_BAN_RESET_AFTER` | `86400` | Offense-Zähler nach so vielen Sekunden ohne neues Vergehen zurücksetzen |

Beispiel mit Standardwerten:

| Vergehen | Stufe | Dauer |
|---:|---:|---|
| 1 | 1 | 1 Stunde |
| 2 | 2 | 2 Stunden |
| 3 | 3 | 4 Stunden |
| 4 | 4 | 8 Stunden |
| 5 | 5 | permanent |

Progressive Sperren gelten für Monitor-Sperren wie `rate-limit` und `subdomain-flood`. Watchlist-Treffer sind sofort permanent. GeoIP und externe Blocklisten haben eigene Regeln.

Wartung:

```bash
sudo /opt/adguard-shield/adguard-shield offense-status
sudo /opt/adguard-shield/adguard-shield offense-cleanup
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

## Logging

| Parameter | Standard | Beschreibung |
|---|---|---|
| `LOG_FILE` | `/var/log/adguard-shield.log` | Datei für Daemon-Ereignisse |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` oder `ERROR` |

`LOG_FILE` enthält Start/Stop, Worker-Läufe, Sperren, Freigaben, Warnungen und Fehler. Query-Inhalte werden nicht dauerhaft ins Log geschrieben.

CLI:

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo /opt/adguard-shield/adguard-shield logs-follow debug
sudo /opt/adguard-shield/adguard-shield live
```

Für produktiven Betrieb ist `INFO` sinnvoll. Für Fehlersuche kurzzeitig `DEBUG` verwenden.

## State und Runtime

| Parameter | Standard | Beschreibung |
|---|---|---|
| `STATE_DIR` | `/var/lib/adguard-shield` | Verzeichnis für SQLite-Datenbank und Caches |
| `PID_FILE` | `/var/run/adguard-shield.pid` | PID-Datei für direkten Vordergrundlauf |

SQLite-Datei:

```text
${STATE_DIR}/adguard-shield.db
```

Weitere Dateien in `STATE_DIR`:

- Caches für externe Listen
- gespeicherte Firewall-Regeln bei `firewall-save`
- SQLite-WAL-Dateien

## Benachrichtigungen

| Parameter | Standard | Beschreibung |
|---|---|---|
| `NOTIFY_ENABLED` | `false` | Benachrichtigungen aktivieren |
| `NOTIFY_TYPE` | `ntfy` | `ntfy`, `discord`, `slack`, `gotify` oder `generic` |
| `NOTIFY_WEBHOOK_URL` | leer | Webhook-URL für Discord, Slack, Gotify oder Generic |
| `NTFY_SERVER_URL` | `https://ntfy.sh` | Ntfy-Server |
| `NTFY_TOPIC` | leer | Ntfy-Topic |
| `NTFY_TOKEN` | leer | optionaler Access-Token |
| `NTFY_PRIORITY` | `4` | Ntfy-Priorität von 1 bis 5 |

Ntfy-Beispiel:

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC="mein-adguard-shield"
NTFY_PRIORITY="4"
```

Discord-Beispiel:

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="discord"
NOTIFY_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

Details stehen in [Benachrichtigungen](benachrichtigungen.md).

## E-Mail-Reports

| Parameter | Standard | Beschreibung |
|---|---|---|
| `REPORT_ENABLED` | `false` | Report-Funktion logisch aktivieren |
| `REPORT_INTERVAL` | `weekly` | `daily`, `weekly`, `biweekly` oder `monthly` |
| `REPORT_TIME` | `08:00` | Versandzeit im Format `HH:MM` |
| `REPORT_EMAIL_TO` | `admin@example.com` | Empfänger |
| `REPORT_EMAIL_FROM` | `adguard-shield@example.com` | Absender |
| `REPORT_FORMAT` | `html` | `html` oder `txt` |
| `REPORT_MAIL_CMD` | `msmtp` | Mailprogramm |
| `REPORT_BUSIEST_DAY_RANGE` | `30` | Zeitraum in Tagen für "Aktivster Tag"; aktuell als Kompatibilitätsparameter vorhanden |

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

Cron installieren:

```bash
sudo /opt/adguard-shield/adguard-shield report-install
```

Details stehen in [E-Mail Report](report.md).

## Externe Whitelist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `EXTERNAL_WHITELIST_ENABLED` | `false` | externe Whitelist aktivieren |
| `EXTERNAL_WHITELIST_URLS` | leer | kommagetrennte URLs |
| `EXTERNAL_WHITELIST_INTERVAL` | `300` | Synchronisationsintervall in Sekunden |
| `EXTERNAL_WHITELIST_CACHE_DIR` | `/var/lib/adguard-shield/external-whitelist` | Cache-Verzeichnis |

Beispiel:

```bash
EXTERNAL_WHITELIST_ENABLED=true
EXTERNAL_WHITELIST_URLS="https://example.com/trusted.txt"
EXTERNAL_WHITELIST_INTERVAL=300
```

Listenformat:

```text
# Hostnamen werden regelmäßig aufgelöst
mein-router.dyndns.org
vpn.example.com

# IPs und Netze
192.168.1.10
10.0.0.0/24
2001:db8::1
```

Mehrere Listen:

```bash
EXTERNAL_WHITELIST_URLS="https://example.com/a.txt,https://example.net/b.txt"
```

Verhalten:

- Hostnamen werden per DNS aufgelöst.
- Aufgelöste IPs landen in SQLite.
- Bereits aktive Sperren werden aufgehoben, wenn die IP später in der Whitelist auftaucht.
- Kommentare und Inline-Kommentare werden unterstützt.

Manuell synchronisieren:

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-sync
```

## Externe Blocklist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `EXTERNAL_BLOCKLIST_ENABLED` | `false` | externe Blocklist aktivieren |
| `EXTERNAL_BLOCKLIST_URLS` | leer | kommagetrennte URLs |
| `EXTERNAL_BLOCKLIST_INTERVAL` | `300` | Synchronisationsintervall in Sekunden |
| `EXTERNAL_BLOCKLIST_BAN_DURATION` | `0` | Sperrdauer in Sekunden, `0` = permanent |
| `EXTERNAL_BLOCKLIST_AUTO_UNBAN` | `true` | IPs freigeben, wenn sie nicht mehr in der Liste stehen |
| `EXTERNAL_BLOCKLIST_NOTIFY` | `false` | Benachrichtigungen für Blocklist-Sperren senden |
| `EXTERNAL_BLOCKLIST_CACHE_DIR` | `/var/lib/adguard-shield/external-blocklist` | Cache-Verzeichnis |

Beispiel:

```bash
EXTERNAL_BLOCKLIST_ENABLED=true
EXTERNAL_BLOCKLIST_URLS="https://example.com/blocklist.txt"
EXTERNAL_BLOCKLIST_INTERVAL=300
EXTERNAL_BLOCKLIST_BAN_DURATION=0
EXTERNAL_BLOCKLIST_AUTO_UNBAN=true
EXTERNAL_BLOCKLIST_NOTIFY=false
```

Listenformat:

```text
# IPv4
203.0.113.50
198.51.100.0/24

# IPv6
2001:db8::dead:beef
2001:db8::/32

# Hostnamen
bad-actor.example.com

# Hosts-Datei-Format wird erkannt
0.0.0.0 malware.example.net
127.0.0.1 tracker.example.org
```

Unterstützt:

| Format | Beispiel |
|---|---|
| IPv4 | `203.0.113.50` |
| IPv4-CIDR | `198.51.100.0/24` |
| IPv6 | `2001:db8::1` |
| IPv6-CIDR | `2001:db8::/32` |
| Hostname | `bad.example.com` |
| Hosts-Format | `0.0.0.0 bad.example.com` |
| Kommentar | `# Text` |
| Inline-Kommentar | `203.0.113.50 # Grund` |

Nicht sinnvoll und wird übersprungen:

- URLs wie `https://...`
- IP:Port wie `203.0.113.50:8443`
- Hostnamen ohne Punkt oder mit ungültigen Zeichen
- nicht auflösbare Hostnamen
- Blocking-Antworten wie `0.0.0.0` oder `::`

Hinweise:

- Große Listen können viele Sperren erzeugen. `EXTERNAL_BLOCKLIST_NOTIFY=false` ist deshalb der sichere Standard.
- Wenn ein Hostname mehrere IPs liefert, werden alle aufgelösten IPs verarbeitet.
- IPs aus der Whitelist werden nicht gesperrt.
- Bei `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` werden entfernte Einträge wieder freigegeben.

Manuell synchronisieren:

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-sync
```

Dateiformat-Empfehlungen:

- UTF-8 ohne BOM
- Unix-Zeilenenden `LF`
- IP-Listen und Hostname-Listen möglichst getrennt pflegen

## AbuseIPDB

| Parameter | Standard | Beschreibung |
|---|---|---|
| `ABUSEIPDB_ENABLED` | `false` | AbuseIPDB-Reporting aktivieren |
| `ABUSEIPDB_API_KEY` | leer | API-Key |
| `ABUSEIPDB_CATEGORIES` | `4` | Kategorien, kommagetrennt möglich |

Beispiel:

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="dein-api-key"
ABUSEIPDB_CATEGORIES="4"
```

Gemeldet werden nur permanente Monitor-Sperren:

- Watchlist-Treffer
- Progressive-Ban-Sperren auf Maximalstufe

Nicht gemeldet werden:

- temporäre Sperren
- GeoIP-Sperren
- externe Blocklist-Sperren
- manuelle Sperren

## GeoIP-Länderfilter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `GEOIP_ENABLED` | `false` | GeoIP-Filter aktivieren |
| `GEOIP_MODE` | `blocklist` | `blocklist` oder `allowlist` |
| `GEOIP_COUNTRIES` | leer | ISO-3166-1-Alpha-2-Ländercodes |
| `GEOIP_CHECK_INTERVAL` | `0` | Legacy-Parameter; die Go-Version nutzt den zentralen Query-Poller |
| `GEOIP_NOTIFY` | `true` | Benachrichtigungen bei GeoIP-Sperren |
| `GEOIP_SKIP_PRIVATE` | `true` | private/lokale IPs überspringen |
| `GEOIP_LICENSE_KEY` | leer | MaxMind-License-Key für Auto-Download |
| `GEOIP_MMDB_PATH` | leer | manueller Pfad zur MaxMind-MMDB |
| `GEOIP_CACHE_TTL` | `86400` | Cache-Zeit in Sekunden |

Blocklist-Modus:

```bash
GEOIP_ENABLED=true
GEOIP_MODE="blocklist"
GEOIP_COUNTRIES="CN,RU,KP,IR"
```

Damit werden öffentliche Clients aus diesen Ländern gesperrt.

Allowlist-Modus:

```bash
GEOIP_ENABLED=true
GEOIP_MODE="allowlist"
GEOIP_COUNTRIES="DE,AT,CH"
```

Damit werden nur diese Länder erlaubt. Andere öffentliche Länder werden gesperrt.

Private IPs:

```bash
GEOIP_SKIP_PRIVATE=true
```

Damit werden unter anderem private Netze, Loopback, Link-Local und CGNAT übersprungen.

### GeoIP-Datenquellen

Priorität:

1. `GEOIP_MMDB_PATH`, wenn gesetzt
2. automatisch geladene MaxMind-Datenbank, wenn `GEOIP_LICENSE_KEY` gesetzt ist
3. Legacy-Fallback über `geoiplookup` oder `geoiplookup6`

Automatischer MaxMind-Download:

```bash
GEOIP_LICENSE_KEY="dein_maxmind_license_key"
```

Die Datenbank wird unter `/opt/adguard-shield/geoip/` gespeichert und nach 24 Stunden erneuert.

Manueller Pfad:

```bash
GEOIP_MMDB_PATH="/usr/share/GeoIP/GeoLite2-Country.mmdb"
```

Nützliche Befehle:

```bash
sudo /opt/adguard-shield/adguard-shield geoip-status
sudo /opt/adguard-shield/adguard-shield geoip-lookup 8.8.8.8
sudo /opt/adguard-shield/adguard-shield geoip-sync
sudo /opt/adguard-shield/adguard-shield geoip-flush-cache
```

## Protokollerkennung

AdGuard Shield liest das Feld `client_proto` aus der AdGuard-Home-API.

| API-Wert | Anzeige | Bedeutung |
|---|---|---|
| leer oder `dns` | `DNS` | klassisches DNS |
| `doh` | `DoH` | DNS-over-HTTPS |
| `dot` | `DoT` | DNS-over-TLS |
| `doq` | `DoQ` | DNS-over-QUIC |
| `dnscrypt` | `DNSCrypt` | DNSCrypt |

Die Sperre blockiert die konfigurierten Ports unabhängig davon, welches Protokoll den Verstoß ausgelöst hat.

## Beispielkonfiguration für ein Heimnetz

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="geheim"

RATE_LIMIT_MAX_REQUESTS=30
RATE_LIMIT_WINDOW=60
CHECK_INTERVAL=10
API_QUERY_LIMIT=500

SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=50
SUBDOMAIN_FLOOD_WINDOW=60

BAN_DURATION=3600
PROGRESSIVE_BAN_ENABLED=true
PROGRESSIVE_BAN_MAX_LEVEL=5

WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.10"

NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_TOPIC="adguard-shield-home"

REPORT_ENABLED=false
GEOIP_ENABLED=false
EXTERNAL_BLOCKLIST_ENABLED=false
EXTERNAL_WHITELIST_ENABLED=false
```

## Beispielkonfiguration für einen öffentlichen Resolver

```bash
ADGUARD_URL="https://dns.example.com"
ADGUARD_USER="admin"
ADGUARD_PASS="geheim"

RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_WINDOW=60
CHECK_INTERVAL=5
API_QUERY_LIMIT=2000

SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=75
SUBDOMAIN_FLOOD_WINDOW=60

DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com,apple.com"

BAN_DURATION=3600
PROGRESSIVE_BAN_ENABLED=true
PROGRESSIVE_BAN_MULTIPLIER=2
PROGRESSIVE_BAN_MAX_LEVEL=5

ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."

NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_TOPIC="adguard-shield-prod"
```

Vor produktiver Aktivierung:

```bash
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield dry-run
```
