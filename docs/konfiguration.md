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

Nach Änderungen muss der Service neu gestartet werden:

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
# API-Verbindung testen
sudo /opt/adguard-shield/adguard-shield test

# Dry-Run: zeigt, was gesperrt würde, ohne die Firewall zu verändern
sudo /opt/adguard-shield/adguard-shield dry-run
```

---

## AdGuard Home API

| Parameter | Standard | Beschreibung |
|---|---|---|
| `ADGUARD_URL` | `https://dns1.domain.com` | URL der AdGuard-Home-Weboberfläche/API |
| `ADGUARD_USER` | `admin` | Benutzername für die API-Authentifizierung |
| `ADGUARD_PASS` | `changeme` | Passwort für die API-Authentifizierung |

### Beispiel: Lokale Instanz

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="sehr-geheim"
```

### Beispiel: Entfernte Instanz mit HTTPS

```bash
ADGUARD_URL="https://dns.example.com"
ADGUARD_USER="admin"
ADGUARD_PASS="geheim"
```

AdGuard Shield ruft intern diesen Endpunkt ab:

```text
/control/querylog?limit=<API_QUERY_LIMIT>&response_status=all
```

**Hinweis:** Der HTTP-Client akzeptiert auch selbstsignierte TLS-Zertifikate. Das erleichtert lokale Setups, ersetzt aber keine saubere Absicherung der AdGuard-Home-Oberfläche.

---

## Querylog und Polling

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `CHECK_INTERVAL` | `10` | Abstand zwischen Querylog-Abfragen in Sekunden |
| `API_QUERY_LIMIT` | `500` | Anzahl der Querylog-Einträge pro API-Abfrage (max. 5000) |

### Empfehlungen

| Situation | Empfehlung |
|---|---|
| Normaler Betrieb | `CHECK_INTERVAL=10` ist ein guter Standard |
| Hohes DNS-Aufkommen | `API_QUERY_LIMIT` auf 1000–2000 erhöhen |
| `API_QUERY_LIMIT` zu niedrig | Spitzen im Querylog können zwischen zwei Polls verpasst werden |
| Sehr kurze Intervalle | Erzeugen mehr API-Last auf AdGuard Home |

---

## Rate-Limit

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `RATE_LIMIT_MAX_REQUESTS` | `30` | Maximale Anfragen pro Client und Domain im Zeitfenster |
| `RATE_LIMIT_WINDOW` | `60` | Zeitfenster in Sekunden |

Das bedeutet: Wenn ein Client dieselbe Domain mehr als 30-mal innerhalb von 60 Sekunden abfragt, wird er als auffällig erkannt und gesperrt.

### Empfohlene Startwerte

| Umgebung | `MAX_REQUESTS` | `WINDOW` | Hinweis |
|---|---:|---:|---|
| Kleines Heimnetz | `30` | `60` | Standardwerte |
| Viele Clients | `60`–`120` | `60` | Höherer Grenzwert für mehr Grundlast |
| Aktive Resolver/Forwarder | nach Bedarf | `60` | Zuerst Forwarder whitelisten |

**Wichtig:** Wenn ein Router, Reverse Proxy oder lokaler DNS-Forwarder stellvertretend für viele Clients fragt, sollte dieser Client in die Whitelist. Sonst sieht AdGuard Shield nur eine sehr aktive IP und sperrt den Forwarder statt der eigentlichen Verursacher.

---

## Subdomain-Flood-Erkennung

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `SUBDOMAIN_FLOOD_ENABLED` | `true` | Erkennung zufälliger Subdomains aktivieren |
| `SUBDOMAIN_FLOOD_MAX_UNIQUE` | `50` | Maximale eindeutige Subdomains pro Client und Basisdomain |
| `SUBDOMAIN_FLOOD_WINDOW` | `60` | Zeitfenster in Sekunden |

Diese Erkennung zielt auf Muster wie:

```text
a1b2.example.com
f8x9.example.com
zz12.example.com
```

Dabei zählt AdGuard Shield nicht die Gesamtzahl der Anfragen, sondern die Anzahl **unterschiedlicher** Subdomains unter derselben Basisdomain. Direkte Anfragen an `example.com` selbst zählen nicht.

### Hinweise

- Multi-Part-TLDs wie `.co.uk` werden korrekt als Basisdomain erkannt.
- CDNs und manche Apps nutzen legitim viele Subdomains. Betroffene Clients whitelisten oder Grenzwert erhöhen.

---

## DNS-Flood-Watchlist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `DNS_FLOOD_WATCHLIST_ENABLED` | `false` | Watchlist aktivieren |
| `DNS_FLOOD_WATCHLIST` | leer | Kommagetrennte Domainliste |

Die Watchlist ist für Domains gedacht, bei denen eine Überschreitung sofort hart behandelt werden soll, ohne progressive Stufen.

### Beispiel

```bash
DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com,apple.com"
```

### Matching-Logik

Wenn ein Client `login.microsoft.com` über das Rate-Limit bringt, wird sofort permanent gesperrt, weil `login.microsoft.com` zur Watchlist-Domain `microsoft.com` gehört. `evil-microsoft.com` würde dagegen **nicht** matchen.

### Folgen eines Watchlist-Treffers

| Aspekt | Verhalten |
|---|---|
| Grund | `dns-flood-watchlist` |
| Sperrdauer | Permanent |
| Progressive Sperren | Werden übersprungen |
| AbuseIPDB | Wird gemeldet, falls aktiviert |

---

## Sperrdauer und Firewall

| Parameter | Standard | Beschreibung |
|---|---|---|
| `BAN_DURATION` | `3600` | Basisdauer temporärer Monitor-Sperren in Sekunden (1 Stunde) |
| `IPTABLES_CHAIN` | `ADGUARD_SHIELD` | Name der eigenen Firewall-Chain |
| `BLOCKED_PORTS` | `53 443 853` | Ports, die für gesperrte Clients blockiert werden (Leerzeichen-getrennt) |
| `FIREWALL_BACKEND` | `ipset` | Firewall-Backend (ipset + iptables) |
| `FIREWALL_MODE` | `host` | Verkehrsweg der AdGuard-Home-Installation |
| `DRY_RUN` | `false` | Konfigurationsweiter Testmodus ohne echte Sperren |

### Blockierte Ports

| Port | Zweck |
|---:|---|
| `53` | Klassisches DNS über UDP/TCP |
| `443` | DNS-over-HTTPS (DoH), sofern AdGuard Home darüber erreichbar ist |
| `853` | DNS-over-TLS (DoT) und DNS-over-QUIC (DoQ) |

### Firewall-Modi

| Modus | Einsatz | Parent-Chain |
|---|---|---|
| `host` | Klassische AdGuard-Home-Installation direkt auf dem Host | `INPUT` |
| `docker-host` | Docker mit `network_mode: host` (Alias von `host`) | `INPUT` |
| `docker-bridge` | Docker mit veröffentlichten Ports, z.B. `-p 53:53` | `DOCKER-USER` |
| `hybrid` | Schützt Host-Ports und Docker-Forwarding gleichzeitig | `INPUT` + `DOCKER-USER` |

Details zu den Docker-Modi stehen in [Docker-Installationen](docker.md).

---

## Whitelist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `WHITELIST` | `127.0.0.1,::1` | IPs, die nie gesperrt werden (kommagetrennt) |

### Beispiel

```bash
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.10,fd00::1"
```

### Empfohlene Whitelist-Einträge

| Typ | Beispiel | Grund |
|---|---|---|
| Localhost | `127.0.0.1`, `::1` | Lokale Anfragen |
| Router/Gateway | `192.168.1.1` | Bündelt oft DNS für alle Clients |
| Admin-IPs | `192.168.1.10` | Eigene Management-Geräte |
| Monitoring | Monitoring-IP | Regelmäßige DNS-Checks |
| Interne Resolver | Resolver-IP | Fragt stellvertretend für viele Clients |
| VPN-Endpunkte | VPN-IP | Bündeln DNS-Anfragen vieler Nutzer |

**Wichtig:** Die Whitelist wird vor jeder Sperre geprüft. Das gilt für automatische, manuelle, GeoIP- und externe Blocklist-Sperren.

---

## Progressive Sperren

| Parameter | Standard | Beschreibung |
|---|---:|---|
| `PROGRESSIVE_BAN_ENABLED` | `true` | Wiederholungstäter stufenweise länger sperren |
| `PROGRESSIVE_BAN_MULTIPLIER` | `2` | Multiplikator pro Stufe (2 = Verdopplung) |
| `PROGRESSIVE_BAN_MAX_LEVEL` | `5` | Ab dieser Stufe permanent sperren (`0` = nie permanent durch Stufe) |
| `PROGRESSIVE_BAN_RESET_AFTER` | `86400` | Offense-Zähler nach so vielen Sekunden ohne neues Vergehen zurücksetzen |

### Stufenverlauf mit Standardwerten

| Vergehen | Stufe | Berechnung | Sperrdauer |
|---:|---:|---|---|
| 1 | 1 | 3600 × 2⁰ | 1 Stunde |
| 2 | 2 | 3600 × 2¹ | 2 Stunden |
| 3 | 3 | 3600 × 2² | 4 Stunden |
| 4 | 4 | 3600 × 2³ | 8 Stunden |
| 5 | 5 | Max-Level erreicht | Permanent |

Progressive Sperren gelten für Monitor-Sperren wie `rate-limit` und `subdomain-flood`. Watchlist-Treffer sind sofort permanent. GeoIP und externe Blocklisten haben eigene Regeln.

### Verwaltungsbefehle

```bash
sudo /opt/adguard-shield/adguard-shield offense-status         # Zähler anzeigen
sudo /opt/adguard-shield/adguard-shield offense-cleanup        # Abgelaufene entfernen
sudo /opt/adguard-shield/adguard-shield reset-offenses         # Alle zurücksetzen
sudo /opt/adguard-shield/adguard-shield reset-offenses <IP>    # Eine IP zurücksetzen
```

---

## Logging

| Parameter | Standard | Beschreibung |
|---|---|---|
| `LOG_FILE` | `/var/log/adguard-shield.log` | Datei für Daemon-Ereignisse |
| `LOG_LEVEL` | `INFO` | Minimales Log-Level |

### Verfügbare Log-Level

| Level | Beschreibung | Empfehlung |
|---|---|---|
| `DEBUG` | Detaillierte Informationen, z.B. einzelne API-Ergebnisse | Nur kurzzeitig für Fehlersuche |
| `INFO` | Normale Betriebsmeldungen (Start, Sperren, Freigaben) | Empfohlen für den produktiven Betrieb |
| `WARN` | Warnungen (API-Fehler, fehlende Dateien, Konfigurationsprobleme) | |
| `ERROR` | Fehler, die den Betrieb beeinträchtigen | |

### CLI-Befehle

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo /opt/adguard-shield/adguard-shield logs-follow debug
sudo /opt/adguard-shield/adguard-shield live
```

**Hinweis:** Query-Inhalte werden nicht dauerhaft ins Log geschrieben. Für Query-nahe Diagnose ist die Live-Ansicht gedacht.

---

## State und Runtime

| Parameter | Standard | Beschreibung |
|---|---|---|
| `STATE_DIR` | `/var/lib/adguard-shield` | Verzeichnis für SQLite-Datenbank und Caches |
| `PID_FILE` | `/var/run/adguard-shield.pid` | PID-Datei für direkten Vordergrundlauf |

### SQLite-Datei

```text
${STATE_DIR}/adguard-shield.db
```

### Weitere Dateien in STATE_DIR

| Datei/Verzeichnis | Inhalt |
|---|---|
| `adguard-shield.db` | Hauptdatenbank (Sperren, History, Offenses, Caches) |
| `adguard-shield.db-wal` | WAL-Datei (im laufenden Betrieb) |
| `adguard-shield.db-shm` | Shared-Memory-Datei (im laufenden Betrieb) |
| `external-blocklist/` | Cache für heruntergeladene Blocklisten |
| `external-whitelist/` | Cache für heruntergeladene Whitelists |
| `iptables-rules.v4` | Gesicherte IPv4-Firewall-Regeln |
| `iptables-rules.v6` | Gesicherte IPv6-Firewall-Regeln |

---

## Benachrichtigungen

| Parameter | Standard | Beschreibung |
|---|---|---|
| `NOTIFY_ENABLED` | `false` | Benachrichtigungen aktivieren |
| `NOTIFY_TYPE` | `ntfy` | Benachrichtigungskanal |
| `NOTIFY_WEBHOOK_URL` | leer | Webhook-URL (nicht für ntfy) |
| `NTFY_SERVER_URL` | `https://ntfy.sh` | Ntfy-Server |
| `NTFY_TOPIC` | leer | Ntfy-Topic |
| `NTFY_TOKEN` | leer | Optionaler Ntfy-Access-Token |
| `NTFY_PRIORITY` | `4` | Ntfy-Priorität (1–5) |

### Verfügbare Typen

| Typ | Beschreibung |
|---|---|
| `ntfy` | Ntfy Push-Benachrichtigungen (öffentlich oder selbst gehostet) |
| `discord` | Discord-Webhook |
| `slack` | Slack-Webhook |
| `gotify` | Gotify-Server |
| `generic` | Eigener Webhook-Endpunkt (JSON POST) |

### Beispiel: Ntfy

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC="mein-adguard-shield"
NTFY_PRIORITY="4"
```

### Beispiel: Discord

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="discord"
NOTIFY_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

Details zu allen Kanälen stehen in [Benachrichtigungen](benachrichtigungen.md).

---

## E-Mail-Reports

| Parameter | Standard | Beschreibung |
|---|---|---|
| `REPORT_ENABLED` | `false` | Report-Funktion logisch aktivieren |
| `REPORT_INTERVAL` | `weekly` | Versandintervall |
| `REPORT_TIME` | `08:00` | Versandzeit im Format `HH:MM` |
| `REPORT_EMAIL_TO` | `admin@example.com` | Empfängeradresse |
| `REPORT_EMAIL_FROM` | `adguard-shield@example.com` | Absenderadresse |
| `REPORT_FORMAT` | `html` | Report-Format |
| `REPORT_MAIL_CMD` | `msmtp` | Mailprogramm für den Versand |
| `REPORT_BUSIEST_DAY_RANGE` | `30` | Zeitraum für "Aktivster Tag" (Kompatibilitätsparameter) |

### Verfügbare Intervalle

| Intervall | Versand |
|---|---|
| `daily` | Täglich zur konfigurierten Uhrzeit |
| `weekly` | Montags zur konfigurierten Uhrzeit |
| `biweekly` | Am 1. und 15. des Monats |
| `monthly` | Am 1. des Monats |

### Verfügbare Formate

| Format | Beschreibung |
|---|---|
| `html` | HTML-formatierte E-Mail (empfohlen für Standard-Mail-Clients) |
| `txt` | Reiner Text (robuster für einfache Mail-Setups) |

### Beispiel

```bash
REPORT_ENABLED=true
REPORT_INTERVAL="weekly"
REPORT_TIME="08:00"
REPORT_EMAIL_TO="admin@example.com"
REPORT_EMAIL_FROM="adguard-shield@example.com"
REPORT_FORMAT="html"
REPORT_MAIL_CMD="msmtp"
```

### Cron-Job installieren

```bash
sudo /opt/adguard-shield/adguard-shield report-install
```

Details stehen in [E-Mail Report](report.md).

---

## Externe Whitelist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `EXTERNAL_WHITELIST_ENABLED` | `false` | Externe Whitelist aktivieren |
| `EXTERNAL_WHITELIST_URLS` | leer | Kommagetrennte URLs zu den Whitelist-Dateien |
| `EXTERNAL_WHITELIST_INTERVAL` | `300` | Synchronisationsintervall in Sekunden |
| `EXTERNAL_WHITELIST_CACHE_DIR` | `/var/lib/adguard-shield/external-whitelist` | Cache-Verzeichnis |

### Beispiel

```bash
EXTERNAL_WHITELIST_ENABLED=true
EXTERNAL_WHITELIST_URLS="https://example.com/trusted.txt"
EXTERNAL_WHITELIST_INTERVAL=300
```

### Listenformat

```text
# Hostnamen werden regelmäßig per DNS aufgelöst
mein-router.dyndns.org
vpn.example.com

# IPs und Netze direkt
192.168.1.10
10.0.0.0/24
2001:db8::1
```

### Mehrere Listen

```bash
EXTERNAL_WHITELIST_URLS="https://example.com/a.txt,https://example.net/b.txt"
```

### Verhalten

- Hostnamen werden per DNS aufgelöst und als IPs in SQLite gespeichert.
- Aufgelöste IPs werden bei jedem Sync aktualisiert.
- Bereits aktive Sperren werden aufgehoben, wenn die IP in der Whitelist auftaucht.
- Kommentare (`#`) und Inline-Kommentare werden unterstützt.

---

## Externe Blocklist

| Parameter | Standard | Beschreibung |
|---|---|---|
| `EXTERNAL_BLOCKLIST_ENABLED` | `false` | Externe Blocklist aktivieren |
| `EXTERNAL_BLOCKLIST_URLS` | leer | Kommagetrennte URLs |
| `EXTERNAL_BLOCKLIST_INTERVAL` | `300` | Synchronisationsintervall in Sekunden |
| `EXTERNAL_BLOCKLIST_BAN_DURATION` | `0` | Sperrdauer in Sekunden (`0` = permanent bis IP aus Liste entfernt) |
| `EXTERNAL_BLOCKLIST_AUTO_UNBAN` | `true` | IPs freigeben, wenn sie nicht mehr in der Liste stehen |
| `EXTERNAL_BLOCKLIST_NOTIFY` | `false` | Benachrichtigungen für Blocklist-Sperren senden |
| `EXTERNAL_BLOCKLIST_CACHE_DIR` | `/var/lib/adguard-shield/external-blocklist` | Cache-Verzeichnis |

### Beispiel

```bash
EXTERNAL_BLOCKLIST_ENABLED=true
EXTERNAL_BLOCKLIST_URLS="https://example.com/blocklist.txt"
EXTERNAL_BLOCKLIST_INTERVAL=300
EXTERNAL_BLOCKLIST_BAN_DURATION=0
EXTERNAL_BLOCKLIST_AUTO_UNBAN=true
EXTERNAL_BLOCKLIST_NOTIFY=false
```

### Unterstützte Listenformate

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

### Ignorierte Einträge

- URLs wie `https://...`
- IP:Port wie `203.0.113.50:8443`
- Hostnamen ohne Punkt oder mit ungültigen Zeichen
- Nicht auflösbare Hostnamen
- Blocking-Antworten wie `0.0.0.0` oder `::`

### Hinweise

- Große Listen können viele Sperren erzeugen. `EXTERNAL_BLOCKLIST_NOTIFY=false` ist deshalb der sichere Standard.
- Hostnamen mit mehreren IPs: Alle aufgelösten IPs werden verarbeitet.
- IPs aus der Whitelist werden nicht gesperrt.
- Bei `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` werden entfernte Einträge automatisch wieder freigegeben.

### Dateiformat-Empfehlungen

- UTF-8 ohne BOM
- Unix-Zeilenenden (`LF`)
- IP-Listen und Hostname-Listen möglichst getrennt pflegen

---

## AbuseIPDB

| Parameter | Standard | Beschreibung |
|---|---|---|
| `ABUSEIPDB_ENABLED` | `false` | AbuseIPDB-Reporting aktivieren |
| `ABUSEIPDB_API_KEY` | leer | API-Key von abuseipdb.com |
| `ABUSEIPDB_CATEGORIES` | `4` | Kategorien, kommagetrennt (siehe [abuseipdb.com/categories](https://www.abuseipdb.com/categories)) |

### Beispiel

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="dein-api-key"
ABUSEIPDB_CATEGORIES="4"
```

### Was gemeldet wird

| Wird gemeldet | Wird nicht gemeldet |
|---|---|
| Watchlist-Treffer (permanent) | Temporäre Sperren |
| Progressive-Ban auf Maximalstufe (permanent) | GeoIP-Sperren |
| | Externe Blocklist-Sperren |
| | Manuelle Sperren |

---

## GeoIP-Länderfilter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `GEOIP_ENABLED` | `false` | GeoIP-Filter aktivieren |
| `GEOIP_MODE` | `blocklist` | Filtermodus |
| `GEOIP_COUNTRIES` | leer | Ländercodes nach ISO 3166-1 Alpha-2 |
| `GEOIP_CHECK_INTERVAL` | `0` | Legacy-Parameter (Go-Version nutzt den zentralen Poller) |
| `GEOIP_NOTIFY` | `true` | Benachrichtigungen bei GeoIP-Sperren senden |
| `GEOIP_SKIP_PRIVATE` | `true` | Private/lokale IPs überspringen |
| `GEOIP_LICENSE_KEY` | leer | MaxMind-License-Key für automatischen Download |
| `GEOIP_MMDB_PATH` | leer | Manueller Pfad zur MaxMind-MMDB-Datei (hat Vorrang) |
| `GEOIP_CACHE_TTL` | `86400` | GeoIP-Cache-Dauer in Sekunden (Standard: 24 Stunden) |

### Modi

| Modus | Beschreibung |
|---|---|
| `blocklist` | Nur die genannten Länder werden gesperrt. Alle anderen sind erlaubt. |
| `allowlist` | Nur die genannten Länder sind erlaubt. Alle anderen öffentlichen IPs werden gesperrt. |

### Ländercodes

Die Ländercodes folgen dem Standard **ISO 3166-1 Alpha-2**. Eine vollständige Liste aller Ländercodes findest du in der [ISO-3166-1-Kodierliste auf Wikipedia](https://de.wikipedia.org/wiki/ISO-3166-1-Kodierliste).

Häufig verwendete Codes:

| Code | Land | | Code | Land |
|---|---|---|---|---|
| `DE` | Deutschland | | `CN` | China |
| `AT` | Österreich | | `RU` | Russland |
| `CH` | Schweiz | | `KP` | Nordkorea |
| `US` | Vereinigte Staaten | | `IR` | Iran |
| `GB` | Vereinigtes Königreich | | `BR` | Brasilien |
| `FR` | Frankreich | | `IN` | Indien |
| `NL` | Niederlande | | `VN` | Vietnam |

### Beispiel: Blocklist-Modus

```bash
GEOIP_ENABLED=true
GEOIP_MODE="blocklist"
GEOIP_COUNTRIES="CN,RU,KP,IR"
```

Damit werden öffentliche DNS-Clients aus China, Russland, Nordkorea und dem Iran gesperrt.

### Beispiel: Allowlist-Modus

```bash
GEOIP_ENABLED=true
GEOIP_MODE="allowlist"
GEOIP_COUNTRIES="DE,AT,CH"
```

Damit werden nur Clients aus Deutschland, Österreich und der Schweiz erlaubt. Alle anderen öffentlichen Länder werden gesperrt.

### Private IPs

```bash
GEOIP_SKIP_PRIVATE=true
```

Damit werden folgende Adressbereiche übersprungen:

- Private Netze (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-Local (169.254.0.0/16, fe80::/10)
- CGNAT (100.64.0.0/10)

### GeoIP-Datenquellen

| Priorität | Quelle | Konfiguration |
|---:|---|---|
| 1 | Manueller MMDB-Pfad | `GEOIP_MMDB_PATH="/usr/share/GeoIP/GeoLite2-Country.mmdb"` |
| 2 | Automatischer MaxMind-Download | `GEOIP_LICENSE_KEY="dein_maxmind_license_key"` |
| 3 | Legacy-Fallback | `geoiplookup` / `geoiplookup6` Systembefehle |

### Automatischer MaxMind-Download

```bash
GEOIP_LICENSE_KEY="dein_maxmind_license_key"
```

Die Datenbank wird unter `/opt/adguard-shield/geoip/` gespeichert und nach 24 Stunden automatisch erneuert.

### GeoIP-Befehle

```bash
sudo /opt/adguard-shield/adguard-shield geoip-status         # Status anzeigen
sudo /opt/adguard-shield/adguard-shield geoip-lookup 8.8.8.8 # IP nachschlagen
sudo /opt/adguard-shield/adguard-shield geoip-sync            # Clients prüfen
sudo /opt/adguard-shield/adguard-shield geoip-flush-cache     # Cache leeren
sudo /opt/adguard-shield/adguard-shield geoip-flush           # Alle GeoIP-Sperren aufheben
```

---

## Protokollerkennung

AdGuard Shield liest das Feld `client_proto` aus der AdGuard-Home-API und zeigt das verwendete DNS-Protokoll an.

| API-Wert | Anzeige | Bedeutung |
|---|---|---|
| leer oder `dns` | `DNS` | Klassisches DNS |
| `doh` | `DoH` | DNS-over-HTTPS |
| `dot` | `DoT` | DNS-over-TLS |
| `doq` | `DoQ` | DNS-over-QUIC |
| `dnscrypt` | `DNSCrypt` | DNSCrypt-Protokoll |

Die Sperre blockiert immer alle konfigurierten Ports, unabhängig davon, welches Protokoll den Verstoß ausgelöst hat.

---

## Beispielkonfiguration: Heimnetz

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

## Beispielkonfiguration: Öffentlicher Resolver

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

GEOIP_ENABLED=true
GEOIP_MODE="blocklist"
GEOIP_COUNTRIES="CN,RU,KP,IR"
GEOIP_LICENSE_KEY="..."

ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."

NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_TOPIC="adguard-shield-prod"
```

### Vor produktiver Aktivierung

```bash
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield dry-run
```
