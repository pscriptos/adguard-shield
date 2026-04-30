# Architektur & Funktionsweise

Dieses Dokument erklärt, wie AdGuard Shield intern arbeitet. Es geht dabei nicht nur um die Dateien auf dem System, sondern auch um den Weg einer DNS-Anfrage vom AdGuard-Home-Querylog bis zur Firewall-Sperre und die Logik hinter jeder Erkennungsmethode.

## Kurzüberblick

AdGuard Shield besteht in der Go-Version aus einem einzelnen Binary:

```text
/opt/adguard-shield/adguard-shield
```

Das Binary übernimmt alle Aufgaben, die früher auf mehrere Shell-Skripte verteilt waren:

- Querylog-Polling über die AdGuard-Home-API
- Erkennung von Rate-Limit-Verstößen
- Erkennung von Random-Subdomain-Floods
- DNS-Flood-Watchlist mit sofortigem Permanent-Ban
- Verwaltung aktiver Sperren in SQLite
- Firewall-Steuerung über `ipset`, `iptables` und `ip6tables`
- automatische Freigabe abgelaufener temporärer Sperren
- externe Blocklisten und externe Whitelists
- GeoIP-Länderfilter
- progressive Sperren für Wiederholungstäter
- Benachrichtigungen und AbuseIPDB-Reporting
- E-Mail-Reports

## Datenfluss

```text
Clients
  │
  │ DNS, DoH, DoT, DoQ, DNSCrypt
  ▼
AdGuard Home
  │
  │ /control/querylog
  ▼
AdGuard Shield Go-Daemon
  │
  ├── Rate-Limit-Prüfung pro Client + Domain
  ├── Subdomain-Flood-Prüfung pro Client + Basisdomain
  ├── Watchlist-Prüfung
  ├── Whitelist-Prüfung (statisch + extern)
  ├── GeoIP-Prüfung
  ├── Progressive Ban-Berechnung
  ├── externe Listen-Abgleich
  ▼
SQLite State
  │
  ▼
ipset + iptables/ip6tables
  │
  ▼
DNS-relevante Ports werden für gesperrte Clients blockiert
```

**Wichtig:** AdGuard Shield analysiert nicht den Netzwerkverkehr direkt. Es liest das Querylog von AdGuard Home. Dadurch erkennt es auch Anfragen über verschlüsselte DNS-Protokolle (DoH, DoT, DoQ, DNSCrypt), solange diese in AdGuard Home sichtbar sind.

## Laufzeit im produktiven Betrieb

Der systemd-Service startet den Daemon so:

```bash
/opt/adguard-shield/adguard-shield -config /opt/adguard-shield/adguard-shield.conf run
```

Beim Start passiert in dieser Reihenfolge:

| Schritt | Aktion | Beschreibung |
|---:|---|---|
| 1 | Konfiguration laden | Liest `adguard-shield.conf` und validiert alle Parameter |
| 2 | SQLite-Datenbank öffnen | Öffnet oder erstellt die Datenbank unter `STATE_DIR` im WAL-Modus |
| 3 | Logdatei öffnen | Initialisiert die Datei unter `LOG_FILE` |
| 4 | Firewall vorbereiten | Erstellt Chain und ipsets, falls nicht vorhanden |
| 5 | GeoIP öffnen | Lädt die MaxMind-Datenbank, falls GeoIP aktiviert ist |
| 6 | Whitelist-Cache laden | Liest aufgelöste externe Whitelist-IPs aus SQLite |
| 7 | GeoIP-Reconcile | Prüft bestehende GeoIP-Sperren gegen aktuelle Konfiguration |
| 8 | Firewall-Reconcile | Überträgt aktive Sperren aus SQLite wieder in die Firewall |
| 9 | Hintergrundjobs starten | Startet Goroutines für externe Listen und Offense-Cleanup |
| 10 | Querylog-Poller starten | Beginnt mit der regelmäßigen Auswertung des Querylogs |

Das Reconcile beim Start ist besonders wichtig: Wenn der Server neu startet oder `iptables`-Regeln verloren gehen (z.B. durch einen Reboot), bleiben die Sperren in SQLite erhalten und werden beim nächsten Start wieder in die Firewall übertragen.

## Querylog-Poller

Der Daemon ruft regelmäßig den AdGuard-Home-Endpunkt ab:

```text
/control/querylog?limit=<API_QUERY_LIMIT>&response_status=all
```

Gesteuert wird das über:

```bash
CHECK_INTERVAL=10       # Abstand zwischen Abfragen in Sekunden
API_QUERY_LIMIT=500     # Maximale Einträge pro API-Abfrage
```

Aus jedem Querylog-Eintrag werden diese Informationen extrahiert:

| Feld | Verwendung |
|---|---|
| Zeitstempel | Bestimmt, ob die Anfrage im aktuellen Zeitfenster liegt |
| Client-IP | Schlüssel für Rate-Limit, Whitelist, GeoIP und Firewall |
| Domain | Schlüssel für Rate-Limit und Subdomain-Flood |
| `client_proto` | Anzeige von DNS, DoH, DoT, DoQ oder DNSCrypt |

Bereits gesehene Querylog-Einträge werden im Speicher dedupliziert. Der Daemon hält nur Ereignisse aus dem relevanten Zeitfenster plus kleinem Puffer vor, sodass der Speicherverbrauch auch bei hohem DNS-Aufkommen stabil bleibt.

## Erkennungsmethoden im Detail

### Rate-Limit-Sperre

Eine Rate-Limit-Sperre entsteht, wenn ein Client dieselbe Domain innerhalb des konfigurierten Fensters zu oft abfragt.

**Konfiguration:**

```bash
RATE_LIMIT_MAX_REQUESTS=30   # Maximale Anfragen pro Client und Domain
RATE_LIMIT_WINDOW=60         # Zeitfenster in Sekunden
```

**Ablauf am Beispiel:**

1. Client `192.168.1.50` fragt `example.com` 45-mal innerhalb von 60 Sekunden ab.
2. Der Poller sieht diese Einträge im Querylog.
3. AdGuard Shield zählt pro Client und Domain.
4. `45 > 30`, also ist das Limit überschritten.
5. Die IP wird gegen statische und externe Whitelists geprüft.
6. Falls die Domain nicht auf der Watchlist steht, entsteht eine normale `rate-limit`-Sperre.
7. Bei aktivem Progressive-Ban wird die aktuelle Offense-Stufe berechnet.
8. Die IP wird in SQLite gespeichert und per Firewall blockiert.
9. History, Log und optionale Benachrichtigung werden geschrieben.

### Subdomain-Flood-Erkennung

Random-Subdomain-Floods sehen anders aus als normale Wiederholungen. Ein Client fragt nicht eine Domain ständig ab, sondern erzeugt viele verschiedene, oft zufällige Subdomains:

```text
a8f3.example.com
k29x.example.com
z9p1.example.com
m7q2.example.com
```

AdGuard Shield extrahiert daraus die Basisdomain `example.com` und zählt pro Client, wie viele **unterschiedliche** Subdomains im Fenster vorkommen. Direkte Anfragen an `example.com` selbst werden bei dieser Erkennung nicht mitgezählt.

**Konfiguration:**

```bash
SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=50    # Maximale eindeutige Subdomains
SUBDOMAIN_FLOOD_WINDOW=60        # Zeitfenster in Sekunden
```

**Ablauf am Beispiel:**

1. Client `10.0.0.99` fragt 63 verschiedene Subdomains von `example.com` ab.
2. Sobald mehr als `SUBDOMAIN_FLOOD_MAX_UNIQUE` eindeutige Subdomains erkannt werden, wird gesperrt.
3. In der History erscheint die Domain als `*.example.com`.
4. Der Grund lautet `subdomain-flood`, außer die Basisdomain steht auf der DNS-Flood-Watchlist.

**Hinweise:**

- Multi-Part-TLDs wie `.co.uk` werden korrekt als Basisdomain erkannt.
- CDNs und manche Apps erzeugen legitim viele Subdomains. In solchen Fällen den Grenzwert erhöhen oder den Client whitelisten.

### DNS-Flood-Watchlist

Die Watchlist ist für Domains gedacht, bei denen du nicht stufenweise reagieren möchtest. Wenn eine Domain auf der Watchlist steht und gleichzeitig ein Rate-Limit- oder Subdomain-Flood-Verstoß erkannt wird, wird sofort permanent gesperrt.

**Konfiguration:**

```bash
DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com"
```

**Matching-Logik:**

| Anfrage | Watchlist-Eintrag | Treffer? |
|---|---|---|
| `microsoft.com` | `microsoft.com` | Ja |
| `login.microsoft.com` | `microsoft.com` | Ja |
| `evil-microsoft.com` | `microsoft.com` | Nein |

**Bei einem Treffer:**

- Reason wird `dns-flood-watchlist`
- Sperre ist immer permanent
- Progressive-Ban-Stufen werden für die Dauer ignoriert
- AbuseIPDB-Reporting wird ausgelöst, wenn aktiviert und ein API-Key vorhanden ist

### Progressive Sperren

Progressive Sperren erhöhen die Sperrdauer bei wiederholten Verstößen. Das Verhalten ähnelt fail2ban.

**Konfiguration:**

```bash
BAN_DURATION=3600                   # Basis-Sperrdauer: 1 Stunde
PROGRESSIVE_BAN_ENABLED=true
PROGRESSIVE_BAN_MULTIPLIER=2        # Verdopplung pro Stufe
PROGRESSIVE_BAN_MAX_LEVEL=5          # Ab Stufe 5 permanent
PROGRESSIVE_BAN_RESET_AFTER=86400    # Zähler-Reset nach 24h ohne Vergehen
```

**Stufenverlauf mit Standardwerten:**

| Vergehen | Stufe | Berechnung | Sperrdauer |
|---:|---:|---|---|
| 1 | 1 | 3600 × 2⁰ | 1 Stunde |
| 2 | 2 | 3600 × 2¹ | 2 Stunden |
| 3 | 3 | 3600 × 2² | 4 Stunden |
| 4 | 4 | 3600 × 2³ | 8 Stunden |
| 5 | 5 | Max-Level erreicht | Permanent |

Der Offense-Zähler wird in SQLite gespeichert. Wenn eine IP länger als `PROGRESSIVE_BAN_RESET_AFTER` (Standard: 24 Stunden) nicht auffällig war, wird der Zähler vom Cleanup-Job entfernt.

**Geltungsbereich:** Progressive Sperren gelten nur für Monitor-Sperren (`rate-limit`, `subdomain-flood`). Watchlist-Treffer sind sofort permanent. GeoIP- und externe Blocklist-Sperren haben eigene Regeln.

## Firewall-Modell

AdGuard Shield nutzt eine eigene Chain und zwei ipsets, um gesperrte IPs effizient zu verwalten:

```text
Chain:  ADGUARD_SHIELD
IPv4:   adguard_shield_v4
IPv6:   adguard_shield_v6
```

### Chain-Einbindung

Die Chain wird je nach `FIREWALL_MODE` in die passende Host-Chain eingehängt:

| Modus | Parent-Chain | Einsatzgebiet |
|---|---|---|
| `host` / `docker-host` | `INPUT` | Klassische Installation oder Docker mit Host-Netzwerk |
| `docker-bridge` | `DOCKER-USER` | Docker mit veröffentlichten Ports (`-p 53:53`) |
| `hybrid` | `INPUT` und `DOCKER-USER` | Gemischte Setups oder Migrationsphasen |

### Regelstruktur im Host-Modus

```text
INPUT
  ├── tcp/53  → ADGUARD_SHIELD
  ├── udp/53  → ADGUARD_SHIELD
  ├── tcp/443 → ADGUARD_SHIELD
  ├── udp/443 → ADGUARD_SHIELD
  ├── tcp/853 → ADGUARD_SHIELD
  └── udp/853 → ADGUARD_SHIELD

ADGUARD_SHIELD
  ├── src in adguard_shield_v4 → DROP
  └── src in adguard_shield_v6 → DROP
```

Bei Docker Bridge mit veröffentlichten Ports ersetzt `DOCKER-USER` die `INPUT`-Chain. Docker leitet solche Pakete nach DNAT über `FORWARD`; die `INPUT`-Chain sieht sie dort nicht zuverlässig.

### Blockierte Ports

Die Ports werden über `BLOCKED_PORTS` konfiguriert:

```bash
BLOCKED_PORTS="53 443 853"
```

| Port | Protokoll | Zweck |
|---:|---|---|
| 53 | UDP/TCP | Klassisches DNS |
| 443 | TCP | DNS-over-HTTPS (DoH) |
| 853 | TCP/UDP | DNS-over-TLS (DoT) und DNS-over-QUIC (DoQ) |

Die Erkennung basiert auf dem AdGuard-Home-Querylog, die Sperre blockiert aber alle konfigurierten Ports, unabhängig davon, welches Protokoll den Verstoß ausgelöst hat.

### Warum ipset?

- Viele gesperrte IPs erzeugen nicht tausende einzelne `iptables`-Regeln
- IPv4 und IPv6 werden getrennt sauber verwaltet
- Sperren und Freigaben sind performant, auch bei hunderten IPs
- Die eigene Chain bleibt übersichtlich und beeinträchtigt bestehende Regeln nicht

## SQLite-State

Der zentrale Zustand liegt standardmäßig hier:

```text
/var/lib/adguard-shield/adguard-shield.db
```

### Tabellen

| Tabelle | Inhalt | Beschreibung |
|---|---|---|
| `active_bans` | Aktive Sperren | IP, Grund, Dauer, Quelle, Ablaufzeit, Offense-Level, GeoIP-Metadaten |
| `ban_history` | Dauerhafte Historie | Zeitstempel, Aktion (BAN/UNBAN/DRY), Client-IP, Domain, Protokoll, Grund |
| `offense_tracking` | Progressive-Ban-Stufen | Client-IP, aktuelle Offense-Stufe, letzter Verstoß |
| `whitelist_cache` | Externe Whitelist | Aufgelöste IPs aus externen Whitelist-URLs mit Quellzuordnung |
| `geoip_cache` | GeoIP-Ergebnisse | IP, Ländercode, Zeitstempel der Abfrage, DB-Änderungszeitpunkt |

Die Datenbank nutzt WAL-Modus (Write-Ahead Logging) und einen Busy-Timeout, damit Daemon und CLI-Befehle gleichzeitig lesen und schreiben können, ohne sich gegenseitig zu blockieren.

### History-Aktionen

| Aktion | Bedeutung |
|---|---|
| `BAN` | Aktive Sperre gesetzt (Firewall-Regel erstellt) |
| `UNBAN` | Sperre aufgehoben (manuell, abgelaufen oder durch Whitelist) |
| `DRY` | Sperre wäre gesetzt worden, wurde aber im Dry-Run nur protokolliert |

## Verzeichnisstruktur

Nach einer Standardinstallation sieht die Struktur so aus:

```text
/opt/adguard-shield/
├── adguard-shield                 # Go-Binary
├── adguard-shield.conf            # Konfiguration, chmod 600
├── adguard-shield.conf.old        # Backup nach Konfigurationsmigration
└── geoip/                         # automatische MaxMind-Downloads

/etc/systemd/system/
└── adguard-shield.service

/var/lib/adguard-shield/
├── adguard-shield.db              # SQLite State-Datenbank
├── adguard-shield.db-wal          # WAL-Datei (im laufenden Betrieb)
├── adguard-shield.db-shm          # Shared-Memory-Datei (im laufenden Betrieb)
├── external-blocklist/            # Cache für heruntergeladene Blocklisten
├── external-whitelist/            # Cache für heruntergeladene Whitelists
├── iptables-rules.v4              # Gesicherte IPv4-Regeln (nach firewall-save)
└── iptables-rules.v6              # Gesicherte IPv6-Regeln (nach firewall-save)

/var/log/
└── adguard-shield.log             # Daemon-Logdatei

/etc/cron.d/
└── adguard-shield-report          # Cron-Job für Reports (optional)
```

## Hintergrundjobs im Daemon

Es gibt in der Go-Version keine separaten Worker-Skripte mehr. Diese Aufgaben laufen als Goroutines im Daemon:

| Aufgabe | Wann aktiv | Intervall | Zweck |
|---|---|---|---|
| Querylog-Poller | Immer | `CHECK_INTERVAL` | Liest und analysiert AdGuard-Home-Querylogs |
| Externe Whitelist | `EXTERNAL_WHITELIST_ENABLED=true` | `EXTERNAL_WHITELIST_INTERVAL` | Lädt Listen, löst Hostnamen auf, aktualisiert Whitelist-Cache |
| Externe Blocklist | `EXTERNAL_BLOCKLIST_ENABLED=true` | `EXTERNAL_BLOCKLIST_INTERVAL` | Lädt Listen, sperrt neue IPs, hebt entfernte IPs optional auf |
| Offense-Cleanup | `PROGRESSIVE_BAN_ENABLED=true` | Stündlich | Entfernt abgelaufene Offense-Zähler |
| GeoIP-Lookups | `GEOIP_ENABLED=true` | Mit jedem Poll | Prüft neue öffentliche Client-IPs gegen Länderregeln |

Externe Whitelist und Blocklist laufen sofort beim Start einmalig und danach im jeweiligen Intervall. Die Sperren-Freigabe abgelaufener Bans wird bei jedem Querylog-Poll mit geprüft.

## Whitelist-Logik

Vor jeder Sperre wird geprüft, ob die IP vertrauenswürdig ist.

**Quellen (in Prüfreihenfolge):**

1. Statische `WHITELIST` aus der Konfiguration (kommagetrennt)
2. Aufgelöste IPs aus externen Whitelists (gespeichert in SQLite)

**Verhalten:**

- Eine gewhitelistete IP wird nie gesperrt, unabhängig von der Sperrquelle.
- Dies gilt für automatische Sperren, manuelle Sperren, GeoIP-Sperren und externe Blocklist-Sperren.
- Wenn eine externe Whitelist später eine bereits gesperrte IP enthält, hebt der Daemon diese Sperre automatisch auf.

## GeoIP-Logik

GeoIP arbeitet mit der MaxMind GeoLite2-Datenbank und filtert DNS-Clients nach ihrem geografischen Herkunftsland.

### Private IPs

Wenn `GEOIP_SKIP_PRIVATE=true` gesetzt ist (Standard), werden folgende Adressbereiche übersprungen:

- Private Netze (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-Local (169.254.0.0/16, fe80::/10)
- CGNAT (100.64.0.0/10)

### Modi

| Modus | Verhalten |
|---|---|
| `blocklist` | Nur die in `GEOIP_COUNTRIES` genannten Länder werden gesperrt. Alle anderen sind erlaubt. |
| `allowlist` | Nur die in `GEOIP_COUNTRIES` genannten Länder sind erlaubt. Alle anderen öffentlichen IPs werden gesperrt. |

Die Ländercodes folgen dem Standard ISO 3166-1 Alpha-2 (siehe [ISO-3166-1-Kodierliste auf Wikipedia](https://de.wikipedia.org/wiki/ISO-3166-1-Kodierliste)).

### GeoIP-Datenquellen (Priorität)

| Priorität | Quelle | Konfiguration |
|---:|---|---|
| 1 | Manueller MMDB-Pfad | `GEOIP_MMDB_PATH="/pfad/zur/GeoLite2-Country.mmdb"` |
| 2 | Automatischer MaxMind-Download | `GEOIP_LICENSE_KEY="dein_key"` |
| 3 | Legacy-Fallback | `geoiplookup` / `geoiplookup6` (Systembefehle) |

**GeoIP-Sperren sind permanent**, werden aber beim Start gegen die aktuelle Konfiguration geprüft. Wenn GeoIP deaktiviert wird, der Modus wechselt oder ein Land nicht mehr blockiert werden müsste, wird die Sperre automatisch aufgehoben.

## AbuseIPDB-Reporting

AbuseIPDB wird nur für **permanente** Monitor-Sperren genutzt:

| Wird gemeldet | Wird nicht gemeldet |
|---|---|
| DNS-Flood-Watchlist-Treffer | Temporäre Rate-Limit-Sperren |
| Progressive-Ban auf Maximalstufe | Manuelle Sperren |
| | GeoIP-Sperren |
| | Externe Blocklist-Sperren |

**Konfiguration:**

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."
ABUSEIPDB_CATEGORIES="4"     # 4 = DDoS Attack
```

Die Kategorie-Nummern sind auf [abuseipdb.com/categories](https://www.abuseipdb.com/categories) dokumentiert.

## Protokollerkennung

AdGuard Shield liest das Feld `client_proto` aus der AdGuard-Home-API und zeigt das Protokoll in History, Logs und Benachrichtigungen an:

| API-Wert | Anzeige | Beschreibung |
|---|---|---|
| leer oder `dns` | `DNS` | Klassisches DNS über UDP/TCP |
| `doh` | `DoH` | DNS-over-HTTPS |
| `dot` | `DoT` | DNS-over-TLS |
| `doq` | `DoQ` | DNS-over-QUIC |
| `dnscrypt` | `DNSCrypt` | DNSCrypt-Protokoll |

Die Sperre blockiert die konfigurierten Ports unabhängig davon, welches Protokoll den Verstoß ausgelöst hat. So wird verhindert, dass ein gesperrter Client einfach auf ein anderes DNS-Protokoll ausweicht.

## History und Logs

Es gibt zwei unterschiedliche Blickwinkel auf das Geschehen:

| Quelle | Inhalt | Befehl |
|---|---|---|
| `ban_history` in SQLite | Sperren, Freigaben und Dry-Run-Ereignisse | `history [N]` |
| `LOG_FILE` | Daemon-Ereignisse, Worker-Läufe, Warnungen, Fehler | `logs`, `logs-follow` |
| Live-Ansicht | Aktuelle Queries, Top-Clients, Sperren, Systemereignisse | `live` |

**Wichtig:** Query-Inhalte werden nicht dauerhaft in die Logdatei geschrieben. Für aktuelle Queries ist die Live-Ansicht (`live`) gedacht.

### History-Gründe

| Grund | Bedeutung |
|---|---|
| `rate-limit` | Gleiche Domain zu oft angefragt |
| `subdomain-flood` | Zu viele eindeutige Subdomains einer Basisdomain |
| `dns-flood-watchlist` | Watchlist-Treffer mit sofortigem Permanent-Ban |
| `external-blocklist` | Sperre aus externer Blocklist |
| `geoip` | GeoIP-Länderfilter |
| `manual` | Manueller Ban oder Unban |
| `manual-flush` | Freigabe aller Sperren durch `flush` |
| `expired` | Temporäre Sperre ist abgelaufen |
| `external-whitelist` | Freigabe durch externe Whitelist |

## Unterschied zur alten Shell-Architektur

Früher gab es unter anderem:

- `adguard-shield.sh` (Hauptskript)
- `iptables-helper.sh` (Firewall-Management)
- `external-blocklist-worker.sh` (Blocklist-Synchronisation)
- `external-whitelist-worker.sh` (Whitelist-Synchronisation)
- `geoip-worker.sh` (GeoIP-Prüfung)
- `offense-cleanup-worker.sh` (Offense-Bereinigung)
- `report-generator.sh` (Report-Erstellung)
- `unban-expired.sh` (Ablauf temporärer Sperren)
- Watchdog-Service und Watchdog-Timer (Überwachung)

In der Go-Version gibt es diese Skripte nicht mehr. Der systemd-Service nutzt `Restart=on-failure`; die eigentlichen Worker laufen als Goroutines im Daemon. Alte Artefakte werden vom Installer erkannt und müssen vor der Go-Installation entfernt werden, damit nicht zwei Implementierungen parallel dieselbe Firewall und dieselben Dateien verwalten.
