# Architektur & Funktionsweise

Dieses Dokument erklärt, wie AdGuard Shield intern arbeitet. Es geht dabei nicht nur um die Dateien auf dem System, sondern auch um den Weg einer DNS-Anfrage vom AdGuard-Home-Querylog bis zur Firewall-Sperre.

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
  |
  | DNS, DoH, DoT, DoQ, DNSCrypt
  v
AdGuard Home
  |
  | /control/querylog
  v
AdGuard Shield Go-Daemon
  |
  |-- Rate-Limit-Prüfung pro Client + Domain
  |-- Subdomain-Flood-Prüfung pro Client + Basisdomain
  |-- Watchlist-Prüfung
  |-- Whitelist-Prüfung
  |-- GeoIP-Prüfung
  |-- externe Listen
  v
SQLite State
  |
  v
ipset + iptables/ip6tables
  |
  v
DNS-relevante Ports werden für gesperrte Clients blockiert
```

Wichtig: AdGuard Shield analysiert nicht den Netzwerkverkehr direkt. Es liest das Querylog von AdGuard Home. Dadurch erkennt es auch Anfragen über moderne DNS-Protokolle, solange diese in AdGuard Home sichtbar sind.

## Laufzeit im produktiven Betrieb

Der systemd-Service startet den Daemon so:

```bash
/opt/adguard-shield/adguard-shield -config /opt/adguard-shield/adguard-shield.conf run
```

Beim Start passiert in dieser Reihenfolge:

1. Konfiguration wird geladen.
2. SQLite-Datenbank unter `STATE_DIR` wird geöffnet oder angelegt.
3. Logdatei wird geöffnet.
4. Firewall-Chain und ipsets werden vorbereitet.
5. GeoIP-Datenbank wird geöffnet, falls GeoIP aktiv ist.
6. Whitelist-Cache wird aus SQLite geladen.
7. GeoIP-Sperren werden gegen die aktuelle GeoIP-Konfiguration geprüft.
8. Aktive Sperren aus SQLite werden wieder in die Firewall geschrieben.
9. Hintergrundjobs für externe Whitelist, externe Blocklist und Offense-Cleanup starten, falls aktiviert.
10. Der zentrale Querylog-Poller beginnt mit der regelmäßigen Auswertung.

Das Reconcile beim Start ist wichtig: Wenn der Server neu startet oder iptables-Regeln verloren gehen, bleiben die Sperren in SQLite erhalten und werden beim nächsten Start wieder in die Firewall übertragen.

## Querylog-Poller

Der Daemon ruft regelmäßig den AdGuard-Home-Endpunkt ab:

```text
/control/querylog?limit=<API_QUERY_LIMIT>&response_status=all
```

Gesteuert wird das über:

```bash
CHECK_INTERVAL=10
API_QUERY_LIMIT=500
```

Aus jedem Querylog-Eintrag werden diese Informationen extrahiert:

| Feld | Verwendung |
|---|---|
| Zeitstempel | Bestimmt, ob die Anfrage im aktuellen Zeitfenster liegt |
| Client-IP | Schlüssel für Rate-Limit, Whitelist, GeoIP und Firewall |
| Domain | Schlüssel für Rate-Limit und Subdomain-Flood |
| `client_proto` | Anzeige von DNS, DoH, DoT, DoQ oder DNSCrypt |

Bereits gesehene Querylog-Einträge werden im Speicher dedupliziert. Der Daemon hält nur Ereignisse aus dem relevanten Zeitfenster plus kleinem Puffer vor.

## Rate-Limit-Sperre

Eine Rate-Limit-Sperre entsteht, wenn ein Client dieselbe Domain innerhalb des konfigurierten Fensters zu oft abfragt.

Beispiel:

```bash
RATE_LIMIT_MAX_REQUESTS=30
RATE_LIMIT_WINDOW=60
```

Ablauf:

1. Client `192.168.1.50` fragt `example.com` 45-mal innerhalb von 60 Sekunden ab.
2. Der Poller sieht diese Einträge im Querylog.
3. AdGuard Shield zählt pro Client und Domain.
4. `45 > 30`, also ist das Limit überschritten.
5. Die IP wird gegen statische und externe Whitelists geprüft.
6. Falls die Domain nicht auf der Watchlist steht, entsteht eine normale `rate-limit`-Sperre.
7. Bei aktivem Progressive-Ban wird die aktuelle Offense-Stufe berechnet.
8. Die IP wird in SQLite gespeichert und per Firewall blockiert.
9. History, Log und optionale Benachrichtigung werden geschrieben.

## Subdomain-Flood-Erkennung

Random-Subdomain-Floods sehen anders aus als normale Wiederholungen. Ein Client fragt nicht eine Domain ständig neu ab, sondern viele zufällige Subdomains:

```text
a8f3.example.com
k29x.example.com
z9p1.example.com
```

AdGuard Shield extrahiert daraus die Basisdomain `example.com` und zählt pro Client, wie viele unterschiedliche Subdomains im Fenster vorkommen.

Gesteuert wird das über:

```bash
SUBDOMAIN_FLOOD_ENABLED=true
SUBDOMAIN_FLOOD_MAX_UNIQUE=50
SUBDOMAIN_FLOOD_WINDOW=60
```

Ablauf:

1. Client `10.0.0.99` fragt 63 verschiedene Subdomains von `example.com` ab.
2. Direkte Anfragen an `example.com` zählen für diese Erkennung nicht.
3. Sobald mehr als `SUBDOMAIN_FLOOD_MAX_UNIQUE` eindeutige Subdomains erkannt werden, wird gesperrt.
4. In der History erscheint die Domain als `*.example.com`.
5. Der Grund lautet `subdomain-flood`, außer die Basisdomain steht auf der DNS-Flood-Watchlist.

## DNS-Flood-Watchlist

Die Watchlist ist für Domains gedacht, bei denen du nicht stufenweise reagieren möchtest. Wenn eine Domain auf der Watchlist steht und gleichzeitig ein Rate-Limit- oder Subdomain-Flood-Verstoß erkannt wird, wird sofort permanent gesperrt.

```bash
DNS_FLOOD_WATCHLIST_ENABLED=true
DNS_FLOOD_WATCHLIST="microsoft.com,google.com"
```

Matching:

- `microsoft.com` matcht `microsoft.com`
- `login.microsoft.com` matcht ebenfalls `microsoft.com`
- `evil-microsoft.com` matcht nicht

Bei einem Treffer:

- Reason wird `dns-flood-watchlist`
- Sperre ist permanent
- Progressive-Ban-Stufen werden für die Dauer ignoriert
- AbuseIPDB-Reporting kann ausgelöst werden, wenn es aktiviert und ein API-Key vorhanden ist

## Progressive Sperren

Progressive Sperren erhöhen die Sperrdauer bei wiederholten Monitor-Sperren. Das Verhalten ähnelt fail2ban.

Standard:

```bash
BAN_DURATION=3600
PROGRESSIVE_BAN_ENABLED=true
PROGRESSIVE_BAN_MULTIPLIER=2
PROGRESSIVE_BAN_MAX_LEVEL=5
PROGRESSIVE_BAN_RESET_AFTER=86400
```

Beispiel:

| Vergehen | Stufe | Dauer |
|---|---:|---|
| 1 | 1 | 1 Stunde |
| 2 | 2 | 2 Stunden |
| 3 | 3 | 4 Stunden |
| 4 | 4 | 8 Stunden |
| 5 | 5 | permanent |

Der Offense-Zähler wird in SQLite gespeichert. Wenn eine IP länger als `PROGRESSIVE_BAN_RESET_AFTER` nicht auffällig war, kann der Cleanup sie entfernen.

Progressive Sperren gelten für Monitor-Sperren. GeoIP- und externe Blocklist-Sperren haben eigene Regeln.

## Firewall-Modell

AdGuard Shield nutzt eine eigene Chain und zwei ipsets:

```text
ADGUARD_SHIELD
adguard_shield_v4
adguard_shield_v6
```

Die Chain wird je nach `FIREWALL_MODE` in die passende Host-Chain eingehängt:

| Modus | Parent-Chain |
|---|---|
| `host` / `docker-host` | `INPUT` |
| `docker-bridge` | `DOCKER-USER` |
| `hybrid` | `INPUT` und `DOCKER-USER` |

Für klassische Installationen und Docker mit Host-Netzwerk sieht das so aus:

```text
INPUT
  |- tcp/53  -> ADGUARD_SHIELD
  |- udp/53  -> ADGUARD_SHIELD
  |- tcp/443 -> ADGUARD_SHIELD
  |- udp/443 -> ADGUARD_SHIELD
  |- tcp/853 -> ADGUARD_SHIELD
  |- udp/853 -> ADGUARD_SHIELD

ADGUARD_SHIELD
  |- src in adguard_shield_v4 -> DROP
  |- src in adguard_shield_v6 -> DROP
```

Bei Docker Bridge mit veröffentlichten Ports ersetzt `DOCKER-USER` die `INPUT`-Chain im oberen Teil des Diagramms. Docker leitet solche Pakete nach DNAT über `FORWARD`; `INPUT` sieht sie dort nicht zuverlässig.

Die Ports kommen aus:

```bash
BLOCKED_PORTS="53 443 853"
```

Das blockiert klassische DNS-Anfragen und die üblichen Ports für DoH, DoT und DoQ. Die Erkennung selbst basiert weiterhin auf dem AdGuard-Home-Querylog.

Warum `ipset`?

- viele gesperrte IPs erzeugen nicht tausende einzelne iptables-Regeln
- IPv4 und IPv6 werden getrennt sauber verwaltet
- Sperren und Freigaben sind schneller
- die eigene Chain bleibt übersichtlich

## SQLite-State

Der zentrale Zustand liegt standardmäßig hier:

```text
/var/lib/adguard-shield/adguard-shield.db
```

Wichtige Tabellen:

| Tabelle | Inhalt |
|---|---|
| `active_bans` | aktuell aktive Sperren mit IP, Grund, Dauer, Quelle und Ablaufzeit |
| `ban_history` | dauerhafte Historie von `BAN`, `UNBAN` und `DRY` |
| `offense_tracking` | Progressive-Ban-Stufen pro Client-IP |
| `whitelist_cache` | aufgelöste IPs aus externen Whitelists |
| `geoip_cache` | gecachte GeoIP-Ergebnisse |

Die Datenbank nutzt WAL-Modus und einen Busy-Timeout, damit Daemon und CLI-Befehle gleichzeitig lesen können.

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
├── adguard-shield.db
├── external-blocklist/
├── external-whitelist/
├── iptables-rules.v4
└── iptables-rules.v6

/var/log/
└── adguard-shield.log
```

## Hintergrundjobs im Daemon

Es gibt in der Go-Version keine separaten Worker-Skripte mehr. Diese Aufgaben laufen als Goroutines im Daemon:

| Aufgabe | Wann aktiv | Zweck |
|---|---|---|
| Querylog-Poller | immer | liest und analysiert AdGuard-Home-Querylogs |
| externe Whitelist | `EXTERNAL_WHITELIST_ENABLED=true` | lädt Listen, löst Hostnamen auf, aktualisiert Whitelist-Cache |
| externe Blocklist | `EXTERNAL_BLOCKLIST_ENABLED=true` | lädt Listen, sperrt gewünschte IPs und hebt entfernte IPs optional auf |
| Offense-Cleanup | `PROGRESSIVE_BAN_ENABLED=true` | entfernt abgelaufene Offense-Zähler |
| GeoIP-Lookups | `GEOIP_ENABLED=true` | prüft neue öffentliche Client-IPs gegen Länderregeln |

Externe Whitelist und Blocklist laufen sofort beim Start einmalig und danach im jeweiligen Intervall.

## Whitelist-Logik

Vor jeder Sperre wird geprüft, ob die IP vertrauenswürdig ist.

Quellen:

- statische `WHITELIST` aus der Konfiguration
- aufgelöste IPs aus externen Whitelists

Eine gewhitelistete IP wird nicht gesperrt. Wenn eine externe Whitelist später eine bereits gesperrte IP enthält, hebt der Daemon diese Sperre automatisch auf.

## GeoIP-Logik

GeoIP arbeitet nur mit öffentlichen IPs, wenn `GEOIP_SKIP_PRIVATE=true` gesetzt ist. Private Netze, Loopback, Link-Local und CGNAT werden übersprungen.

Modi:

| Modus | Verhalten |
|---|---|
| `blocklist` | Länder aus `GEOIP_COUNTRIES` werden gesperrt |
| `allowlist` | nur Länder aus `GEOIP_COUNTRIES` sind erlaubt, alle anderen öffentlichen Länder werden gesperrt |

GeoIP-Sperren sind permanent, werden aber beim Start gegen die aktuelle Konfiguration geprüft. Wenn GeoIP deaktiviert wird, der Modus wechselt oder ein Land nicht mehr blockiert werden müsste, kann die Sperre automatisch aufgehoben werden.

## AbuseIPDB-Reporting

AbuseIPDB wird nur für permanente Monitor-Sperren genutzt:

- DNS-Flood-Watchlist-Treffer
- Progressive-Ban-Sperren, die die maximale Stufe erreicht haben

Nicht gemeldet werden:

- temporäre Rate-Limit-Sperren
- manuelle Sperren
- GeoIP-Sperren
- externe Blocklist-Sperren

Voraussetzung:

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."
```

## History und Logs

Es gibt zwei unterschiedliche Blickwinkel:

| Quelle | Inhalt |
|---|---|
| `ban_history` in SQLite | Sperren, Freigaben und Dry-Run-Ereignisse |
| `LOG_FILE` | Daemon-Ereignisse, Worker-Läufe, Warnungen, Fehler |

Query-Inhalte werden nicht dauerhaft in die Logdatei geschrieben. Für aktuelle Queries gibt es die Live-Ansicht:

```bash
sudo /opt/adguard-shield/adguard-shield live
```

History:

```bash
sudo /opt/adguard-shield/adguard-shield history
sudo /opt/adguard-shield/adguard-shield history 200
```

Logs:

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo journalctl -u adguard-shield -f
```

## Unterschied zur alten Shell-Architektur

Früher gab es unter anderem:

- `adguard-shield.sh`
- `iptables-helper.sh`
- `external-blocklist-worker.sh`
- `external-whitelist-worker.sh`
- `geoip-worker.sh`
- `offense-cleanup-worker.sh`
- `report-generator.sh`
- `unban-expired.sh`
- Watchdog-Service und Watchdog-Timer

In der Go-Version gibt es diese Skripte nicht mehr. Der systemd-Service nutzt `Restart=on-failure`; die eigentlichen Worker laufen im Daemon. Alte Artefakte werden vom Installer erkannt und müssen vor der Go-Installation entfernt werden, damit keine zwei Implementierungen parallel dieselbe Firewall und dieselben Dateien verwalten.
