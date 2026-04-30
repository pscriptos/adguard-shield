# Tipps & Troubleshooting

Dieses Dokument hilft beim Eingrenzen typischer Probleme im Betrieb. Die Reihenfolge ist bewusst praktisch: erst prüfen, ob der Dienst läuft, dann API, Firewall, Sperren, Listen und optionale Module.

## Erste Diagnose

Diese Befehle liefern meistens schon genug Hinweise:

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
```

Wenn du aktuelle Queries sehen willst:

```bash
sudo /opt/adguard-shield/adguard-shield live
```

## Service startet nicht

Prüfen:

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
```

Typische Ursachen:

- Konfigurationsdatei fehlt oder hat falsche Rechte
- Binary fehlt oder ist nicht ausführbar
- `iptables`, `ip6tables` oder `ipset` fehlen
- AdGuard-Home-API ist nicht erreichbar
- alte Shell-Artefakte verursachen Konflikte
- systemd-Unit wurde manuell geändert, aber `daemon-reload` fehlt

Nützliche Prüfungen:

```bash
ls -l /opt/adguard-shield/adguard-shield
ls -l /opt/adguard-shield/adguard-shield.conf
which iptables ip6tables ipset systemctl
sudo systemctl daemon-reload
```

## Verbindung zu AdGuard Home schlägt fehl

Test:

```bash
sudo /opt/adguard-shield/adguard-shield test
```

Prüfe in `/opt/adguard-shield/adguard-shield.conf`:

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="..."
```

Häufige Fehler:

| Symptom | Mögliche Ursache |
|---|---|
| HTTP 401/403 | Benutzername oder Passwort falsch |
| HTTP 404 | falsche URL oder AdGuard Home nicht hinter dieser URL |
| Timeout | Firewall, DNS, falsche IP, Dienst nicht erreichbar |
| connection refused | AdGuard Home läuft nicht oder anderer Port |
| keine Querylog-Einträge | Querylog in AdGuard Home deaktiviert oder leer |

Direkt testen:

```bash
curl -k -u "admin:passwort" "http://127.0.0.1:3000/control/querylog?limit=1&response_status=all"
```

Passe URL und Zugangsdaten entsprechend an.

## Keine Sperren trotz vieler Anfragen

Prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield live --once
sudo /opt/adguard-shield/adguard-shield history 50
sudo /opt/adguard-shield/adguard-shield logs --level debug --limit 100
```

Mögliche Ursachen:

- `RATE_LIMIT_MAX_REQUESTS` ist zu hoch
- `RATE_LIMIT_WINDOW` ist zu kurz
- `API_QUERY_LIMIT` ist zu niedrig und verpasst Spitzen
- Client steht in `WHITELIST`
- externe Whitelist enthält die IP
- AdGuard Home sieht nicht die echte Client-IP, sondern nur einen Proxy/Forwarder
- Querylog enthält die Anfragen nicht
- `DRY_RUN=true` ist gesetzt

Wichtig bei Proxies und Forwardern: Wenn AdGuard Home nur eine einzige interne IP sieht, zählt AdGuard Shield auch nur diese IP. In solchen Setups muss die Architektur geprüft oder der Forwarder gewhitelistet werden.

## Zu viele Sperren

Erst Übersicht:

```bash
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield history 100
```

Dann Ursachen einordnen:

| Ursache | Gegenmaßnahme |
|---|---|
| legitimer Client fragt häufig dieselbe Domain | Client whitelisten oder Limit erhöhen |
| Router/Resolver bündelt viele Clients | Router/Resolver whitelisten |
| CDN/App erzeugt viele Subdomains | `SUBDOMAIN_FLOOD_MAX_UNIQUE` erhöhen |
| externe Blocklist ist sehr groß | `blocklist-status` prüfen und Benachrichtigungen deaktiviert lassen |
| GeoIP Allowlist zu eng | Länder prüfen oder `GEOIP_MODE` ändern |

Falsch gesperrte IP freigeben:

```bash
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

Dauerhaft ausnehmen:

```bash
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.100"
```

Danach:

```bash
sudo systemctl restart adguard-shield
```

## Firewall prüfen

Status:

```bash
sudo /opt/adguard-shield/adguard-shield firewall-status
```

Direkt prüfen:

```bash
sudo ipset list adguard_shield_v4
sudo ipset list adguard_shield_v6
sudo iptables -n -L ADGUARD_SHIELD --line-numbers -v
sudo ip6tables -n -L ADGUARD_SHIELD --line-numbers -v
```

Firewall neu aufbauen:

```bash
sudo /opt/adguard-shield/adguard-shield firewall-remove
sudo /opt/adguard-shield/adguard-shield firewall-create
sudo systemctl restart adguard-shield
```

Nach dem Neustart werden aktive Sperren aus SQLite wieder in die ipsets geschrieben.

## Sperren bleiben nach Ablauf aktiv

Prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield history 100
```

Temporäre Sperren werden beim Start und während des Pollings auf Ablauf geprüft. Wenn eine Sperre permanent ist, wird sie nicht automatisch freigegeben.

Permanent sind typischerweise:

- DNS-Flood-Watchlist-Treffer
- Progressive-Ban-Maximalstufe
- manuelle `ban`-Sperren
- GeoIP-Sperren
- externe Blocklist mit `EXTERNAL_BLOCKLIST_BAN_DURATION=0`

Manuell freigeben:

```bash
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
```

## Dry-Run verwenden

Dry-Run ist ideal für neue Regeln:

```bash
sudo /opt/adguard-shield/adguard-shield dry-run
```

Währenddessen:

```bash
sudo /opt/adguard-shield/adguard-shield history 50
```

Im Dry-Run werden mögliche Sperren als `DRY` protokolliert. Es entstehen keine aktiven Sperren und keine Firewall-Änderungen.

## Externe Whitelist

Status:

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-status
```

Manuell synchronisieren:

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-sync
```

Typische Probleme:

- URL nicht erreichbar
- Datei enthält Windows-Zeilenenden oder BOM
- Hostname ist nicht auflösbar
- Einträge enthalten Ports oder URLs statt IP/Hostname
- DNS-Auflösung liefert `0.0.0.0`, weil AdGuard den Host blockiert

Format prüfen:

```text
192.168.1.100
10.0.0.0/24
trusted.example.com
# Kommentare sind erlaubt
```

## Externe Blocklist

Status:

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-status
```

Manuell synchronisieren:

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-sync
```

Alle externen Blocklist-Sperren freigeben:

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-flush
```

Wenn zu viele IPs gesperrt werden:

1. `EXTERNAL_BLOCKLIST_URLS` prüfen.
2. Liste manuell ansehen.
3. Whitelist für eigene IPs ergänzen.
4. `EXTERNAL_BLOCKLIST_NOTIFY=false` lassen.
5. Bei Bedarf `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` setzen.

## GeoIP

Status:

```bash
sudo /opt/adguard-shield/adguard-shield geoip-status
```

Einzelne IP prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield geoip-lookup 8.8.8.8
```

Cache leeren:

```bash
sudo /opt/adguard-shield/adguard-shield geoip-flush-cache
```

Alle GeoIP-Sperren freigeben:

```bash
sudo /opt/adguard-shield/adguard-shield geoip-flush
```

Typische Ursachen:

| Problem | Lösung |
|---|---|
| keine Länder erkannt | MaxMind-Key, MMDB-Pfad oder `geoiplookup` prüfen |
| private IPs werden nicht geprüft | `GEOIP_SKIP_PRIVATE=true` ist aktiv, das ist Standard |
| zu viele Länder gesperrt | `GEOIP_MODE` und `GEOIP_COUNTRIES` prüfen |
| Allowlist sperrt fast alles | im Allowlist-Modus sind nur genannte Länder erlaubt |

## Reports

Status:

```bash
sudo /opt/adguard-shield/adguard-shield report-status
```

Test:

```bash
sudo /opt/adguard-shield/adguard-shield report-test
sudo /opt/adguard-shield/adguard-shield report-generate txt
```

Wenn keine Mail ankommt:

- `REPORT_EMAIL_TO` gesetzt?
- `REPORT_MAIL_CMD` vorhanden?
- Mailer für root konfiguriert?
- Cron installiert?
- Spam-Ordner geprüft?

Cron prüfen:

```bash
sudo cat /etc/cron.d/adguard-shield-report
sudo /opt/adguard-shield/adguard-shield report-send
```

## Benachrichtigungen

Prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
```

Häufige Ursachen:

- `NOTIFY_ENABLED=false`
- falscher `NOTIFY_TYPE`
- Webhook-URL leer
- Ntfy-Topic leer
- Token ungültig
- ausgehende HTTPS-Verbindung blockiert
- externe Blocklist meldet nichts, weil `EXTERNAL_BLOCKLIST_NOTIFY=false`
- GeoIP meldet nichts, weil `GEOIP_NOTIFY=false`

## SQLite direkt auswerten

Für tiefergehende Analysen:

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "select source, reason, count(*) from active_bans group by source, reason order by count(*) desc;"
```

Letzte History:

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "select timestamp_text, action, client_ip, domain, reason from ban_history order by id desc limit 20;"
```

Offense-Zähler:

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "select client_ip, offense_level, last_offense from offense_tracking order by offense_level desc;"
```

## Alte Shell-Artefakte entfernen

Wenn der Installer alte Dateien meldet, zuerst sauber migrieren. Typische alte Dateien:

```text
adguard-shield.sh
iptables-helper.sh
external-blocklist-worker.sh
external-whitelist-worker.sh
geoip-worker.sh
offense-cleanup-worker.sh
report-generator.sh
unban-expired.sh
adguard-shield-watchdog.sh
```

Die Go-Version ersetzt diese Funktionen durch das eine Binary. Alte Worker sollten nicht parallel laufen.

## Service hart zurücksetzen

Wenn der Zustand unklar ist:

```bash
sudo systemctl stop adguard-shield
sudo /opt/adguard-shield/adguard-shield firewall-remove
sudo systemctl start adguard-shield
sudo /opt/adguard-shield/adguard-shield status
```

Das entfernt die Firewall-Struktur und lässt den Daemon sie beim Start wieder aus SQLite aufbauen.

## Deinstallation

Konfiguration behalten:

```bash
sudo /opt/adguard-shield/adguard-shield uninstall --keep-config
```

Alles entfernen:

```bash
sudo /opt/adguard-shield/adguard-shield uninstall
```

Ohne `--keep-config` werden Installationsverzeichnis, State-Verzeichnis und Logdatei entfernt.
