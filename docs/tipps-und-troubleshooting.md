# Tipps & Troubleshooting

Dieses Dokument hilft beim Eingrenzen typischer Probleme im Betrieb. Die Reihenfolge ist bewusst praktisch: erst prüfen, ob der Dienst läuft, dann API, Firewall, Sperren, Listen und optionale Module.

## Erste Diagnose

Diese fünf Befehle liefern meistens schon genug Hinweise, um ein Problem einzugrenzen:

```bash
# 1. Läuft der Service?
sudo systemctl status adguard-shield

# 2. Was sagt das Journal?
sudo journalctl -u adguard-shield --no-pager -n 100

# 3. Funktioniert die API?
sudo /opt/adguard-shield/adguard-shield test

# 4. Was ist der aktuelle Zustand?
sudo /opt/adguard-shield/adguard-shield status

# 5. Gibt es Warnungen oder Fehler?
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
```

Wenn du aktuelle Queries und den Echtzeit-Zustand sehen willst:

```bash
sudo /opt/adguard-shield/adguard-shield live
```

---

## Service startet nicht

### Prüfen

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
```

### Typische Ursachen

| Ursache | Lösung |
|---|---|
| Konfigurationsdatei fehlt | `/opt/adguard-shield/adguard-shield.conf` prüfen |
| Falsche Dateirechte | `sudo chmod 600 /opt/adguard-shield/adguard-shield.conf` |
| Binary fehlt oder nicht ausführbar | `ls -l /opt/adguard-shield/adguard-shield` prüfen |
| Systempakete fehlen | `which iptables ip6tables ipset systemctl` prüfen |
| API nicht erreichbar | Erst AdGuard Home starten |
| Alte Shell-Artefakte | Go-Installer meldet Konflikte, alte Version deinstallieren |
| Unit manuell geändert | `sudo systemctl daemon-reload` ausführen |

### Nützliche Prüfbefehle

```bash
ls -l /opt/adguard-shield/adguard-shield
ls -l /opt/adguard-shield/adguard-shield.conf
which iptables ip6tables ipset systemctl
sudo systemctl daemon-reload
```

---

## Verbindung zu AdGuard Home schlägt fehl

### Test

```bash
sudo /opt/adguard-shield/adguard-shield test
```

### Konfiguration prüfen

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="..."
```

### Häufige Fehler und Lösungen

| Symptom | Mögliche Ursache | Lösung |
|---|---|---|
| HTTP 401/403 | Benutzername oder Passwort falsch | Zugangsdaten in der Konfiguration prüfen |
| HTTP 404 | Falsche URL oder falscher Port | URL und Port prüfen, AdGuard-Home-Weboberfläche testen |
| Timeout | Firewall, DNS-Problem oder falsche IP | Netzwerk und Erreichbarkeit prüfen |
| Connection refused | AdGuard Home läuft nicht oder anderer Port | `systemctl status AdGuardHome` prüfen |
| Keine Querylog-Einträge | Querylog deaktiviert oder leer | In AdGuard Home prüfen: Einstellungen > Querylog |

### Direkt testen (unabhängig von AdGuard Shield)

```bash
curl -k -u "admin:passwort" "http://127.0.0.1:3000/control/querylog?limit=1&response_status=all"
```

Passe URL und Zugangsdaten entsprechend an.

---

## Keine Sperren trotz vieler Anfragen

### Prüfen

```bash
sudo /opt/adguard-shield/adguard-shield live --once
sudo /opt/adguard-shield/adguard-shield history 50
sudo /opt/adguard-shield/adguard-shield logs --level debug --limit 100
```

### Mögliche Ursachen und Lösungen

| Ursache | Lösung |
|---|---|
| `RATE_LIMIT_MAX_REQUESTS` zu hoch | Grenzwert senken oder `live` beobachten |
| `RATE_LIMIT_WINDOW` zu kurz | Zeitfenster verlängern |
| `API_QUERY_LIMIT` zu niedrig | Erhöhen, damit Spitzen nicht verpasst werden |
| Client steht in `WHITELIST` | Whitelist prüfen |
| Externe Whitelist enthält die IP | `whitelist-status` prüfen |
| Proxy/Forwarder maskiert echte Client-IPs | AdGuard Home sieht nur die Forwarder-IP; Forwarder whitelisten |
| Querylog enthält die Anfragen nicht | In AdGuard Home prüfen, ob Querylog aktiviert ist |
| `DRY_RUN=true` ist gesetzt | In der Konfiguration auf `false` setzen |

**Wichtig bei Proxies und Forwardern:** Wenn AdGuard Home nur eine einzige interne IP sieht (z.B. die IP eines Routers oder Reverse Proxy), zählt AdGuard Shield auch nur diese IP. In solchen Setups muss die Architektur geprüft oder der Forwarder gewhitelistet werden.

---

## Zu viele Sperren

### Übersicht verschaffen

```bash
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield history 100
```

### Ursachen und Gegenmaßnahmen

| Ursache | Gegenmaßnahme |
|---|---|
| Legitimer Client fragt häufig dieselbe Domain | Client whitelisten oder `RATE_LIMIT_MAX_REQUESTS` erhöhen |
| Router/Resolver bündelt viele Clients | Router/Resolver in `WHITELIST` aufnehmen |
| CDN/App erzeugt viele Subdomains | `SUBDOMAIN_FLOOD_MAX_UNIQUE` erhöhen |
| Externe Blocklist ist sehr groß | `blocklist-status` prüfen und ggf. Liste anpassen |
| GeoIP Allowlist zu eng | Länder prüfen oder `GEOIP_MODE` wechseln |

### Falsch gesperrte IP freigeben

```bash
# Sperre aufheben
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100

# Offense-Zähler zurücksetzen (damit progressive Sperren nicht sofort eskalieren)
sudo /opt/adguard-shield/adguard-shield reset-offenses 192.168.1.100
```

### Dauerhaft ausnehmen

```bash
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.100"
```

Danach:

```bash
sudo systemctl restart adguard-shield
```

---

## Firewall prüfen

### Status über AdGuard Shield

```bash
sudo /opt/adguard-shield/adguard-shield firewall-status
```

### Direkte Prüfung mit Systembefehlen

```bash
# ipsets anzeigen
sudo ipset list adguard_shield_v4
sudo ipset list adguard_shield_v6

# iptables-Regeln anzeigen
sudo iptables -n -L ADGUARD_SHIELD --line-numbers -v
sudo ip6tables -n -L ADGUARD_SHIELD --line-numbers -v

# Prüfen, ob Chain in INPUT eingehängt ist
sudo iptables -n -L INPUT --line-numbers -v | grep ADGUARD

# Bei Docker Bridge: DOCKER-USER prüfen
sudo iptables -n -L DOCKER-USER --line-numbers -v | grep ADGUARD
```

### Firewall neu aufbauen

```bash
sudo /opt/adguard-shield/adguard-shield firewall-remove
sudo /opt/adguard-shield/adguard-shield firewall-create
sudo systemctl restart adguard-shield
```

Nach dem Neustart werden aktive Sperren aus SQLite wieder in die ipsets geschrieben.

---

## Sperren bleiben nach Ablauf aktiv

### Prüfen

```bash
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield history 100
```

Temporäre Sperren werden beim Start und während jedes Pollings auf Ablauf geprüft. Wenn eine Sperre als permanent angezeigt wird, wird sie nicht automatisch freigegeben.

### Permanente Sperren (gewollt)

| Typ | Warum permanent |
|---|---|
| DNS-Flood-Watchlist-Treffer | Sofortiger Permanent-Ban |
| Progressive-Ban auf Maximalstufe | Eskalation durch wiederholte Verstöße |
| Manuelle `ban`-Sperren | Manuell gesetzt, manuell aufheben |
| GeoIP-Sperren | Permanent bis Konfigurationsänderung |
| Externe Blocklist mit `BAN_DURATION=0` | Permanent bis IP aus Liste entfernt |

### Manuell freigeben

```bash
sudo /opt/adguard-shield/adguard-shield unban 192.168.1.100
```

---

## Dry-Run verwenden

Dry-Run ist ideal, um neue Konfigurationen zu prüfen, bevor sie produktiv gehen:

```bash
# Dry-Run starten (Strg+C zum Beenden)
sudo /opt/adguard-shield/adguard-shield dry-run
```

Währenddessen die Ergebnisse prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield history 50
```

Im Dry-Run werden mögliche Sperren als `DRY` protokolliert. Es entstehen keine aktiven Sperren und keine Firewall-Änderungen.

---

## Externe Whitelist

### Status prüfen

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-status
```

### Manuell synchronisieren

```bash
sudo /opt/adguard-shield/adguard-shield whitelist-sync
```

### Typische Probleme

| Problem | Lösung |
|---|---|
| URL nicht erreichbar | URL im Browser oder mit `curl` testen |
| Windows-Zeilenenden oder BOM | Datei in UTF-8 ohne BOM und mit `LF`-Zeilenenden speichern |
| Hostname nicht auflösbar | DNS-Auflösung prüfen, ggf. alternativen Hostnamen verwenden |
| Einträge enthalten Ports oder URLs | Nur IPs, CIDR-Netze und Hostnamen werden unterstützt |
| DNS liefert `0.0.0.0` | AdGuard blockiert den Host; Ausnahme in AdGuard Home einrichten |

### Erwartetes Listenformat

```text
192.168.1.100           # IPv4-Adresse
10.0.0.0/24             # CIDR-Netz
trusted.example.com     # Hostname (wird per DNS aufgelöst)
# Kommentare sind erlaubt
```

---

## Externe Blocklist

### Status prüfen

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-status
```

### Manuell synchronisieren

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-sync
```

### Alle Blocklist-Sperren freigeben

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-flush
```

### Zu viele IPs gesperrt?

1. `EXTERNAL_BLOCKLIST_URLS` prüfen: Welche Listen sind konfiguriert?
2. Liste manuell ansehen: Wie viele Einträge enthält sie?
3. Whitelist ergänzen: Eigene IPs sollten dort stehen.
4. `EXTERNAL_BLOCKLIST_NOTIFY=false` belassen, um den Benachrichtigungskanal nicht zu überfluten.
5. `EXTERNAL_BLOCKLIST_AUTO_UNBAN=true` setzen, damit entfernte Einträge automatisch freigegeben werden.

---

## GeoIP

### Status prüfen

```bash
sudo /opt/adguard-shield/adguard-shield geoip-status
```

### Einzelne IP prüfen

```bash
sudo /opt/adguard-shield/adguard-shield geoip-lookup 8.8.8.8
```

### Cache leeren

```bash
sudo /opt/adguard-shield/adguard-shield geoip-flush-cache
```

### Alle GeoIP-Sperren freigeben

```bash
sudo /opt/adguard-shield/adguard-shield geoip-flush
```

### Typische Probleme und Lösungen

| Problem | Lösung |
|---|---|
| Keine Länder erkannt | MaxMind-Key, MMDB-Pfad oder `geoiplookup`-Befehl prüfen |
| Private IPs werden nicht geprüft | `GEOIP_SKIP_PRIVATE=true` ist Standard und korrekt |
| Zu viele Länder gesperrt | `GEOIP_MODE` und `GEOIP_COUNTRIES` prüfen |
| Allowlist sperrt fast alles | Im Allowlist-Modus sind nur genannte Länder erlaubt; alle anderen werden gesperrt |
| Datenbank nicht gefunden | `GEOIP_LICENSE_KEY` oder `GEOIP_MMDB_PATH` setzen |
| Datenbank veraltet | `geoip-flush-cache` und Service neu starten |

### Ländercodes nachschlagen

Die GeoIP-Ländercodes folgen dem Standard ISO 3166-1 Alpha-2. Eine vollständige Liste findest du in der [ISO-3166-1-Kodierliste auf Wikipedia](https://de.wikipedia.org/wiki/ISO-3166-1-Kodierliste).

---

## Reports

### Status prüfen

```bash
sudo /opt/adguard-shield/adguard-shield report-status
```

### Funktionstest

```bash
# Testmail senden
sudo /opt/adguard-shield/adguard-shield report-test

# Text-Report in der Konsole ansehen
sudo /opt/adguard-shield/adguard-shield report-generate txt
```

### Keine Mail kommt an?

| Prüfpunkt | Befehl / Aktion |
|---|---|
| `REPORT_EMAIL_TO` gesetzt? | Konfiguration prüfen |
| `REPORT_MAIL_CMD` vorhanden? | `which msmtp` |
| Mailer für root konfiguriert? | `/root/.msmtprc` oder `/etc/msmtprc` prüfen |
| Cron installiert? | `sudo cat /etc/cron.d/adguard-shield-report` |
| Spam-Ordner geprüft? | E-Mail-Provider prüfen |
| SMTP-Port offen? | Ausgehende Verbindung auf Port 587/465 testen |

### Cron prüfen

```bash
sudo cat /etc/cron.d/adguard-shield-report
sudo /opt/adguard-shield/adguard-shield report-send
```

---

## Benachrichtigungen

### Prüfen

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
```

### Checkliste

| Prüfpunkt | Beschreibung |
|---|---|
| `NOTIFY_ENABLED=true` | Benachrichtigungen global aktiviert? |
| `NOTIFY_TYPE` | Korrekt geschrieben? (`ntfy`, `discord`, `slack`, `gotify`, `generic`) |
| Webhook-URL | Gesetzt und erreichbar? |
| Ntfy-Topic | Nicht leer? |
| Token | Gültig und nicht abgelaufen? |
| Netzwerk | Ausgehende HTTPS-Verbindungen möglich? |
| Modul-Schalter | `EXTERNAL_BLOCKLIST_NOTIFY` und `GEOIP_NOTIFY` separat prüfen |

Bei `generic` Webhook kannst du testweise einen lokalen HTTP-Empfänger oder einen Request-Inspector (z.B. webhook.site) verwenden, um den gesendeten Payload zu sehen.

---

## SQLite direkt auswerten

Für tiefergehende Analysen kannst du die SQLite-Datenbank direkt abfragen:

### Sperren nach Quelle und Grund

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "SELECT source, reason, count(*) FROM active_bans GROUP BY source, reason ORDER BY count(*) DESC;"
```

### Letzte History-Einträge

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "SELECT timestamp_text, action, client_ip, domain, reason FROM ban_history ORDER BY id DESC LIMIT 20;"
```

### Offense-Zähler

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "SELECT client_ip, offense_level, last_offense FROM offense_tracking ORDER BY offense_level DESC;"
```

### Whitelist-Cache

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "SELECT ip, source FROM whitelist_cache ORDER BY ip;"
```

### GeoIP-Cache

```bash
sudo sqlite3 /var/lib/adguard-shield/adguard-shield.db \
  "SELECT ip, country_code FROM geoip_cache ORDER BY ip LIMIT 50;"
```

---

## Alte Shell-Artefakte entfernen

Wenn der Installer alte Dateien meldet, zuerst sauber migrieren. Typische alte Dateien:

| Datei | Funktion in der alten Version |
|---|---|
| `adguard-shield.sh` | Hauptskript |
| `iptables-helper.sh` | Firewall-Management |
| `external-blocklist-worker.sh` | Blocklist-Synchronisation |
| `external-whitelist-worker.sh` | Whitelist-Synchronisation |
| `geoip-worker.sh` | GeoIP-Prüfung |
| `offense-cleanup-worker.sh` | Offense-Bereinigung |
| `report-generator.sh` | Report-Erstellung |
| `unban-expired.sh` | Ablauf temporärer Sperren |
| `adguard-shield-watchdog.sh` | Watchdog-Skript |

Die Go-Version ersetzt diese Funktionen durch das eine Binary. Alte Worker sollten nicht parallel laufen.

Details zur Migration stehen in der [Update-Anleitung](update.md).

---

## Service hart zurücksetzen

Wenn der Zustand unklar ist und ein sauberer Neustart nötig ist:

```bash
# Service stoppen
sudo systemctl stop adguard-shield

# Firewall-Struktur entfernen
sudo /opt/adguard-shield/adguard-shield firewall-remove

# Service neu starten (baut Firewall aus SQLite wieder auf)
sudo systemctl start adguard-shield

# Status prüfen
sudo /opt/adguard-shield/adguard-shield status
```

Das entfernt die Firewall-Struktur und lässt den Daemon sie beim Start wieder aus dem SQLite-State aufbauen. Aktive Sperren bleiben in der Datenbank erhalten.

---

## Deinstallation

### Konfiguration behalten

```bash
sudo /opt/adguard-shield/adguard-shield uninstall --keep-config
```

### Alles entfernen

```bash
sudo /opt/adguard-shield/adguard-shield uninstall
```

Ohne `--keep-config` werden Installationsverzeichnis, State-Verzeichnis und Logdatei entfernt.

---

## Zusammenfassung: Wichtigste Diagnosebefehle

| Befehl | Zweck |
|---|---|
| `systemctl status adguard-shield` | Service-Status prüfen |
| `journalctl -u adguard-shield -n 100` | Systemd-Journal ansehen |
| `test` | API-Verbindung prüfen |
| `status` | Aktuellen Zustand und aktive Sperren anzeigen |
| `live` | Echtzeit-Ansicht mit Queries, Sperren und Logs |
| `history 100` | Ban-History anzeigen |
| `logs --level warn --limit 100` | Warnungen und Fehler anzeigen |
| `firewall-status` | Firewall-Regeln und ipsets anzeigen |
| `dry-run` | Konfiguration testen ohne echte Sperren |
