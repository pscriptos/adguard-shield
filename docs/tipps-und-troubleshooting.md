# Tipps & Troubleshooting

Dieses Dokument hilft beim Eingrenzen typischer Probleme im Betrieb. Die Reihenfolge ist bewusst praktisch: erst prüfen, ob der Dienst läuft, dann API, Firewall, Sperren, Listen und optionale Module.

## Erste Diagnose

Diese Befehle liefern meistens schon genug Hinweise, um ein Problem einzugrenzen:

```bash
# 1. Läuft der Service?
sudo systemctl status adguard-shield

# 2. Was sagt das Journal?
sudo journalctl -u adguard-shield --no-pager -n 100

# 3. Funktioniert die API?
sudo adguard-shield test

# 4. Was ist der aktuelle Zustand?
sudo adguard-shield status

# 5. Was ist zu einer konkreten IP bekannt?
sudo adguard-shield ip-status 192.168.1.100

# 6. Gibt es Warnungen oder Fehler?
sudo adguard-shield logs --level warn --limit 100
```

Wenn du aktuelle Queries und den Echtzeit-Zustand sehen willst:

```bash
sudo adguard-shield live
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
| Konfiguration geändert, aber ohne Wirkung | `sudo systemctl restart adguard-shield` ausführen; `systemctl reload` lädt die Konfiguration nicht neu |
| Warnungen zur Konfiguration im Log | Tippfehler oder ungültige Werte; betroffene Parameter nutzen den Standardwert (siehe [Konfiguration](konfiguration.md#prüfung-beim-laden)) |

### Warnungen zur Konfiguration

Ungültige Werte stoppen den Dienst nicht. AdGuard Shield verwendet stattdessen den Standardwert und meldet das beim Start im Log (`Konfiguration: ...`) sowie bei jedem CLI-Befehl als `WARNUNG:` auf stderr:

```text
WARNUNG: RATE_LIMIT_WINDOW="abc" ist keine gültige Zahl, verwende Standardwert 60
WARNUNG: BAN_HISTORY_FILE wird ignoriert (History liegt in der SQLite-Datenbank)
```

| Warnung | Lösung |
|---|---|
| Unbekannter Schlüssel | Tippfehler im Parameternamen korrigieren |
| Keine gültige Zahl / kein gültiger Wahrheitswert | Wert korrigieren (`true`/`false`, Zahlen ohne Einheit) |
| Veralteter Schlüssel der Shell-Version | Zeile aus der Konfiguration löschen |
| Ungültige Ports in `BLOCKED_PORTS` | Nur Portnummern `1`–`65535` oder Bereiche `a:b` verwenden |

Nach der Korrektur `sudo systemctl restart adguard-shield` ausführen. Mit `sudo adguard-shield status` lässt sich schnell prüfen, ob noch Warnungen ausgegeben werden.

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
sudo adguard-shield test
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
sudo adguard-shield live --once
sudo adguard-shield history 50
sudo adguard-shield logs --level debug --limit 100
```

### Mögliche Ursachen und Lösungen

| Ursache | Lösung |
|---|---|
| `RATE_LIMIT_MAX_REQUESTS` zu hoch | Grenzwert senken oder `live` beobachten |
| `RATE_LIMIT_WINDOW` zu kurz | Zeitfenster verlängern |
| `API_QUERY_LIMIT` zu niedrig | Erhöhen, wenn das Log „Limit von 20 Seiten erreicht“ meldet |
| Client steht in `WHITELIST` | Whitelist prüfen |
| Externe Whitelist enthält die IP | `whitelist-status` prüfen |
| Proxy/Forwarder maskiert echte Client-IPs | AdGuard Home sieht nur die Forwarder-IP; Forwarder whitelisten |
| Querylog enthält die Anfragen nicht | In AdGuard Home prüfen, ob Querylog aktiviert ist |
| `DRY_RUN=true` ist gesetzt | In der Konfiguration auf `false` setzen |

### Warnung „Limit von 20 Seiten erreicht“

Pro Poll lädt AdGuard Shield das Querylog seitenweise (je `API_QUERY_LIMIT` Einträge), bis bereits ausgewertete Einträge oder der Beginn des Analysefensters erreicht sind, höchstens aber 20 Seiten. Erscheint im Log

```text
Querylog: Limit von 20 Seiten erreicht, ältere Einträge werden nicht ausgewertet
```

kamen zwischen zwei Polls mehr als `20 × API_QUERY_LIMIT` Anfragen an. Ein Teil davon wird dann nicht ausgewertet. Abhilfe: `API_QUERY_LIMIT` erhöhen (z.B. `2000`) und/oder `CHECK_INTERVAL` verkürzen. Die Warnung wird höchstens alle 5 Minuten wiederholt; bei einem kurzen Flood ist sie unkritisch.

**Wichtig bei Proxies und Forwardern:** Wenn AdGuard Home nur eine einzige interne IP sieht (z.B. die IP eines Routers oder Reverse Proxy), zählt AdGuard Shield auch nur diese IP. In solchen Setups muss die Architektur geprüft oder der Forwarder gewhitelistet werden.

---

## Zu viele Sperren

### Übersicht verschaffen

```bash
sudo adguard-shield status
sudo adguard-shield ip-status 192.168.1.100
sudo adguard-shield history 100
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
sudo adguard-shield unban 192.168.1.100

# Offense-Zähler zurücksetzen (damit progressive Sperren nicht sofort eskalieren)
sudo adguard-shield reset-offenses 192.168.1.100
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
sudo adguard-shield firewall-status
```

### Direkte Prüfung mit Systembefehlen

```bash
# ipsets anzeigen (temporäre Sperren mit timeout, permanente ohne)
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
sudo adguard-shield firewall-remove
sudo adguard-shield firewall-create
sudo systemctl restart adguard-shield
```

Nach dem Neustart werden aktive Sperren aus SQLite wieder in die ipsets geschrieben.

---

## Sperren bleiben nach Ablauf aktiv

### Prüfen

```bash
sudo adguard-shield status
sudo adguard-shield history 100
```

Temporäre Sperren werden beim Start und danach minütlich auf Ablauf geprüft. Zusätzlich entfernt der Kernel temporäre Einträge über den ipset-Timeout selbst aus der Firewall. Wenn eine Sperre als permanent angezeigt wird, wird sie nicht automatisch freigegeben.

### Permanente Sperren (gewollt)

| Typ | Warum permanent |
|---|---|
| DNS-Flood-Watchlist-Treffer | Sofortiger Permanent-Ban |
| Progressive-Ban auf Maximalstufe | Eskalation durch wiederholte Verstöße |
| Manuelle `ban`-Sperren | Manuell gesetzt, manuell aufheben |
| GeoIP-Sperren | Permanent bis Konfigurationsänderung |
| Externe Blocklist mit `EXTERNAL_BLOCKLIST_BAN_DURATION=0` | Permanent bis IP aus Liste entfernt |
| Monitor-Sperren mit `BAN_DURATION=0` | Rate-Limit- und Subdomain-Flood-Sperren sind dann immer permanent |

### Manuell freigeben

```bash
sudo adguard-shield unban 192.168.1.100
```

---

## Dry-Run verwenden

Dry-Run ist ideal, um neue Konfigurationen zu prüfen, bevor sie produktiv gehen:

```bash
# Dry-Run starten (Strg+C zum Beenden)
sudo adguard-shield dry-run
```

Währenddessen die Ergebnisse prüfen:

```bash
sudo adguard-shield history 50
```

Im Dry-Run werden mögliche Sperren als `DRY` protokolliert. Es entstehen keine aktiven Sperren und keine Firewall-Änderungen.

---

## Externe Whitelist

### Status prüfen

```bash
sudo adguard-shield whitelist-status
```

### Manuell synchronisieren

```bash
sudo adguard-shield whitelist-sync
```

### Typische Probleme

| Problem | Lösung |
|---|---|
| URL nicht erreichbar | URL im Browser oder mit `curl` testen |
| Windows-Zeilenenden oder BOM | Datei in UTF-8 ohne BOM und mit `LF`-Zeilenenden speichern |
| Hostname nicht auflösbar | DNS-Auflösung prüfen, ggf. alternativen Hostnamen verwenden |
| Einträge enthalten Ports oder URLs | Nur IPs, CIDR-Netze und Hostnamen werden unterstützt |
| DNS liefert `0.0.0.0` | AdGuard blockiert den Host; Ausnahme in AdGuard Home einrichten |
| Log meldet „zu breite Netze werden ignoriert“ | `/0`, IPv4 kürzer als `/8` und IPv6 kürzer als `/16` werden bewusst nicht übernommen; kleinere Netze eintragen |
| Sync bricht mit Fehler ab, Whitelist bleibt alt | Mindestens eine Quelle ist nicht erreichbar und nicht im Cache; die bisherige Whitelist bleibt absichtlich erhalten. URL prüfen und `whitelist-sync` wiederholen |

### Sicherheitsbremse: Freigabe abgebrochen

Würde eine Whitelist-Synchronisation auf einen Schlag mehr als 50 % der aktiven Sperren (und mehr als 100 Sperren) aufheben, bricht AdGuard Shield die Freigabe ab und schreibt einen ERROR ins Log:

```text
Externe Whitelist: Freigabe von 812 der 1000 aktiven Sperren abgebrochen (Sicherheitsbremse, mehr als 50%); Whitelist ist aktiv, bitte Listen prüfen
```

Die neue Whitelist ist trotzdem aktiv, verhindert also neue Sperren; nur die bestehenden Sperren bleiben stehen. Typische Ursache ist eine fehlerhafte oder zu weit gefasste Liste. Vorgehen:

1. Listeninhalt prüfen (`sudo adguard-shield whitelist-status` und die Quell-URLs).
2. Ist die Liste fehlerhaft: Liste korrigieren, danach `sudo adguard-shield whitelist-sync`.
3. Ist die Freigabe gewollt: betroffene Sperren gezielt mit `unban` aufheben oder mit `flush` alle Sperren aufheben.

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
sudo adguard-shield blocklist-status
```

### Manuell synchronisieren

```bash
sudo adguard-shield blocklist-sync
```

### Alle Blocklist-Sperren freigeben

```bash
sudo adguard-shield blocklist-flush
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
sudo adguard-shield geoip-status
```

### Einzelne IP prüfen

```bash
sudo adguard-shield geoip-lookup 8.8.8.8
```

### Cache leeren

```bash
sudo adguard-shield geoip-flush-cache
```

### Alle GeoIP-Sperren freigeben

```bash
sudo adguard-shield geoip-flush
```

### Typische Probleme und Lösungen

| Problem | Lösung |
|---|---|
| Keine Länder erkannt | MaxMind-Key, MMDB-Pfad oder `geoiplookup`-Befehl prüfen |
| Private IPs werden nicht geprüft | `GEOIP_SKIP_PRIVATE=true` ist Standard und korrekt |
| Zu viele Länder gesperrt | `GEOIP_MODE` und `GEOIP_COUNTRIES` prüfen |
| Allowlist sperrt fast alles | Im Allowlist-Modus sind nur genannte Länder erlaubt; alle anderen werden gesperrt |
| Datenbank nicht gefunden | `GEOIP_LICENSE_KEY` oder `GEOIP_MMDB_PATH` setzen |
| Datenbank veraltet | Wird täglich automatisch erneuert und ohne Neustart übernommen (Worker `geoip-refresh`); für sofortige Übernahme `geoip-flush-cache` und Service neu starten |
| Log meldet `geoip-refresh Fehler` | Download fehlgeschlagen (z.B. ungültiger `GEOIP_LICENSE_KEY` oder kein Internetzugang); die ältere Datenbank wird weiter genutzt |

### Ländercodes nachschlagen

Die GeoIP-Ländercodes folgen dem Standard ISO 3166-1 Alpha-2. Eine vollständige Liste findest du in der [ISO-3166-1-Kodierliste auf Wikipedia](https://de.wikipedia.org/wiki/ISO-3166-1-Kodierliste).

---

## Reports

### Status prüfen

```bash
sudo adguard-shield report-status
```

### Funktionstest

```bash
# Testmail senden
sudo adguard-shield report-test

# Text-Report in der Konsole ansehen
sudo adguard-shield report-generate txt
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
sudo adguard-shield report-send
```

---

## Benachrichtigungen

### Prüfen

```bash
sudo adguard-shield logs --level warn --limit 100
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
| TLS-Zertifikat | Gültiges Zertifikat am Ziel? Siehe unten |
| Modul-Schalter | `EXTERNAL_BLOCKLIST_NOTIFY` und `GEOIP_NOTIFY` separat prüfen |
| Warteschlange voll | Bei sehr vielen Sperren auf einmal werden Nachrichten über 256 verworfen (WARN im Log) |

### TLS-Fehler bei Benachrichtigungen

Seit v1.2.0 prüfen Benachrichtigungen das TLS-Zertifikat des Ziels. Bei einem selbst gehosteten Dienst (ntfy, Gotify, eigener Webhook) mit selbstsigniertem Zertifikat erscheint im Log z.B.:

```text
Benachrichtigung fehlgeschlagen (ntfy/ban): ... x509: certificate signed by unknown authority
```

Lösung: ein gültiges Zertifikat einsetzen (z.B. Let's Encrypt) oder für dieses interne Ziel die Prüfung abschalten:

```bash
NOTIFY_TLS_INSECURE=true
```

Danach `sudo systemctl restart adguard-shield`. Die Einstellung gilt nur für Benachrichtigungen, nicht für AbuseIPDB, externe Listen oder den MaxMind-Download. Details stehen in [Benachrichtigungen](benachrichtigungen.md#tls-zertifikate).

Bei `generic` Webhook kannst du testweise einen lokalen HTTP-Empfänger oder einen Request-Inspector (z.B. webhook.site) verwenden, um den gesendeten Payload zu sehen.

---

## Logdatei und Rotation

Die Logdatei (`LOG_FILE`, Standard `/var/log/adguard-shield.log`) wird ab `LOG_MAX_SIZE_MB` (Standard `50`) automatisch rotiert: Die aktuelle Datei wird nach `adguard-shield.log.1` verschoben und eine neue Datei begonnen. Es gibt genau ein Backup; ein älteres `.1` wird dabei ersetzt.

| Beobachtung | Erklärung |
|---|---|
| `adguard-shield.log` ist plötzlich fast leer | Rotation hat stattgefunden; ältere Einträge stehen in `adguard-shield.log.1` |
| `logs` zeigt ältere Einträge nicht mehr | `logs` und `logs-follow` lesen nur die aktuelle Datei; ältere Einträge mit `sudo less /var/log/adguard-shield.log.1` ansehen |
| Log wächst unbegrenzt | `LOG_MAX_SIZE_MB=0` deaktiviert die Rotation; Wert größer als `0` setzen und Dienst neu starten |

Soll stattdessen ein externes `logrotate` die Datei verwalten, `LOG_MAX_SIZE_MB=0` setzen und in logrotate `copytruncate` verwenden, da der Daemon die Logdatei dauerhaft geöffnet hält.

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
  "SELECT ip_address, source FROM whitelist_cache ORDER BY ip_address;"
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
sudo adguard-shield firewall-remove

# Service neu starten (baut Firewall aus SQLite wieder auf)
sudo systemctl start adguard-shield

# Status prüfen
sudo adguard-shield status
```

Das entfernt die Firewall-Struktur und lässt den Daemon sie beim Start wieder aus dem SQLite-State aufbauen. Aktive Sperren bleiben in der Datenbank erhalten.

---

## Deinstallation

### Konfiguration behalten

```bash
sudo adguard-shield uninstall --keep-config
```

### Alles entfernen

```bash
sudo adguard-shield uninstall
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
| `ip-status <IP>` | Einzelne IP auf Sperre, Whitelist, Offenses, GeoIP und History prüfen |
| `live` | Echtzeit-Ansicht mit Queries, Sperren und Logs |
| `history 100` | Ban-History anzeigen |
| `logs --level warn --limit 100` | Warnungen und Fehler anzeigen |
| `firewall-status` | Firewall-Regeln und ipsets anzeigen |
| `dry-run` | Konfiguration testen ohne echte Sperren |
