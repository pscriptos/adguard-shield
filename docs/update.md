# Update-Anleitung

AdGuard Shield wird in der Go-Version über das Binary selbst installiert und aktualisiert. Es gibt kein `install.sh` und kein `update`-Shellskript mehr.

## Kurzfassung

```bash
# Neues Linux-Binary bereitstellen
chmod +x ./adguard-shield

# Update durchführen
sudo ./adguard-shield update
```

Am Ende fragt der Updater, ob AdGuard Shield direkt neu gestartet werden soll.

Der Updater registriert dabei auch den globalen CLI-Befehl `/usr/local/bin/adguard-shield`. Nach dem Update kannst du die installierte Anwendung daher direkt mit `sudo adguard-shield <befehl>` verwenden.

### Nach dem Update prüfen

```bash
sudo adguard-shield install-status
sudo adguard-shield status
sudo journalctl -u adguard-shield --no-pager -n 50
```

---

## Update von v1.1.x auf v1.2.0

Das Update läuft wie gewohnt über `sudo ./adguard-shield update`. Datenbank, Sperren und Konfiguration werden übernommen. Vorher solltest du trotzdem ein Backup anlegen:

```bash
sudo systemctl stop adguard-shield
sudo mkdir -p /root/adguard-shield-backup
sudo cp -a /opt/adguard-shield/adguard-shield /opt/adguard-shield/adguard-shield.conf* /root/adguard-shield-backup/
sudo cp -a /var/lib/adguard-shield/adguard-shield.db* /root/adguard-shield-backup/
```

Was automatisch passiert:

| Bereich | Änderung |
|---|---|
| Datenbank | Schema-Migration auf Version 2 (nur zusätzliche Indizes). v1.1.3 kann die Datenbank weiterhin lesen. |
| Konfiguration | Neue Parameter `ADGUARD_TLS_INSECURE`, `NOTIFY_TLS_INSECURE`, `LOG_MAX_SIZE_MB`, `BAN_HISTORY_RETENTION_DAYS` und die `WEB_*`-Parameter der optionalen [Web-Statusseite](webinterface.md) (standardmäßig aus) werden ergänzt (sofern noch nicht vorhanden), vorhandene Werte bleiben unverändert. Die bisherige Datei liegt danach als `adguard-shield.conf.old` vor (eine ältere `.old` wird dabei ersetzt). |
| systemd-Unit | Wird neu geschrieben, `ExecReload` entfällt. |
| Firewall | Beim Start werden alle Sperren aus der Datenbank per `ipset restore` übernommen. Permanente Sperren, die durch einen Fehler in älteren Versionen nach `BAN_DURATION` aus dem ipset gefallen waren, sind danach wieder aktiv. |

Was du prüfen solltest:

| Thema | Hinweis |
|---|---|
| TLS-Zertifikate | Benachrichtigungen (ntfy, Gotify, Webhooks) und externe Listen prüfen jetzt das TLS-Zertifikat. Nutzt du einen eigenen Server mit selbstsigniertem Zertifikat, schlagen Benachrichtigungen fehl (`Benachrichtigung fehlgeschlagen` im Log). Abhilfe: gültiges Zertifikat oder `NOTIFY_TLS_INSECURE=true`. Für externe Listen gibt es keine Ausnahme – bei Fehlern bleibt die bisherige Whitelist erhalten bzw. der Cache wird genutzt. |
| AdGuard-API-Zertifikat | Auch das TLS-Zertifikat der AdGuard-Home-API wird jetzt geprüft (`ADGUARD_TLS_INSECURE=false`, wird beim Update ergänzt). Bis v1.1.x wurde es nie geprüft. Bei selbstsigniertem Zertifikat schlägt die Abfrage fehl (`sudo adguard-shield test` meldet einen Zertifikatsfehler). Abhilfe: gültiges Zertifikat, `ADGUARD_URL` auf `http://127.0.0.1:<port>` umstellen oder bewusst `ADGUARD_TLS_INSECURE=true` setzen. |
| Konfigurations-Warnungen | Ungültige, unbekannte oder veraltete Parameter werden beim Start und bei jedem CLI-Befehl als `WARNUNG` gemeldet (z. B. `BAN_HISTORY_FILE` aus der alten Shell-Version). Ungültige Werte werden durch den Standardwert ersetzt. Veraltete Zeilen kannst du aus der Konfiguration löschen. |
| Logrotation | `LOG_MAX_SIZE_MB` (Standard 50) wird jetzt ausgewertet: Das Log wird nach `adguard-shield.log.1` rotiert. |
| `BLOCKED_PORTS` | Kommas sind jetzt erlaubt, ungültige Ports werden mit Warnung ignoriert. Port-Namen wie `domain` werden nicht mehr akzeptiert – bitte Portnummern verwenden. |
| `systemctl reload` | Wird nicht mehr unterstützt; nach Änderungen an der Konfiguration `systemctl restart adguard-shield` verwenden. |
| Subdomain-Flood | Die Basisdomain wird jetzt über die Public Suffix List bestimmt. Hosts unter Plattform-Suffixen wie `github.io` oder `cloudfront.net` zählen als eigene Basisdomains und lösen dadurch seltener Subdomain-Flood-Sperren aus. |
| Whitelist-Netze | Zu breite Netze (`/0`, IPv4 kürzer als `/8`, IPv6 kürzer als `/16`) werden in `WHITELIST` und externen Whitelists ignoriert und mit Warnung gemeldet. |
| Benachrichtigungen | Werden im Daemon jetzt asynchron über eine Warteschlange (256 Einträge) versendet; bei Überlauf werden einzelne Nachrichten verworfen (WARN im Log). |

Rollback: Dienst stoppen, Binary und Datenbank aus dem Backup zurückkopieren (`-wal`/`-shm` der neuen Version vorher löschen), `systemctl daemon-reload`, Dienst starten.

---

## Neues Binary beziehen

Du brauchst ein fertiges Linux-Binary. Das kann aus einem Release, aus CI oder aus einem lokalen Build kommen.

### Variante A: Release-Binary herunterladen

```bash
curl -fL -o adguard-shield-linux-amd64.tar.gz \
  https://git.techniverse.net/scriptos/adguard-shield/releases/download/v1.2.0/adguard-shield-linux-amd64.tar.gz
tar -xzf adguard-shield-linux-amd64.tar.gz
chmod +x ./adguard-shield
```

### Variante B: Lokal mit Go bauen

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o adguard-shield ./cmd/adguard-shieldd
```

### Variante C: Per Docker bauen (ohne lokales Go)

```bash
docker run --rm -v "$PWD":/src -w /src \
  -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
  golang:1.26.9 go build -o adguard-shield ./cmd/adguard-shieldd
```

Auf dem Zielserver muss Go nicht installiert sein, wenn dort nur das fertige Binary ausgeführt wird.

---

## Was `update` macht

Der Update-Befehl nutzt intern dieselbe Routine wie die Installation:

| Schritt | Aktion |
|---:|---|
| 1 | Linux- und Root-Rechte prüfen |
| 2 | Auf alte Shell-Artefakte prüfen |
| 3 | Systemabhängigkeiten prüfen (sofern nicht `--skip-deps`) |
| 4 | Installationsverzeichnis sicherstellen |
| 5 | Neues Binary nach `/opt/adguard-shield/adguard-shield` kopieren |
| 6 | CLI-Befehl `/usr/local/bin/adguard-shield` registrieren/aktualisieren (sofern nicht `--no-register`) |
| 7 | Report-Templates installieren |
| 8 | Konfiguration migrieren (vorhandene Werte behalten, neue ergänzen) |
| 9 | systemd-Service neu schreiben |
| 10 | `systemctl daemon-reload` und Autostart aktivieren (sofern nicht `--no-enable`) |
| 11 | Nachfrage: Service direkt neu starten |

---

## Konfigurationsmigration

Vorhandene Werte bleiben erhalten. Neue Parameter werden am Ende der Datei ergänzt. Der Installer überschreibt keine bestehenden Einstellungen.

Wenn eine Migration nötig ist:

| Datei | Inhalt |
|---|---|
| `adguard-shield.conf` | Aktualisierte Konfiguration mit alten + neuen Parametern |
| `adguard-shield.conf.old` | Backup der vorherigen Datei |

### Änderungen prüfen

```bash
sudo diff -u /opt/adguard-shield/adguard-shield.conf.old /opt/adguard-shield/adguard-shield.conf
```

Falls `diff` keine `.old`-Datei findet, war keine Konfigurationsmigration nötig.

### Neue Parameter prüfen

Nach dem Update solltest du die neu ergänzten Parameter überprüfen und bei Bedarf anpassen:

```bash
sudo nano /opt/adguard-shield/adguard-shield.conf
```

---

## Update-Optionen

### Update mit Service-Neustart

Wenn der Service nach dem Update direkt laufen soll, bestätige die Nachfrage am Ende mit `j`.

Wenn du vorher manuell prüfen möchtest:

```bash
sudo ./adguard-shield update
sudo adguard-shield test
sudo adguard-shield dry-run
sudo systemctl restart adguard-shield
```

### Update ohne Paketprüfung

```bash
sudo ./adguard-shield update --skip-deps
```

Sinnvoll, wenn `iptables`, `ip6tables`, `ipset` und `systemctl` bereits vorhanden sind oder die Paketinstallation nicht über `apt-get` laufen soll.

### Update ohne CLI-Registrierung

```bash
sudo ./adguard-shield update --no-register
```

Damit wird kein Symlink unter `/usr/local/bin/adguard-shield` angelegt oder geändert. Die Anwendung bleibt dann weiterhin über `/opt/adguard-shield/adguard-shield` erreichbar.

### Update mit expliziter Konfigurationsquelle

```bash
sudo ./adguard-shield update --config-source ./adguard-shield.conf
```

### Update in anderem Installationsverzeichnis

```bash
sudo ./adguard-shield update --install-dir /opt/adguard-shield-test
```

**Hinweis:** Die systemd-Unit heißt weiterhin `adguard-shield.service`, und der globale CLI-Befehl heißt weiterhin `/usr/local/bin/adguard-shield`. Mehrere parallele produktive Installationen über dieselbe Unit oder denselben CLI-Befehl sind nicht vorgesehen.

---

## Migration von der alten Shell-Version

Die Go-Version erkennt alte Shell-Artefakte und bricht ab, wenn sie noch vorhanden sind.

### Typische alte Artefakte

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
| `adguard-shield-watchdog.service` | Watchdog-Service |
| `adguard-shield-watchdog.timer` | Watchdog-Timer |

### Warum bricht der Installer ab?

Die alte und die neue Version würden sonst dieselbe Firewall, dieselbe Konfiguration und dieselben Sperren verwalten. Das kann zu schwer nachvollziehbaren Zuständen führen, bei denen zwei Implementierungen sich gegenseitig die Regeln überschreiben.

### Empfohlener Migrationsablauf

```bash
# 1. Konfiguration sichern
sudo cp /opt/adguard-shield/adguard-shield.conf /root/adguard-shield.conf.backup

# 2. Alte Shell-Version mit deren Uninstaller entfernen
#    (dabei Konfiguration behalten, falls der alte Uninstaller diese Option anbietet)

# 3. Neues Go-Binary installieren und alte Konfiguration als Quelle nutzen
sudo ./adguard-shield install --config-source /root/adguard-shield.conf.backup

# 4. API-Verbindung prüfen
sudo adguard-shield test

# 5. Dry-Run: prüfen, was gesperrt würde
sudo adguard-shield dry-run

# 6. Produktiven Service starten
sudo systemctl start adguard-shield
sudo systemctl status adguard-shield
```

**Wichtig:** Wenn der Go-Installer Legacy-Dateien meldet, entferne nur die gemeldeten alten Artefakte der Shell-Version. Keine fremden Firewall-Regeln oder unrelated Dateien löschen.

---

## Nach dem Update prüfen

### Installation

```bash
sudo adguard-shield install-status
```

### Service

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
```

### API-Verbindung

```bash
sudo adguard-shield test
```

### Laufzeitstatus

```bash
sudo adguard-shield status
sudo adguard-shield live --once
```

### Firewall

```bash
sudo adguard-shield firewall-status
```

---

## Rollback

Ein Rollback besteht aus zwei Teilen: altes Binary wieder bereitstellen und passende Konfiguration verwenden.

### Schritt-für-Schritt

```bash
# 1. Service stoppen
sudo systemctl stop adguard-shield

# 2. Altes Binary wiederherstellen
sudo cp ./adguard-shield-alte-version /opt/adguard-shield/adguard-shield
sudo chmod +x /opt/adguard-shield/adguard-shield

# 3. Service starten
sudo systemctl start adguard-shield
```

### Konfiguration zurücksetzen (optional)

```bash
sudo cp /opt/adguard-shield/adguard-shield.conf.old /opt/adguard-shield/adguard-shield.conf
sudo systemctl restart adguard-shield
```

**Hinweis:** SQLite-Schema-Migrationen sind aktuell sehr konservativ. Trotzdem solltest du vor größeren Updates ein Backup der Datenbank erstellen, wenn dir History und aktive Sperren wichtig sind.

---

## Backup vor größeren Updates

```bash
# Service kurz stoppen für konsistentes Backup
sudo systemctl stop adguard-shield

# Konfiguration und Datenbank sichern
sudo cp /opt/adguard-shield/adguard-shield.conf /root/adguard-shield.conf.$(date +%F)
sudo cp /var/lib/adguard-shield/adguard-shield.db /root/adguard-shield.db.$(date +%F)

# Service wieder starten
sudo systemctl start adguard-shield
```

### WAL-Dateien beachten

Bei laufendem SQLite mit WAL können zusätzliche Dateien existieren:

| Datei | Beschreibung |
|---|---|
| `adguard-shield.db` | Hauptdatenbank |
| `adguard-shield.db-wal` | Write-Ahead-Log (enthält noch nicht in die Hauptdatei geschriebene Daten) |
| `adguard-shield.db-shm` | Shared-Memory-Datei |

Am saubersten ist ein kurzer Service-Stop während des Backups. So wird sichergestellt, dass alle WAL-Einträge in die Hauptdatei geschrieben werden.
