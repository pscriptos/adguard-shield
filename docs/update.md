# Update-Anleitung

AdGuard Shield wird in der Go-Version über das Binary selbst installiert und aktualisiert. Es gibt kein `install.sh` und kein `update`-Shellskript mehr.

## Kurzfassung

```bash
# neues Linux-Binary bereitstellen
chmod +x ./adguard-shield

# Update durchführen
sudo ./adguard-shield update
```

Am Ende fragt der Updater, ob AdGuard Shield direkt neu gestartet werden soll.

Danach prüfen:

```bash
sudo /opt/adguard-shield/adguard-shield install-status
sudo /opt/adguard-shield/adguard-shield status
sudo journalctl -u adguard-shield --no-pager -n 50
```

## Woher kommt das neue Binary?

Du brauchst ein fertiges Linux-Binary. Das kann aus einem Release, aus CI oder aus einem lokalen Build kommen.

Release-Binary für v1.0.0 herunterladen:

```bash
curl -fL -o adguard-shield-linux-amd64.tar.gz \
  https://git.techniverse.net/scriptos/adguard-shield/releases/download/v1.0.0/adguard-shield-linux-amd64.tar.gz
tar -xzf adguard-shield-linux-amd64.tar.gz
chmod +x ./adguard-shield
```

Build mit lokal installiertem Go:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o adguard-shield ./cmd/adguard-shieldd
```

Build ohne lokale Go-Installation mit Docker:

```bash
docker run --rm -v "$PWD":/src -w /src \
  -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
  golang:1.22 go build -o adguard-shield ./cmd/adguard-shieldd
```

Auf dem Zielserver muss Go nicht installiert sein, wenn dort nur das fertige Binary ausgeführt wird.

## Was `update` macht

Der Update-Befehl nutzt intern dieselbe Routine wie die Installation:

1. Linux- und root-Rechte prüfen.
2. Auf alte Shell-Artefakte prüfen.
3. Systemabhängigkeiten prüfen, sofern nicht `--skip-deps` gesetzt ist.
4. Installationsverzeichnis sicherstellen.
5. neues Binary nach `/opt/adguard-shield/adguard-shield` kopieren.
6. Konfiguration migrieren.
7. systemd-Service neu schreiben.
8. `systemctl daemon-reload` ausführen.
9. Autostart aktivieren, sofern nicht `--no-enable` gesetzt ist.
10. fragen, ob der Service direkt neu gestartet werden soll.

## Konfigurationsmigration

Vorhandene Werte bleiben erhalten. Neue Parameter werden ergänzt.

Wenn eine Migration nötig ist:

```text
/opt/adguard-shield/adguard-shield.conf      # aktualisierte Konfiguration
/opt/adguard-shield/adguard-shield.conf.old  # Backup der vorherigen Datei
```

Nach dem Update solltest du prüfen:

```bash
sudo diff -u /opt/adguard-shield/adguard-shield.conf.old /opt/adguard-shield/adguard-shield.conf
```

Falls `diff` keine Datei findet, war keine Konfigurationsmigration nötig.

## Update mit Service-Neustart

Wenn der Service nach dem Update direkt laufen soll, bestätige die Nachfrage am Ende mit `j`.

Wenn du vorher manuell prüfen möchtest:

```bash
sudo ./adguard-shield update
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield dry-run
sudo systemctl restart adguard-shield
```

## Update ohne Paketprüfung

```bash
sudo ./adguard-shield update --skip-deps
```

Das ist sinnvoll, wenn du sicher weißt, dass `iptables`, `ip6tables`, `ipset` und `systemctl` vorhanden sind oder wenn Paketinstallation auf deinem System nicht über `apt-get` laufen soll.

## Update in anderem Installationsverzeichnis

```bash
sudo ./adguard-shield update --install-dir /opt/adguard-shield-test
```

Beachte: Die systemd-Unit heißt weiterhin `adguard-shield.service`. Mehrere parallele produktive Installationen über dieselbe Unit sind nicht vorgesehen.

## Migration von der alten Shell-Version

Die Go-Version erkennt alte Shell-Artefakte und bricht ab, wenn sie noch vorhanden sind.

Typische Funde:

```text
/opt/adguard-shield/adguard-shield.sh
/opt/adguard-shield/iptables-helper.sh
/opt/adguard-shield/external-blocklist-worker.sh
/opt/adguard-shield/external-whitelist-worker.sh
/opt/adguard-shield/geoip-worker.sh
/opt/adguard-shield/offense-cleanup-worker.sh
/opt/adguard-shield/report-generator.sh
/opt/adguard-shield/unban-expired.sh
/etc/systemd/system/adguard-shield-watchdog.service
/etc/systemd/system/adguard-shield-watchdog.timer
```

Warum Abbruch?

Die alte und die neue Version würden sonst dieselbe Firewall, dieselbe Konfiguration und dieselben Sperren verwalten. Das kann zu schwer nachvollziehbaren Zuständen führen.

Empfohlener Migrationsablauf:

```bash
# Konfiguration sichern
sudo cp /opt/adguard-shield/adguard-shield.conf /root/adguard-shield.conf.backup

# alte Shell-Version mit deren Uninstaller entfernen
# dabei Konfiguration behalten, falls der alte Uninstaller diese Option anbietet

# neues Go-Binary installieren und alte Konfiguration als Quelle nutzen
sudo ./adguard-shield install --config-source /root/adguard-shield.conf.backup

# prüfen
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield dry-run
```

Wenn der Go-Installer Legacy-Dateien meldet, entferne nur die gemeldeten alten Artefakte der Shell-Version. Keine fremden Firewall-Regeln oder unrelated Dateien löschen.

## Nach dem Update prüfen

Installation:

```bash
sudo /opt/adguard-shield/adguard-shield install-status
```

Service:

```bash
sudo systemctl status adguard-shield
sudo journalctl -u adguard-shield --no-pager -n 100
```

API:

```bash
sudo /opt/adguard-shield/adguard-shield test
```

Runtime:

```bash
sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield live --once
```

Firewall:

```bash
sudo /opt/adguard-shield/adguard-shield firewall-status
```

## Rollback

Ein Rollback besteht aus zwei Teilen: altes Binary wieder bereitstellen und passende Konfiguration verwenden.

Vorgehen:

1. Service stoppen.
2. altes Binary nach `/opt/adguard-shield/adguard-shield` kopieren.
3. optional `adguard-shield.conf.old` zurückkopieren.
4. Service starten.

Beispiel:

```bash
sudo systemctl stop adguard-shield
sudo cp ./adguard-shield-alte-version /opt/adguard-shield/adguard-shield
sudo chmod +x /opt/adguard-shield/adguard-shield
sudo systemctl start adguard-shield
```

Wenn die Konfiguration zurückgesetzt werden soll:

```bash
sudo cp /opt/adguard-shield/adguard-shield.conf.old /opt/adguard-shield/adguard-shield.conf
sudo systemctl restart adguard-shield
```

Hinweis: SQLite-Schema-Migrationen sind aktuell sehr konservativ. Trotzdem solltest du vor größeren Updates ein Backup von `/var/lib/adguard-shield/adguard-shield.db` erstellen, wenn dir History und aktive Sperren wichtig sind.

## Backup vor größeren Updates

```bash
sudo systemctl stop adguard-shield
sudo cp /opt/adguard-shield/adguard-shield.conf /root/adguard-shield.conf.$(date +%F)
sudo cp /var/lib/adguard-shield/adguard-shield.db /root/adguard-shield.db.$(date +%F)
sudo systemctl start adguard-shield
```

Bei laufendem SQLite mit WAL können zusätzliche Dateien existieren:

```text
adguard-shield.db-wal
adguard-shield.db-shm
```

Am saubersten ist ein kurzer Service-Stop während des Backups.
