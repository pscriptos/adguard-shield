# Befehle & Nutzung

## Installer / Updater

Der Installer bietet ein interaktives Menü wenn er ohne Argumente aufgerufen wird:

```bash
# Interaktives Menü anzeigen
sudo bash install.sh

# Neuinstallation
sudo bash install.sh install

# Update (mit automatischer Konfigurations-Migration)
sudo bash install.sh update

# Deinstallation
sudo bash install.sh uninstall

# Installationsstatus anzeigen
sudo bash install.sh status

# Hilfe anzeigen
sudo bash install.sh --help
```

### Update-Verhalten

Beim Update passiert automatisch:
1. Alle Scripts werden aktualisiert
2. Die bestehende Konfiguration wird als `adguard-shield.conf.old` gesichert
3. Neue Konfigurationsparameter werden automatisch zur bestehenden Konfig hinzugefügt
4. Bestehende Einstellungen bleiben **immer** erhalten
5. Der systemd Service wird per `daemon-reload` neu geladen
6. Der Service wird automatisch neu gestartet (falls er lief)

### Voraussetzungen

Folgende Pakete werden bei der Installation automatisch installiert (via `apt`):
- `curl` — API-Kommunikation mit AdGuard Home
- `jq` — JSON-Verarbeitung der API-Antworten
- `iptables` — Firewall-Regeln für IP-Sperren
- `gawk` — Textverarbeitung
- `systemd` — Service-Management

## systemd Service

AdGuard Shield wird als systemd Service betrieben. **Zum Starten, Stoppen und Neustarten immer `systemctl` verwenden:**

```bash
# Start / Stop / Restart
sudo systemctl start adguard-shield
sudo systemctl stop adguard-shield
sudo systemctl restart adguard-shield

# Status
sudo systemctl status adguard-shield

# Autostart aktivieren / deaktivieren
sudo systemctl enable adguard-shield
sudo systemctl disable adguard-shield
```

> **Hinweis:** Der Service wird bei der Installation automatisch für den Autostart beim Booten aktiviert. Nach einem Update wird der Service automatisch neu gestartet — ein manueller Neustart ist nicht nötig.

## Monitor — Verwaltungsbefehle

Die folgenden Befehle dienen der **Verwaltung und Diagnose** und können jederzeit ausgeführt werden, auch während der Service läuft:

```bash
# Status + aktive Sperren anzeigen
sudo /opt/adguard-shield/adguard-shield.sh status

# Ban-History anzeigen (letzte 50 Einträge)
sudo /opt/adguard-shield/adguard-shield.sh history

# Ban-History anzeigen (letzte 100 Einträge)
sudo /opt/adguard-shield/adguard-shield.sh history 100

# Alle Sperren aufheben
sudo /opt/adguard-shield/adguard-shield.sh flush

# Einzelne IP entsperren
sudo /opt/adguard-shield/adguard-shield.sh unban 192.168.1.100

# API-Verbindung testen
sudo /opt/adguard-shield/adguard-shield.sh test

# Dry-Run (nur loggen, nichts sperren — läuft im Vordergrund!)
sudo /opt/adguard-shield/adguard-shield.sh dry-run

# Offense-Zähler für alle IPs zurücksetzen (Progressive Sperren)
sudo /opt/adguard-shield/adguard-shield.sh reset-offenses

# Offense-Zähler für eine bestimmte IP zurücksetzen
sudo /opt/adguard-shield/adguard-shield.sh reset-offenses 192.168.1.100

# Externe Blocklist - Status anzeigen
sudo /opt/adguard-shield/adguard-shield.sh blocklist-status

# Externe Blocklist - Einmalige Synchronisation
sudo /opt/adguard-shield/adguard-shield.sh blocklist-sync

# Externe Blocklist - Alle Sperren der externen Liste aufheben
sudo /opt/adguard-shield/adguard-shield.sh blocklist-flush
```

> **⚠ Wichtig:** Zum Starten und Stoppen des Monitors **nicht** `adguard-shield.sh start` bzw. `stop` verwenden! Diese Befehle starten den Prozess im **Vordergrund** — die Ausgabe wird live angezeigt und `Strg+C` beendet den gesamten Prozess. Stattdessen immer `sudo systemctl start/stop/restart adguard-shield` nutzen.

## iptables Helper

Für die manuelle Verwaltung der Firewall-Regeln:

```bash
# Chain erstellen
sudo /opt/adguard-shield/iptables-helper.sh create

# Alle Regeln anzeigen
sudo /opt/adguard-shield/iptables-helper.sh status

# IP manuell sperren
sudo /opt/adguard-shield/iptables-helper.sh ban 192.168.1.100

# IP entsperren
sudo /opt/adguard-shield/iptables-helper.sh unban 192.168.1.100

# Alle Regeln leeren
sudo /opt/adguard-shield/iptables-helper.sh flush

# Chain komplett entfernen
sudo /opt/adguard-shield/iptables-helper.sh remove

# Regeln speichern / wiederherstellen
sudo /opt/adguard-shield/iptables-helper.sh save
sudo /opt/adguard-shield/iptables-helper.sh restore
```

## Externer Blocklist-Worker

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-shield/external-blocklist-worker.sh start

# Worker stoppen
sudo /opt/adguard-shield/external-blocklist-worker.sh stop

# Einmalige Synchronisation (z.B. nach Konfigurationsänderung)
sudo /opt/adguard-shield/external-blocklist-worker.sh sync

# Status anzeigen
sudo /opt/adguard-shield/external-blocklist-worker.sh status

# Alle externen Sperren aufheben
sudo /opt/adguard-shield/external-blocklist-worker.sh flush
```

## Logs

```bash
# systemd Journal
sudo journalctl -u adguard-shield -f

# Log-Datei direkt
sudo tail -f /var/log/adguard-shield.log

# Nur Sperr-Einträge
sudo grep "SPERRE" /var/log/adguard-shield.log

# Nur Entsperr-Einträge
sudo grep "ENTSPERRE" /var/log/adguard-shield.log
```

## Cron-basiertes Entsperren

Als Alternative oder Ergänzung zum Haupt-Monitor:

```bash
# Crontab bearbeiten
sudo crontab -e

# Alle 5 Minuten abgelaufene Sperren prüfen
*/5 * * * * /opt/adguard-shield/unban-expired.sh
```

## Hilfe

Alle verfügbaren Befehle und Optionen des Installers anzeigen:

```bash
sudo bash install.sh --help
sudo bash install.sh -h
```
