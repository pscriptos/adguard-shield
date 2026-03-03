# Befehle & Nutzung

## Monitor (Hauptscript)

```bash
# Starten
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh start

# Stoppen
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh stop

# Status + aktive Sperren anzeigen
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh status

# Ban-History anzeigen (letzte 50 Einträge)
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh history

# Ban-History anzeigen (letzte 100 Einträge)
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh history 100

# Alle Sperren aufheben
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh flush

# Einzelne IP entsperren
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh unban 192.168.1.100

# API-Verbindung testen
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh test

# Dry-Run (nur loggen, nichts sperren)
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh dry-run

# Externe Blocklist - Status anzeigen
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh blocklist-status

# Externe Blocklist - Einmalige Synchronisation
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh blocklist-sync

# Externe Blocklist - Alle Sperren der externen Liste aufheben
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh blocklist-flush
```

## iptables Helper

Für die manuelle Verwaltung der Firewall-Regeln:

```bash
# Chain erstellen
sudo /opt/adguard-ratelimit/iptables-helper.sh create

# Alle Regeln anzeigen
sudo /opt/adguard-ratelimit/iptables-helper.sh status

# IP manuell sperren
sudo /opt/adguard-ratelimit/iptables-helper.sh ban 192.168.1.100

# IP entsperren
sudo /opt/adguard-ratelimit/iptables-helper.sh unban 192.168.1.100

# Alle Regeln leeren
sudo /opt/adguard-ratelimit/iptables-helper.sh flush

# Chain komplett entfernen
sudo /opt/adguard-ratelimit/iptables-helper.sh remove

# Regeln speichern / wiederherstellen
sudo /opt/adguard-ratelimit/iptables-helper.sh save
sudo /opt/adguard-ratelimit/iptables-helper.sh restore
```

## Externer Blocklist-Worker

Der Worker kann auch standalone gesteuert werden:

```bash
# Worker manuell starten (normalerweise automatisch per Hauptscript)
sudo /opt/adguard-ratelimit/external-blocklist-worker.sh start

# Worker stoppen
sudo /opt/adguard-ratelimit/external-blocklist-worker.sh stop

# Einmalige Synchronisation (z.B. nach Konfigurationsänderung)
sudo /opt/adguard-ratelimit/external-blocklist-worker.sh sync

# Status anzeigen
sudo /opt/adguard-ratelimit/external-blocklist-worker.sh status

# Alle externen Sperren aufheben
sudo /opt/adguard-ratelimit/external-blocklist-worker.sh flush
```

## systemd Service

```bash
# Start / Stop / Restart
sudo systemctl start adguard-ratelimit
sudo systemctl stop adguard-ratelimit
sudo systemctl restart adguard-ratelimit

# Status
sudo systemctl status adguard-ratelimit

# Autostart aktivieren / deaktivieren
sudo systemctl enable adguard-ratelimit
sudo systemctl disable adguard-ratelimit
```

## Logs

```bash
# systemd Journal
sudo journalctl -u adguard-ratelimit -f

# Log-Datei direkt
sudo tail -f /var/log/adguard-ratelimit.log

# Nur Sperr-Einträge
sudo grep "SPERRE" /var/log/adguard-ratelimit.log

# Nur Entsperr-Einträge
sudo grep "ENTSPERRE" /var/log/adguard-ratelimit.log
```

## Cron-basiertes Entsperren

Als Alternative oder Ergänzung zum Haupt-Monitor:

```bash
# Crontab bearbeiten
sudo crontab -e

# Alle 5 Minuten abgelaufene Sperren prüfen
*/5 * * * * /opt/adguard-ratelimit/unban-expired.sh
```
