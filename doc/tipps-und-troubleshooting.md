# Tipps & Troubleshooting

## Best Practices

- **Erst immer im Dry-Run testen**, bevor der scharfe Modus aktiviert wird
  ```bash
  sudo /opt/adguard-shield/adguard-shield.sh dry-run
  ```
- **Whitelist großzügig pflegen**: Eigene IPs, Router, wichtige Server nicht vergessen
- **Sperrdauer anpassen**: Für DDoS-artige Muster ggf. länger sperren
- **Logs regelmäßig prüfen**: Falsche Positive erkennen und Whitelist anpassen
- **Ban-History nutzen**: `history`-Befehl zeigt alle vergangenen Sperren — hilfreich um Muster zu erkennen
- **Log-Level auf DEBUG** setzen wenn etwas nicht funktioniert

## Häufige Probleme

### API-Verbindung schlägt fehl

```bash
sudo /opt/adguard-shield/adguard-shield.sh test
```

**Mögliche Ursachen:**
- Falsche URL in `ADGUARD_URL` (Port prüfen!)
- Falsche Zugangsdaten (`ADGUARD_USER` / `ADGUARD_PASS`)
- AdGuard Home läuft nicht
- Firewall blockiert lokale Verbindung

**Lösung:** URL manuell testen:
```bash
curl -s -u admin:passwort http://127.0.0.1:3000/control/querylog?limit=1
```

### iptables-Fehler: "Permission denied"

Das Script muss als **root** laufen, da iptables Root-Rechte benötigt.

```bash
sudo /opt/adguard-shield/adguard-shield.sh start
```

### Client wird fälschlich gesperrt

1. Client sofort entsperren:
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh unban 192.168.1.100
   ```
2. In der Ban-History prüfen, warum gesperrt wurde:
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh history | grep 192.168.1.100
   ```
3. IP zur Whitelist hinzufügen in `adguard-shield.conf`
3. Service neustarten:
   ```bash
   sudo systemctl restart adguard-shield
   ```

### Sperren überleben Reboot nicht

Das ist normal — iptables-Regeln sind flüchtig. Der **Service** erstellt die Chain beim Start automatisch neu. Aktive Sperren aus dem State-Verzeichnis werden aber nicht automatisch wiederhergestellt.

**Optionen:**
- `iptables-persistent` installieren (`apt install iptables-persistent`)
- Oder den State beim Boot wiederherstellen lassen (Feature-Idee)

### Zu viele false positives

- `RATE_LIMIT_MAX_REQUESTS` erhöhen (z.B. 50 oder 100)
- `RATE_LIMIT_WINDOW` vergrößern (z.B. 120 Sekunden)
- Windows-Clients fragen manche Domains von Natur aus sehr oft an — Whitelist nutzen

### Monitor startet nicht (PID-File)

```bash
# Altes PID-File entfernen
sudo rm -f /var/run/adguard-shield.pid
sudo systemctl start adguard-shield
```

## Update durchführen

```bash
# Repository aktualisieren
cd /tmp/adguard-shield
git pull

# Update ausführen (Konfig wird automatisch migriert, Service neu gestartet)
sudo bash install.sh update
```

**Was passiert beim Update:**
- Alle Scripts werden aktualisiert
- Konfiguration wird als `adguard-shield.conf.old` gesichert
- Neue Konfigurationsparameter werden automatisch zur bestehenden Konfig ergänzt
- Bestehende Einstellungen bleiben erhalten
- Service wird per `daemon-reload` neu geladen und automatisch neu gestartet

## Deinstallation

```bash
# Über den Installer (interaktiv mit Menü)
sudo bash install.sh uninstall
```

Oder manuell:
```bash
sudo systemctl stop adguard-shield
sudo systemctl disable adguard-shield
sudo /opt/adguard-shield/iptables-helper.sh remove
sudo rm -rf /opt/adguard-shield
sudo rm -f /etc/systemd/system/adguard-shield.service
sudo systemctl daemon-reload
```

## Voraussetzungen

Folgende Pakete werden für den Betrieb benötigt und bei der Installation automatisch installiert:

| Paket | Zweck |
|-------|-------|
| `curl` | API-Kommunikation mit AdGuard Home |
| `jq` | JSON-Verarbeitung der API-Antworten |
| `iptables` | Firewall-Regeln (IPv4 + IPv6) |
| `gawk` | Textverarbeitung in Scripts |
| `systemd` | Service-Management und Autostart |

Diese werden bei `sudo bash install.sh install` automatisch geprüft und bei Bedarf über den Paketmanager (`apt`, `dnf`, `yum`, `pacman`) nachinstalliert.
