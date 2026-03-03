# Tipps & Troubleshooting

## Best Practices

- **Erst immer im Dry-Run testen**, bevor der scharfe Modus aktiviert wird
  ```bash
  sudo /opt/adguard-ratelimit/adguard-ratelimit.sh dry-run
  ```
- **Whitelist großzügig pflegen**: Eigene IPs, Router, wichtige Server nicht vergessen
- **Sperrdauer anpassen**: Für DDoS-artige Muster ggf. länger sperren
- **Logs regelmäßig prüfen**: Falsche Positive erkennen und Whitelist anpassen
- **Ban-History nutzen**: `history`-Befehl zeigt alle vergangenen Sperren — hilfreich um Muster zu erkennen
- **Log-Level auf DEBUG** setzen wenn etwas nicht funktioniert

## Häufige Probleme

### API-Verbindung schlägt fehl

```bash
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh test
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
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh start
```

### Client wird fälschlich gesperrt

1. Client sofort entsperren:
   ```bash
   sudo /opt/adguard-ratelimit/adguard-ratelimit.sh unban 192.168.1.100
   ```
2. In der Ban-History prüfen, warum gesperrt wurde:
   ```bash
   sudo /opt/adguard-ratelimit/adguard-ratelimit.sh history | grep 192.168.1.100
   ```
3. IP zur Whitelist hinzufügen in `adguard-ratelimit.conf`
3. Service neustarten:
   ```bash
   sudo systemctl restart adguard-ratelimit
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
sudo rm -f /var/run/adguard-ratelimit.pid
sudo systemctl start adguard-ratelimit
```

## Deinstallation

```bash
sudo bash install.sh uninstall
```

Oder manuell:
```bash
sudo systemctl stop adguard-ratelimit
sudo systemctl disable adguard-ratelimit
sudo /opt/adguard-ratelimit/iptables-helper.sh remove
sudo rm -rf /opt/adguard-ratelimit
sudo rm -f /etc/systemd/system/adguard-ratelimit.service
sudo systemctl daemon-reload
```
