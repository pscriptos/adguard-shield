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
- DNS-Auflösung des Hostnames fehlgeschlagen
- SSL/TLS-Zertifikatfehler (bei HTTPS)

#### Schritt-für-Schritt Diagnose

**1. Base-URL Erreichbarkeit prüfen (ohne Auth):**
```bash
# Vollständige Diagnose mit HTTP-Headern und Verbindungsdetails
curl -ikv https://dns1.domain.com 2>&1

# Nur HTTP-Statuscode prüfen (schnell)
curl -s -o /dev/null -w "%{http_code}\n" -k https://dns1.domain.com
```

> `-i` zeigt HTTP-Response-Header, `-k` ignoriert SSL-Fehler, `-v` zeigt Verbindungsdetails (DNS, TLS-Handshake, etc.)

**2. DNS-Auflösung testen:**
```bash
# Hostname auflösen
dig +short dns1.domain.com

# Oder mit nslookup
nslookup dns1.domain.com
```

**3. Port-Erreichbarkeit testen:**
```bash
# TCP-Verbindung zum Port prüfen (z.B. Port 3000)
nc -zv 127.0.0.1 3000

# Oder mit curl
curl -v telnet://127.0.0.1:3000
```

**4. API-Endpunkt mit Authentifizierung testen:**
```bash
# Query-Log abfragen (mit Auth + Response-Header)
curl -i -u admin:passwort https://dns1.domain.com/control/querylog?limit=1

# Nur HTTP-Status zurückgeben
curl -s -o /dev/null -w "%{http_code}\n" -u admin:passwort https://dns1.domain.com/control/querylog?limit=1
```

**5. AdGuard Home Status-API prüfen:**
```bash
# Allgemeinen Status abfragen (benötigt keine Auth)
curl -ik https://dns1.domain.com/control/status
```

#### Typische Fehlercodes

| HTTP-Code | Bedeutung | Lösung |
|-----------|-----------|--------|
| `000` | Keine Verbindung | Host nicht erreichbar, DNS-Fehler oder Firewall |
| `200` | Erfolg | Alles in Ordnung ✅ |
| `301/302` | Weiterleitung | URL prüfen — evtl. fehlt `https://` oder Port |
| `401` | Nicht autorisiert | `ADGUARD_USER` / `ADGUARD_PASS` prüfen |
| `403` | Zugriff verweigert | Zugangsdaten oder IP-Beschränkung in AdGuard Home |
| `404` | Nicht gefunden | URL falsch oder AdGuard Home Version zu alt |
| `502/503` | Service nicht verfügbar | AdGuard Home läuft nicht oder wird gerade neu gestartet |

#### curl Exit-Codes

| Exit-Code | Bedeutung |
|-----------|-----------|
| `6` | DNS-Auflösung fehlgeschlagen — Hostname prüfen |
| `7` | Verbindung abgelehnt — Läuft AdGuard Home? Port korrekt? |
| `28` | Timeout — Host nicht erreichbar oder Firewall blockiert |
| `35` | SSL/TLS-Handshake fehlgeschlagen |
| `51` | SSL-Zertifikat: Hostname stimmt nicht überein |
| `60` | SSL-Zertifikat: nicht vertrauenswürdig (selbstsigniert?) |

> **Tipp:** Bei selbstsignierten Zertifikaten `-k` an curl anhängen, um SSL-Fehler zu ignorieren. AdGuard Shield verwendet intern automatisch `-k` bei der API-Kommunikation.

**Lösung:** URL und Zugangsdaten in der Konfiguration anpassen:
```bash
sudo nano /opt/adguard-shield/adguard-shield.conf
sudo systemctl restart adguard-shield
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
3. Offense-Zähler für die IP zurücksetzen (damit die progressive Sperre wieder bei Stufe 1 beginnt):
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh reset-offenses 192.168.1.100
   ```
4. IP zur Whitelist hinzufügen in `adguard-shield.conf`
5. Service neustarten:
   ```bash
   sudo systemctl restart adguard-shield
   ```

### Client wurde permanent gesperrt (Progressive Sperren)

Wenn eine IP die maximale Stufe der progressiven Sperren erreicht hat, wird sie permanent gesperrt und nicht automatisch aufgehoben.

1. IP entsperren:
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh unban 192.168.1.100
   ```
2. Offense-Zähler zurücksetzen:
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh reset-offenses 192.168.1.100
   ```
3. Prüfen ob die IP auf die Whitelist gehört, oder die Progressive-Ban-Einstellungen anpassen (`PROGRESSIVE_BAN_MAX_LEVEL` erhöhen oder auf `0` setzen für keine permanenten Sperren)

### Sperren überleben Reboot nicht

Das ist normal — iptables-Regeln sind flüchtig. Der **Service** erstellt die Chain beim Start automatisch neu. Aktive Sperren aus der SQLite-Datenbank werden aber nicht automatisch als iptables-Regeln wiederhergestellt.

**Optionen:**
- `iptables-persistent` installieren (`apt install iptables-persistent`)
- Oder den State beim Boot wiederherstellen lassen (Feature-Idee)

### Zu viele false positives

- `RATE_LIMIT_MAX_REQUESTS` erhöhen (z.B. 50 oder 100)
- `RATE_LIMIT_WINDOW` vergrößern (z.B. 120 Sekunden)
- Windows-Clients fragen manche Domains von Natur aus sehr oft an — Whitelist nutzen

### Subdomain-Flood-Erkennung sperrt legitime Clients

Manche Dienste (z.B. CDNs, Cloud-Dienste, Microsoft 365) nutzen von Natur aus viele verschiedene Subdomains. Falls ein legitimer Client fälschlicherweise durch die Subdomain-Flood-Erkennung gesperrt wird:

1. Client sofort entsperren:
   ```bash
   sudo /opt/adguard-shield/adguard-shield.sh unban <IP>
   ```
2. Schwellwert erhöhen — z.B. von 50 auf 100 oder 150:
   ```bash
   SUBDOMAIN_FLOOD_MAX_UNIQUE=100
   ```
3. Zeitfenster vergrößern — z.B. auf 120 Sekunden:
   ```bash
   SUBDOMAIN_FLOOD_WINDOW=120
   ```
4. Oder die IP zur Whitelist hinzufügen
5. Im Zweifelsfall die Erkennung temporär deaktivieren:
   ```bash
   SUBDOMAIN_FLOOD_ENABLED=false
   ```

> **Tipp:** Im Dry-Run-Modus (`sudo /opt/adguard-shield/adguard-shield.sh dry-run`) kann man beobachten, welche Clients die Subdomain-Flood-Erkennung auslösen würden, ohne sie wirklich zu sperren.

### Monitor startet nicht (PID-File)

```bash
# Altes PID-File entfernen
sudo rm -f /var/run/adguard-shield.pid
sudo systemctl start adguard-shield
```

### Service ist ausgefallen und startet nicht mehr

Wenn systemd das Restart-Limit erreicht hat (z.B. `"Start request repeated too quickly"`), hilft der **Watchdog** — er prüft alle 5 Minuten ob der Service läuft und startet ihn automatisch neu.

**Watchdog-Status prüfen:**
```bash
# Timer-Status anzeigen
sudo systemctl status adguard-shield-watchdog.timer

# Letzte Watchdog-Ausführungen anzeigen
sudo systemctl list-timers adguard-shield-watchdog.timer

# Watchdog-Logs prüfen
sudo journalctl -u adguard-shield-watchdog.service --no-pager -n 20
```

**Manuelles Recovery (sofort):**
```bash
# systemd-Fehlerzähler zurücksetzen und Service starten
sudo systemctl reset-failed adguard-shield.service
sudo systemctl start adguard-shield.service
```

**Watchdog nachträglich aktivieren:**
```bash
sudo systemctl enable adguard-shield-watchdog.timer
sudo systemctl start adguard-shield-watchdog.timer
```

> **Hinweis:** Der Watchdog sendet automatisch eine Benachrichtigung (falls `NOTIFY_ENABLED=true`), wenn er den Service wiederbeleben muss oder die Recovery fehlschlägt.

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
- Bestehende Flat-File-Daten werden einmalig in die SQLite-Datenbank migriert (mit Fortschrittsanzeige)
- Service wird per `daemon-reload` neu geladen und automatisch neu gestartet

## Deinstallation

Ab Version 0.6 gibt es einen eigenständigen Uninstaller im Installationsverzeichnis. Die Deinstallation kann daher jederzeit durchgeführt werden, **ohne die originalen Installationsdateien (install.sh) behalten zu müssen**:

```bash
# Empfohlen: direkt aus dem Installationsverzeichnis ausführen
sudo bash /opt/adguard-shield/uninstall.sh

# Alternativ: über den Installer (sofern noch vorhanden)
sudo bash install.sh uninstall
```

Beide Wege sind gleichwertig — `install.sh uninstall` delegiert intern an `/opt/adguard-shield/uninstall.sh`.

Oder manuell:
```bash
sudo systemctl stop adguard-shield
sudo systemctl disable adguard-shield
sudo systemctl stop adguard-shield-watchdog.timer
sudo systemctl disable adguard-shield-watchdog.timer
sudo /opt/adguard-shield/iptables-helper.sh remove
sudo rm -rf /opt/adguard-shield
sudo rm -f /etc/systemd/system/adguard-shield.service
sudo rm -f /etc/systemd/system/adguard-shield-watchdog.service
sudo rm -f /etc/systemd/system/adguard-shield-watchdog.timer
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
| `sqlite3` | Datenbank für State-Management, Ban-History und Offense-Tracking |

Diese werden bei `sudo bash install.sh install` automatisch geprüft und bei Bedarf über den Paketmanager (`apt`, `dnf`, `yum`, `pacman`) nachinstalliert.
