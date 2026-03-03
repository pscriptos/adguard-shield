# Konfiguration

Die Konfigurationsdatei liegt nach der Installation unter:

```
/opt/adguard-shield/adguard-shield.conf
```

## Automatische Konfigurations-Migration

Bei einem **Update** (`sudo bash install.sh update`) wird die Konfiguration automatisch migriert:

1. Die aktuelle Konfiguration wird als **Backup** gespeichert: `adguard-shield.conf.old`
2. Neue Parameter (die in der alten Konfig noch nicht existieren) werden **automatisch** zur bestehenden Konfiguration hinzugefügt
3. Alle bestehenden Einstellungen bleiben **unverändert** erhalten

Dadurch muss der Benutzer bei Updates die Konfiguration nicht manuell austauschen oder vergleichen.

> **Hinweis:** Nach einem Update empfiehlt es sich, die eventuell neu hinzugefügten Parameter zu prüfen und bei Bedarf anzupassen.

## Alle Parameter

### AdGuard Home API

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `ADGUARD_URL` | `http://127.0.0.1:3000` | AdGuard Home Web-UI URL |
| `ADGUARD_USER` | `admin` | API Benutzername |
| `ADGUARD_PASS` | `changeme` | API Passwort |

### Rate-Limit

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `RATE_LIMIT_MAX_REQUESTS` | `30` | Max. Anfragen pro Domain/Client innerhalb des Zeitfensters |
| `RATE_LIMIT_WINDOW` | `60` | Zeitfenster in Sekunden |
| `CHECK_INTERVAL` | `10` | Wie oft die Logs geprüft werden (Sekunden) |
| `API_QUERY_LIMIT` | `500` | Anzahl API-Einträge pro Abfrage (max 5000) |

### Sperr-Einstellungen

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `BAN_DURATION` | `3600` | Sperrdauer in Sekunden (3600 = 1 Stunde) |
| `IPTABLES_CHAIN` | `ADGUARD_SHIELD` | Name der iptables Chain |
| `BLOCKED_PORTS` | `53 443 853 784 8853` | Ports die gesperrt werden |
| `WHITELIST` | `127.0.0.1,::1` | IPs die nie gesperrt werden (kommagetrennt) |

### Logging

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `LOG_FILE` | `/var/log/adguard-shield.log` | Pfad zur Log-Datei |
| `LOG_LEVEL` | `INFO` | Log-Level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `LOG_MAX_SIZE_MB` | `50` | Max. Log-Größe bevor rotiert wird |
| `BAN_HISTORY_FILE` | `/var/log/adguard-shield-bans.log` | Datei für die Ban-History (alle Sperren/Entsperrungen) |

### Benachrichtigungen

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `NOTIFY_ENABLED` | `false` | Webhook-Benachrichtigungen aktivieren |
| `NOTIFY_WEBHOOK_URL` | *(leer)* | Webhook-URL |
| `NOTIFY_TYPE` | `generic` | Typ: `discord`, `slack`, `gotify`, `generic` |

### Erweitert

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `STATE_DIR` | `/var/lib/adguard-shield` | Verzeichnis für State-Dateien |
| `PID_FILE` | `/var/run/adguard-shield.pid` | PID-Datei |
| `DRY_RUN` | `false` | Testmodus — nur loggen, nicht sperren |
### Externe Blocklist

Ermöglicht das Einbinden externer IP-Blocklisten (z.B. gehostete Textdateien mit einer IP pro Zeile). Der Worker läuft als Hintergrundprozess und prüft periodisch auf Änderungen.

| Parameter | Standard | Beschreibung |
|-----------|----------|}--------------|
| `EXTERNAL_BLOCKLIST_ENABLED` | `false` | Aktiviert den externen Blocklist-Worker |
| `EXTERNAL_BLOCKLIST_URLS` | *(leer)* | URL(s) zu Textdateien mit IPs (kommagetrennt) |
| `EXTERNAL_BLOCKLIST_INTERVAL` | `300` | Prüfintervall in Sekunden (300 = 5 Min.) |
| `EXTERNAL_BLOCKLIST_BAN_DURATION` | `0` | Sperrdauer in Sekunden (0 = permanent bis IP aus Liste entfernt) |
| `EXTERNAL_BLOCKLIST_AUTO_UNBAN` | `true` | IPs automatisch entsperren wenn aus Liste entfernt |
| `EXTERNAL_BLOCKLIST_CACHE_DIR` | `/var/lib/adguard-shield/external-blocklist` | Lokaler Cache für heruntergeladene Listen |

#### Externe Blocklist einrichten

1. Erstelle eine Textdatei auf einem Webserver mit einer IP pro Zeile:

```text
# Kommentare werden ignoriert
192.168.100.50
10.0.0.99
2001:db8::dead:beef
```

2. Aktiviere die Blocklist in der Konfiguration:

```bash
EXTERNAL_BLOCKLIST_ENABLED=true
EXTERNAL_BLOCKLIST_URLS="https://example.com/blocklist.txt"
EXTERNAL_BLOCKLIST_INTERVAL=300
```

3. Mehrere Listen können kommagetrennt angegeben werden:

```bash
EXTERNAL_BLOCKLIST_URLS="https://example.com/list1.txt,https://other.com/list2.txt"
```

4. Service neustarten:

```bash
sudo systemctl restart adguard-shield
```
## Gesperrte Ports im Detail

Bei einem Rate-Limit-Verstoß werden **alle** DNS-Protokoll-Ports für den Client gesperrt:

| Port | Protokoll | Beschreibung |
|------|-----------|-------------|
| 53   | UDP/TCP   | Standard DNS |
| 443  | TCP       | DNS-over-HTTPS (DoH) |
| 853  | TCP       | DNS-over-TLS (DoT) |
| 853  | UDP       | DNS-over-QUIC (DoQ) |
| 784  | UDP       | DNS-over-QUIC (alternativ) |
| 8853 | UDP       | DNS-over-QUIC (alternativ) |

## Whitelist richtig pflegen

Die Whitelist sollte mindestens enthalten:

- `127.0.0.1` und `::1` (Localhost)
- Die IP deines Routers / Gateways
- Deine eigenen Management-IPs
- Andere vertrauenswürdige DNS-Clients

Beispiel:

```
WHITELIST="127.0.0.1,::1,192.168.1.1,192.168.1.10,fd00::1"
```
