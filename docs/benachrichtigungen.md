# Benachrichtigungen

AdGuard Shield kann Ereignisse an Ntfy, Discord, Slack, Gotify oder einen eigenen Webhook senden. Benachrichtigungen sind optional und werden über `adguard-shield.conf` gesteuert.

Typische Ereignisse:

- Service gestartet
- Service gestoppt
- automatische Sperre
- manuelle Sperre
- GeoIP-Sperre
- externe Blocklist-Sperre, falls separat aktiviert
- Freigabe
- Bulk-Freigabe, zum Beispiel durch `flush`

## Grundkonfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
```

Mögliche Typen:

```text
ntfy
discord
slack
gotify
generic
```

Nach Änderungen:

```bash
sudo systemctl restart adguard-shield
```

Zum Prüfen kannst du den Service neu starten oder im Dry-Run eine Erkennung auslösen.

## Ntfy

Ntfy ist der einfachste Einstieg, weil kein komplexer Webhook-Body benötigt wird.

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC="adguard-shield"
NTFY_TOKEN=""
NTFY_PRIORITY="4"
```

Eigene Ntfy-Instanz:

```bash
NTFY_SERVER_URL="https://ntfy.example.com"
NTFY_TOPIC="dns-security"
NTFY_TOKEN="tk_geheimer_token"
```

Prioritäten:

| Wert | Bedeutung |
|---:|---|
| `1` | Minimum |
| `2` | Niedrig |
| `3` | Standard |
| `4` | Hoch |
| `5` | Maximum |

Hinweise:

- Bei `NOTIFY_TYPE="ntfy"` wird `NOTIFY_WEBHOOK_URL` nicht verwendet.
- Bei privaten Topics oder eigener Instanz ist ein Token empfehlenswert.
- Der Topic-Name sollte nicht öffentlich erratbar sein.

## Discord

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="discord"
NOTIFY_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
```

Webhook erstellen:

1. Discord-Server öffnen.
2. Servereinstellungen öffnen.
3. Integrationen auswählen.
4. Webhooks öffnen.
5. Neuen Webhook erstellen.
6. URL kopieren und in `NOTIFY_WEBHOOK_URL` eintragen.

Discord erhält den Inhalt als `content`.

## Slack

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="slack"
NOTIFY_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"
```

Slack erhält den Inhalt als `text`.

Einrichtung grob:

1. Slack-App mit Incoming Webhooks einrichten.
2. Webhook für den gewünschten Channel aktivieren.
3. Webhook-URL in die Konfiguration kopieren.

## Gotify

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="gotify"
NOTIFY_WEBHOOK_URL="https://gotify.example.com/message?token=xxx"
```

Gotify erhält `title`, `message` und `priority` als Formularwerte.

Token erstellen:

1. Gotify-Weboberfläche öffnen.
2. Apps auswählen.
3. App erstellen.
4. Token in die URL einsetzen.

## Generic Webhook

Für eigene Automatisierung:

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="generic"
NOTIFY_WEBHOOK_URL="https://example.com/adguard-shield-webhook"
```

AdGuard Shield sendet einen `POST` mit JSON:

```json
{
  "title": "AdGuard Shield",
  "message": "AdGuard Shield Ban auf dns1\n---\nIP: 192.168.1.50\nHostname: client.local\nGrund: 45x example.com in 60s via DNS, Rate-Limit\nDauer: 1h 0m [Stufe 1/5]\n\nAbuseIPDB: https://www.abuseipdb.com/check/192.168.1.50",
  "client": "192.168.1.50",
  "action": "ban"
}
```

Mögliche `action`-Werte:

| Aktion | Bedeutung |
|---|---|
| `ban` | Sperre |
| `unban` | Freigabe |
| `manual-flush` | Bulk-Freigabe |
| `geoip-flush` | Bulk-Freigabe von GeoIP-Sperren |
| `external-blocklist-flush` | Bulk-Freigabe externer Blocklist-Sperren |
| `service_start` | Service gestartet |
| `service_stop` | Service gestoppt |

## Externe Blocklist und Benachrichtigungen

Für Sperren aus externen Blocklisten gibt es einen zusätzlichen Schalter:

```bash
EXTERNAL_BLOCKLIST_NOTIFY=false
```

Warum separat?

Eine große Blocklist kann beim ersten Sync hunderte oder tausende IPs sperren. Wenn dafür jede Sperre eine Nachricht erzeugt, wird dein Benachrichtigungskanal unbrauchbar.

Empfehlung:

```bash
EXTERNAL_BLOCKLIST_NOTIFY=false
```

Nur bei kleinen, kuratierten Listen:

```bash
EXTERNAL_BLOCKLIST_NOTIFY=true
```

## GeoIP-Benachrichtigungen

GeoIP hat ebenfalls einen eigenen Schalter:

```bash
GEOIP_NOTIFY=true
```

Wenn GeoIP aktiv ist, aber keine Nachrichten für GeoIP-Sperren gesendet werden sollen:

```bash
GEOIP_NOTIFY=false
```

## Bulk-Freigaben

Diese Befehle können viele IPs auf einmal freigeben:

```bash
sudo /opt/adguard-shield/adguard-shield flush
sudo /opt/adguard-shield/adguard-shield geoip-flush
sudo /opt/adguard-shield/adguard-shield blocklist-flush
```

AdGuard Shield sendet dafür nicht eine Nachricht pro IP, sondern eine zusammenfassende Meldung mit der Anzahl der freigegebenen Sperren.

## AbuseIPDB-Hinweis in Nachrichten

Bei permanenten Monitor-Sperren kann AdGuard Shield zusätzlich an AbuseIPDB melden.

Voraussetzungen:

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."
```

Wenn eine Meldung ausgelöst wurde, enthält die Ban-Nachricht einen entsprechenden Hinweis. Außerdem enthält jede Ban- und Unban-Nachricht einen Link zur AbuseIPDB-Check-Seite der IP.

AbuseIPDB wird nicht für GeoIP- oder externe Blocklist-Sperren verwendet.

## Beispielinhalte

### Service gestartet

```text
AdGuard Shield v1.0.0 wurde auf dns1 gestartet.
```

### Service gestoppt

```text
AdGuard Shield v1.0.0 wurde auf dns1 gestoppt.
```

### Rate-Limit-Sperre

```text
AdGuard Shield Ban auf dns1
---
IP: 192.0.2.50
Hostname: client.example.com
Grund: 45x example.com in 60s via DNS, Rate-Limit
Dauer: 1h 0m [Stufe 1/5]

AbuseIPDB: https://www.abuseipdb.com/check/192.0.2.50
```

### Watchlist-Sperre

```text
AdGuard Shield Ban auf dns1
IP wurde an AbuseIPDB gemeldet
---
IP: 192.0.2.51
Hostname: unknown
Grund: 75x microsoft.com in 60s via DoH, DNS-Flood-Watchlist
Dauer: PERMANENT

AbuseIPDB: https://www.abuseipdb.com/check/192.0.2.51
```

### GeoIP-Sperre

```text
AdGuard Shield GeoIP-Sperre auf dns1
---
IP: 203.0.113.10
Land: BR
Modus: Blocklist
Dauer: PERMANENT

AbuseIPDB: https://www.abuseipdb.com/check/203.0.113.10
```

### Freigabe

```text
AdGuard Shield Freigabe auf dns1
---
IP: 192.0.2.50
Hostname: client.example.com

AbuseIPDB: https://www.abuseipdb.com/check/192.0.2.50
```

### Bulk-Freigabe

```text
AdGuard Shield Bulk-Freigabe auf dns1
---
Freigegebene IPs: 28
Aktion: Manual-Flush
```

## Fehlersuche

Wenn keine Benachrichtigung ankommt:

```bash
sudo /opt/adguard-shield/adguard-shield logs --level warn --limit 100
sudo journalctl -u adguard-shield --no-pager -n 100
```

Prüfe:

- `NOTIFY_ENABLED=true`
- `NOTIFY_TYPE` korrekt geschrieben
- Ziel-URL oder Ntfy-Topic gesetzt
- Token gültig
- Server kann den Webhook erreichen
- Firewall des Servers blockiert ausgehende HTTPS-Verbindungen nicht

Bei `generic` kannst du testweise einen lokalen HTTP-Empfänger oder einen Request-Inspector verwenden.

## Datenschutz

Benachrichtigungen können IP-Adressen, Domainnamen und Hostnamen enthalten. Sende sie nur an Dienste, denen du vertraust. Für öffentliche oder geteilte Kanäle ist Ntfy mit privatem Topic oder eine eigene Ntfy/Gotify-Instanz oft die bessere Wahl.
