# Benachrichtigungen

AdGuard Shield kann Ereignisse an Ntfy, Discord, Slack, Gotify oder einen eigenen Webhook senden. Benachrichtigungen sind optional und werden über `adguard-shield.conf` gesteuert.

## Unterstützte Ereignisse

| Ereignis | Beschreibung |
|---|---|
| Service gestartet | Daemon wurde gestartet |
| Service gestoppt | Daemon wurde gestoppt |
| Automatische Sperre | Rate-Limit- oder Subdomain-Flood-Erkennung |
| Watchlist-Sperre | DNS-Flood-Watchlist-Treffer (permanent) |
| Manuelle Sperre | IP wurde manuell per `ban` gesperrt |
| GeoIP-Sperre | Ländersperre ausgelöst (wenn `GEOIP_NOTIFY=true`) |
| Blocklist-Sperre | Externe Blocklist (wenn `EXTERNAL_BLOCKLIST_NOTIFY=true`) |
| Freigabe | IP wurde entsperrt (manuell, abgelaufen oder durch Whitelist) |
| Bulk-Freigabe | `flush`, `geoip-flush` oder `blocklist-flush` |

## Grundkonfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"     # ntfy, discord, slack, gotify oder generic
```

### Mögliche Typen

| Typ | Protokoll | Beschreibung |
|---|---|---|
| `ntfy` | HTTP POST | Push-Benachrichtigungen über ntfy.sh oder selbst gehostete Instanz |
| `discord` | Webhook | Discord-Kanal-Webhook |
| `slack` | Webhook | Slack Incoming Webhook |
| `gotify` | HTTP POST | Gotify-Server mit App-Token |
| `generic` | HTTP POST (JSON) | Eigener Webhook-Endpunkt |

Nach Änderungen:

```bash
sudo systemctl restart adguard-shield
```

---

## Ntfy

Ntfy ist der einfachste Einstieg, weil kein komplexer Webhook-Body benötigt wird.

### Konfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC="adguard-shield"
NTFY_TOKEN=""
NTFY_PRIORITY="4"
```

### Eigene Ntfy-Instanz

```bash
NTFY_SERVER_URL="https://ntfy.example.com"
NTFY_TOPIC="dns-security"
NTFY_TOKEN="tk_geheimer_token"
```

### Prioritäten

| Wert | Bedeutung | Beschreibung |
|---:|---|---|
| `1` | Minimum | Keine Benachrichtigung auf dem Gerät |
| `2` | Niedrig | Leise Benachrichtigung |
| `3` | Standard | Normale Benachrichtigung |
| `4` | Hoch | Benachrichtigung mit Ton |
| `5` | Maximum | Dringende Benachrichtigung |

### Hinweise

- Bei `NOTIFY_TYPE="ntfy"` wird `NOTIFY_WEBHOOK_URL` nicht verwendet.
- Bei privaten Topics oder eigener Instanz ist ein Token empfehlenswert.
- Der Topic-Name sollte nicht öffentlich erratbar sein, um Fremdzugriff zu verhindern.

---

## Discord

### Konfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="discord"
NOTIFY_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
```

### Webhook erstellen

1. Discord-Server öffnen.
2. Servereinstellungen > Integrationen > Webhooks.
3. Neuen Webhook erstellen.
4. Gewünschten Kanal auswählen.
5. URL kopieren und in `NOTIFY_WEBHOOK_URL` eintragen.

Discord erhält den Inhalt als `content`-Feld im JSON-Body.

---

## Slack

### Konfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="slack"
NOTIFY_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"
```

### Webhook einrichten

1. Slack-App mit Incoming Webhooks erstellen oder vorhandene App verwenden.
2. Webhook für den gewünschten Channel aktivieren.
3. Webhook-URL in die Konfiguration kopieren.

Slack erhält den Inhalt als `text`-Feld im JSON-Body.

---

## Gotify

### Konfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="gotify"
NOTIFY_WEBHOOK_URL="https://gotify.example.com/message?token=xxx"
```

### Token erstellen

1. Gotify-Weboberfläche öffnen.
2. Apps > App erstellen.
3. Token aus der App kopieren und in die URL einsetzen.

Gotify erhält `title`, `message` und `priority` als Formularwerte.

---

## Generic Webhook

Für eigene Automatisierung oder Anbindung an andere Systeme.

### Konfiguration

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="generic"
NOTIFY_WEBHOOK_URL="https://example.com/adguard-shield-webhook"
```

### JSON-Payload

AdGuard Shield sendet einen `POST` mit folgendem JSON-Body:

```json
{
  "title": "AdGuard Shield",
  "message": "AdGuard Shield Ban auf dns1\n---\nIP: 192.168.1.50\nHostname: client.local\nGrund: 45x example.com in 60s via DNS, Rate-Limit\nDauer: 1h 0m [Stufe 1/5]\n\nAbuseIPDB: https://www.abuseipdb.com/check/192.168.1.50",
  "client": "192.168.1.50",
  "action": "ban"
}
```

### Mögliche `action`-Werte

| Aktion | Bedeutung |
|---|---|
| `ban` | Sperre wurde gesetzt |
| `unban` | Sperre wurde aufgehoben |
| `manual-flush` | Bulk-Freigabe aller Sperren |
| `geoip-flush` | Bulk-Freigabe aller GeoIP-Sperren |
| `external-blocklist-flush` | Bulk-Freigabe aller externen Blocklist-Sperren |
| `service_start` | Service wurde gestartet |
| `service_stop` | Service wurde gestoppt |

---

## Separate Steuerung für Module

### Externe Blocklist

```bash
EXTERNAL_BLOCKLIST_NOTIFY=false
```

**Warum separat?** Eine große Blocklist kann beim ersten Sync hunderte oder tausende IPs sperren. Wenn jede Sperre eine Nachricht erzeugt, wird der Benachrichtigungskanal unbrauchbar.

| Listengröße | Empfehlung |
|---|---|
| Große Listen (>100 IPs) | `EXTERNAL_BLOCKLIST_NOTIFY=false` (Standard) |
| Kleine, kuratierte Listen (<50 IPs) | `EXTERNAL_BLOCKLIST_NOTIFY=true` möglich |

### GeoIP

```bash
GEOIP_NOTIFY=true
```

Wenn GeoIP aktiv ist, aber keine Nachrichten für GeoIP-Sperren gesendet werden sollen:

```bash
GEOIP_NOTIFY=false
```

---

## Bulk-Freigaben

Diese Befehle können viele IPs auf einmal freigeben:

```bash
sudo adguard-shield flush
sudo adguard-shield geoip-flush
sudo adguard-shield blocklist-flush
```

AdGuard Shield sendet dafür **nicht** eine Nachricht pro IP, sondern eine zusammenfassende Meldung mit der Anzahl der freigegebenen Sperren.

---

## AbuseIPDB-Hinweis in Nachrichten

Bei permanenten Monitor-Sperren kann AdGuard Shield zusätzlich an AbuseIPDB melden.

**Voraussetzungen:**

```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY="..."
```

**Verhalten:**

- Wenn eine AbuseIPDB-Meldung ausgelöst wurde, enthält die Ban-Nachricht einen entsprechenden Hinweis.
- Jede Ban- und Unban-Nachricht enthält einen Link zur AbuseIPDB-Check-Seite der IP.
- AbuseIPDB wird nicht für GeoIP- oder externe Blocklist-Sperren verwendet.

---

## Beispielinhalte

### Service gestartet

```text
AdGuard Shield v1.1.1 wurde auf dns1 gestartet.
```

### Service gestoppt

```text
AdGuard Shield v1.1.1 wurde auf dns1 gestoppt.
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

---

## Fehlersuche

Wenn keine Benachrichtigung ankommt:

```bash
sudo adguard-shield logs --level warn --limit 100
sudo journalctl -u adguard-shield --no-pager -n 100
```

### Checkliste

| Prüfpunkt | Was zu prüfen ist |
|---|---|
| Aktiviert | `NOTIFY_ENABLED=true` gesetzt? |
| Typ | `NOTIFY_TYPE` korrekt geschrieben? |
| Ziel | Webhook-URL oder Ntfy-Topic gesetzt? |
| Token | Token gültig und nicht abgelaufen? |
| Netzwerk | Server kann ausgehende HTTPS-Verbindungen aufbauen? |
| Firewall | Keine Firewall blockiert ausgehende Verbindungen? |
| Modul-Schalter | `EXTERNAL_BLOCKLIST_NOTIFY` oder `GEOIP_NOTIFY` separat deaktiviert? |

Bei `generic` kannst du testweise einen lokalen HTTP-Empfänger oder einen Request-Inspector verwenden, um den gesendeten Payload zu sehen.

---

## Datenschutz

Benachrichtigungen können IP-Adressen, Domainnamen und Hostnamen enthalten. Sende sie nur an Dienste, denen du vertraust.

Für öffentliche oder geteilte Kanäle ist eine eigene Ntfy- oder Gotify-Instanz mit privatem Topic oft die bessere Wahl als ein öffentlicher Kanal.
