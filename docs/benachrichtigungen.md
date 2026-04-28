# Webhook-Benachrichtigungen

Das Tool kann beim Starten und Stoppen des Services sowie bei Sperren und Entsperrungen Benachrichtigungen an verschiedene Dienste senden.

## Aktivierung

In der Konfiguration (`adguard-shield.conf`):

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="<typ>"
NOTIFY_WEBHOOK_URL="<url>"
```

## Ntfy

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="ntfy"
NTFY_SERVER_URL="https://ntfy.sh"
NTFY_TOPIC="adguard-shield"
NTFY_TOKEN=""
NTFY_PRIORITY="4"
```

> **Hinweis:** Bei Ntfy wird `NOTIFY_WEBHOOK_URL` nicht benötigt – Server-URL und Topic werden separat konfiguriert.

**Eigene Ntfy-Instanz:**
```bash
NTFY_SERVER_URL="https://ntfy.mein-server.de"
NTFY_TOPIC="dns-security"
NTFY_TOKEN="tk_mein_geheimer_token"
```

**Prioritäten:**
| Wert | Bedeutung |
|------|-----------|
| 1    | Minimum   |
| 2    | Niedrig   |
| 3    | Standard  |
| 4    | Hoch      |
| 5    | Maximum   |

**Token erstellen (Self-hosted):**
1. Ntfy Web-UI → Benutzer/Tokens
2. Token kopieren und in `NTFY_TOKEN` eintragen
3. Bei ntfy.sh: Account erstellen → Access Token generieren

## Discord

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="discord"
NOTIFY_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
```

**Webhook erstellen:**
1. Discord Server → Servereinstellungen → Integrationen → Webhooks
2. Neuer Webhook → URL kopieren

## Gotify

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="gotify"
NOTIFY_WEBHOOK_URL="https://gotify.example.com/message?token=xxx"
```

**Token erstellen:**
1. Gotify Web-UI → Apps → App erstellen
2. Token kopieren und in die URL einfügen

## Slack

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="slack"
NOTIFY_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"
```

**Webhook erstellen:**
1. Slack App → Incoming Webhooks aktivieren
2. Webhook-URL kopieren

## Generic (eigener Endpoint)

```bash
NOTIFY_ENABLED=true
NOTIFY_TYPE="generic"
NOTIFY_WEBHOOK_URL="https://your-server.com/webhook"
```

Sendet einen POST mit JSON-Body:

```json
{
  "message": "🚫 AdGuard Shield Ban auf dns1\n---\nIP: 192.168.1.50\nHostname: client.local\nGrund: 45x microsoft.com in 60s via DNS, Rate-Limit\nDauer: 1h 0m\n\nWhois: https://www.whois.com/whois/192.168.1.50\nAbuseIPDB: https://www.abuseipdb.com/check/192.168.1.50",
  "action": "ban",
  "client": "192.168.1.50",
  "domain": "microsoft.com"
}
```

## Benachrichtigungen und externe Blocklisten

Bei Sperren aus der **externen Blocklist** werden Benachrichtigungen separat über `EXTERNAL_BLOCKLIST_NOTIFY` gesteuert — unabhängig von `NOTIFY_ENABLED`.

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------| 
| `EXTERNAL_BLOCKLIST_NOTIFY` | `false` | Benachrichtigungen bei Blocklist-Sperren aktivieren |

> **Wichtig:** Bei großen Listen `EXTERNAL_BLOCKLIST_NOTIFY=false` belassen. Beim ersten Sync (oder nach einem `blocklist-flush`) werden alle IPs der Liste auf einmal gesperrt — mit `true` würde das zu einer Nachrichten-Flut im Notification-Channel führen. Nur auf `true` setzen, wenn die Liste sehr klein ist.

## Beispiel-Nachrichten

### Service gestartet
**Überschrift:** ✅ AdGuard Shield

> 🟢 AdGuard Shield v0.9.0 wurde auf dns1 gestartet.

### Service gestoppt
**Überschrift:** 🚨 🛡️ AdGuard Shield

> 🔴 AdGuard Shield v0.9.0 wurde auf dns1 gestoppt.

### Watchdog — Service wiederhergestellt
**Überschrift:** 🔄 AdGuard Shield Watchdog

> 🔄 AdGuard Shield Watchdog auf dns1
> ---
> Der Service war ausgefallen und wurde automatisch neu gestartet.
> Versuch: 1

### Watchdog — Recovery fehlgeschlagen
**Überschrift:** 🚨 AdGuard Shield Watchdog

> 🚨 AdGuard Shield Watchdog auf dns1
> ---
> Der Service konnte NICHT automatisch neu gestartet werden!
> Manuelles Eingreifen erforderlich.
> Fehlversuche: 1
> Letzter Fehler: (systemd Statusausgabe)

### Sperre (Ban)
**Überschrift:** 🚨 🛡️ AdGuard Shield

> 🚫 AdGuard Shield Ban auf dns1
> ---
> IP: 95.71.42.116
> Hostname: example-host.provider.net
> Grund: 153x radioportal.techniverse.net in 60s via DNS, Rate-Limit
> Dauer: 1h 0m [Stufe 1/5]
>
> Whois: https://www.whois.com/whois/95.71.42.116
> AbuseIPDB: https://www.abuseipdb.com/check/95.71.42.116

Bei permanenter Sperre mit aktiviertem AbuseIPDB-Reporting erscheint zusätzlich:

> 🚫 AdGuard Shield Ban auf dns1
> ⚠️ IP wurde an AbuseIPDB gemeldet
> ---
> IP: 95.71.42.116
> Hostname: example-host.provider.net
> Grund: 153x radioportal.techniverse.net in 60s via DNS, Rate-Limit
> Dauer: PERMANENT [Stufe 5/5]
>
> Whois: https://www.whois.com/whois/95.71.42.116
> AbuseIPDB: https://www.abuseipdb.com/check/95.71.42.116

Bei DNS-Flood-Watchlist-Treffer (sofort permanent, ohne Stufe):

> 🚫 AdGuard Shield Ban auf dns1
> ⚠️ IP wurde an AbuseIPDB gemeldet
> ---
> IP: 95.71.42.116
> Hostname: example-host.provider.net
> Grund: 45x microsoft.com in 60s via DNS, DNS-Flood-Watchlist
> Dauer: PERMANENT
>
> Whois: https://www.whois.com/whois/95.71.42.116
> AbuseIPDB: https://www.abuseipdb.com/check/95.71.42.116

### Entsperrung (Unban)
**Überschrift:** ✅ AdGuard Shield

> ✅ AdGuard Shield Freigabe auf dns1
> ---
> IP: 95.71.42.116
> Hostname: example-host.provider.net
>
> AbuseIPDB: https://www.abuseipdb.com/check/95.71.42.116

### Externe Blocklist – Sperre
**Überschrift:** 🚨 🛡️ AdGuard Shield

> 🚫 AdGuard Shield Ban auf dns1 (Externe Blocklist)
> ---
> IP: 203.0.113.50
> Hostname: bad-actor.example.com
>
> Whois: https://www.whois.com/whois/203.0.113.50
> AbuseIPDB: https://www.abuseipdb.com/check/203.0.113.50

### Externe Blocklist – Entsperrung
**Überschrift:** ✅ AdGuard Shield

> ✅ AdGuard Shield Freigabe auf dns1 (Externe Blocklist)
> ---
> IP: 203.0.113.50
> Hostname: bad-actor.example.com
>
> AbuseIPDB: https://www.abuseipdb.com/check/203.0.113.50

### Hinweise

- Der **Hostname** der IP wird automatisch per Reverse-DNS aufgelöst (`dig`, `host` oder `getent`). Ist kein PTR-Record vorhanden, wird `(unbekannt)` angezeigt.
- Der **Servername** (`dns1` in den Beispielen) wird dynamisch über `$(hostname)` ermittelt und zeigt, auf welchem Server das Ereignis stattfand.
- Die **Überschrift** unterscheidet sich je nach Aktion:
  - 🚨 🛡️ bei Sperren und Service-Stopp
  - ✅ bei Freigaben und Service-Start
- Bei **permanenten Sperren** mit aktiviertem AbuseIPDB-Reporting wird ein Hinweis eingeblendet, dass die IP an AbuseIPDB gemeldet wurde.
