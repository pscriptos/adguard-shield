# Webhook-Benachrichtigungen

Das Tool kann bei Sperren und Entsperrungen Benachrichtigungen an verschiedene Dienste senden.

## Aktivierung

In der Konfiguration (`adguard-ratelimit.conf`):

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
NTFY_TOPIC="adguard-ratelimit"
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
  "message": "🚫 DNS Rate-Limit: Client 192.168.1.50 gesperrt ...",
  "action": "ban",
  "client": "192.168.1.50",
  "domain": "microsoft.com"
}
```

## Beispiel-Nachrichten

**Sperre:**
> 🚫 DNS Rate-Limit: Client **192.168.1.50** gesperrt (45x microsoft.com in 60s). Sperre für 3600s.

**Entsperrung:**
> ✅ DNS Rate-Limit: Client **192.168.1.50** wurde entsperrt.
