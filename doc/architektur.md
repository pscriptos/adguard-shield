# Architektur & Funktionsweise

## Überblick

```
┌─────────────────────┐
│   Client Anfragen   │
│  (DNS/DoH/DoT/DoQ)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐     ┌──────────────────────┐
│   AdGuard Home      │────▶│   Query Log (API)    │
│   DNS Server        │     └──────────┬───────────┘
└─────────────────────┘                │
                                       ▼
                            ┌──────────────────────┐
                            │  adguard-ratelimit.sh │
                            │  (Monitor Script)     │
                            └──────────┬───────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                ┌──────────┐   ┌──────────┐   ┌──────────┐
                │ iptables │   │   Log    │   │ Webhook  │
                │  DROP    │   │  Datei   │   │ Notify   │
                └──────────┘   └──────────┘   └──────────┘
```

## Ablauf einer Sperre

1. Client `192.168.1.50` fragt `microsoft.com` 45x in 60 Sekunden an
2. Monitor fragt die AdGuard Home API alle 10 Sekunden ab (`/control/querylog`)
3. Die Anfragen werden pro Client+Domain-Kombination gezählt
4. Monitor erkennt: 45 > 30 (Limit überschritten)
5. Prüfung: Ist der Client auf der Whitelist? → Nein
6. iptables-Regel wird erstellt: `DROP` für `192.168.1.50` auf allen DNS-Ports
7. State-Datei wird angelegt: `/var/lib/adguard-ratelimit/192.168.1.50.ban`
8. Ban-History Eintrag wird in `/var/log/adguard-ratelimit-bans.log` geschrieben
9. Log-Eintrag + optionale Webhook-Benachrichtigung
10. Nach 3600 Sekunden (1 Stunde): automatische Entsperrung + History-Eintrag

## iptables Strategie

Das Tool erstellt eine eigene Chain `ADGUARD_RATELIMIT`:

```
INPUT Chain
  ├── ... (bestehende Regeln bleiben unberührt)
  ├── -p tcp --dport 53  → ADGUARD_RATELIMIT
  ├── -p udp --dport 53  → ADGUARD_RATELIMIT
  ├── -p tcp --dport 443 → ADGUARD_RATELIMIT
  ├── -p udp --dport 443 → ADGUARD_RATELIMIT
  ├── -p tcp --dport 853 → ADGUARD_RATELIMIT
  ├── -p udp --dport 853 → ADGUARD_RATELIMIT
  └── ...

ADGUARD_RATELIMIT Chain
  ├── -s 192.168.1.50 → DROP  (gesperrter Client)
  ├── -s 10.0.0.25    → DROP  (gesperrter Client)
  └── RETURN                   (alle anderen passieren)
```

**Vorteile der eigenen Chain:**
- Greift nicht in bestehende Firewall-Regeln ein
- Kann komplett geflusht werden ohne andere Regeln zu beeinflussen
- Einfaches Debugging per `iptables -L ADGUARD_RATELIMIT`

## State-Management

Jede aktive Sperre wird als Datei gespeichert:

```
/var/lib/adguard-ratelimit/192.168.1.50.ban
```

Inhalt:
```
CLIENT_IP=192.168.1.50
DOMAIN=microsoft.com
COUNT=45
BAN_TIME=2026-03-03 14:30:00
BAN_UNTIL_EPOCH=1741012200
BAN_UNTIL=2026-03-03 15:30:00
```

Das ermöglicht:
- Persistenz über Script-Neustarts hinweg
- Statusabfragen jederzeit möglich
- Automatisches Aufräumen per Cron-Job

## Dateistruktur nach Installation

```
/opt/adguard-ratelimit/
├── adguard-ratelimit.sh     # Haupt-Monitor-Script
├── adguard-ratelimit.conf   # Konfiguration (chmod 600)
├── iptables-helper.sh       # iptables Verwaltung
└── unban-expired.sh         # Cron-basiertes Entsperren

/etc/systemd/system/
└── adguard-ratelimit.service

/var/lib/adguard-ratelimit/
└── *.ban                    # State-Dateien aktiver Sperren

/var/log/
├── adguard-ratelimit.log        # Laufzeit-Log
└── adguard-ratelimit-bans.log   # Ban-History (alle Sperren/Entsperrungen)
```

## Ban-History

Jede Sperre und Entsperrung wird dauerhaft in der Ban-History protokolliert (`/var/log/adguard-ratelimit-bans.log`). Das ermöglicht eine lückenlose Nachvollziehbarkeit, auch nachdem State-Dateien bereits gelöscht wurden.

**Format:**
```
ZEITSTEMPEL         | AKTION | CLIENT-IP                               | DOMAIN                         | ANFRAGEN | SPERRDAUER | GRUND
2026-03-03 14:30:12 | BAN    | 192.168.1.50                            | microsoft.com                  | 45       | 3600s      | rate-limit
2026-03-03 15:30:12 | UNBAN  | 192.168.1.50                            | microsoft.com                  | -        | -          | expired
2026-03-03 16:10:33 | UNBAN  | 10.0.0.25                               | telemetry.example.com          | -        | -          | manual
```

**Mögliche Gründe (GRUND-Spalte):**
| Grund | Bedeutung |
|-------|----------|
| `rate-limit` | Automatische Sperre wegen Limit-Überschreitung |
| `dry-run` | Im Dry-Run erkannt (nicht wirklich gesperrt) |
| `expired` | Automatisch entsperrt nach Ablauf der Sperrdauer |
| `expired-cron` | Entsperrt durch den Cron-Job (`unban-expired.sh`) |
| `manual` | Manuell entsperrt per `unban`-Befehl |
| `manual-flush` | Entsperrt durch `flush`-Befehl (alle Sperren aufgehoben) |

**History anzeigen:**
```bash
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh history       # letzte 50
sudo /opt/adguard-ratelimit/adguard-ratelimit.sh history 200   # letzte 200
```
