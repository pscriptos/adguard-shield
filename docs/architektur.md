# Architektur & Funktionsweise

## Überblick

```
┌─────────────────────┐
│   Client Anfragen   │
│  (DNS/DoH/DoT/DoQ)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐      ┌──────────────────────┐
│   AdGuard Home      │────▶ │   Query Log (API)   │
│   DNS Server        │      └──────────┬───────────┘
└─────────────────────┘                │
                                       ▼
                            ┌──────────────────────┐
                            │  adguard-shield.sh   │
                            │  (Monitor Script)    │
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

### Rate-Limit-Sperre

1. Client `192.168.1.50` fragt `microsoft.com` 45x in 60 Sekunden an
2. Monitor fragt die AdGuard Home API alle 10 Sekunden ab (`/control/querylog`)
3. Die Anfragen werden pro Client+Domain-Kombination gezählt
4. Monitor erkennt: 45 > 30 (Limit überschritten)
5. Prüfung: Ist der Client auf der Whitelist? → Nein
6. **Progressive Sperren:** Offense-Level wird geprüft/erhöht, Sperrdauer berechnet
7. iptables-Regel wird erstellt: `DROP` für `192.168.1.50` auf allen DNS-Ports
8. State-Datei wird angelegt: `/var/lib/adguard-shield/192.168.1.50.ban`
9. Offense-Datei wird aktualisiert: `/var/lib/adguard-shield/192.168.1.50.offenses`
10. Ban-History Eintrag wird in `/var/log/adguard-shield-bans.log` geschrieben
11. Log-Eintrag + optionale Webhook-Benachrichtigung
12. Nach Ablauf der (progressiven) Sperrdauer: automatische Entsperrung + History-Eintrag

### Subdomain-Flood-Sperre (Random Subdomain Attack)

1. Client `10.0.0.99` fragt `abc123.microsoft.com`, `xyz456.microsoft.com`, ... ab
2. Monitor extrahiert die **Basisdomain** (`microsoft.com`) aus jeder Anfrage
3. Pro Client wird gezählt, wie viele **eindeutige Subdomains** einer Basisdomain im Zeitfenster abgefragt wurden
4. Monitor erkennt: 63 eindeutige Subdomains > 50 (Schwellwert überschritten)
5. Prüfung: Ist der Client auf der Whitelist? → Nein
6. Sperre wird ausgeführt mit Domain `*.microsoft.com` und Grund `subdomain-flood`
7. Progressive Sperren greifen auch hier — Wiederholungstäter werden stufenweise länger gesperrt

> **Hinweis:** Die Subdomain-Flood-Erkennung hat ein eigenes Zeitfenster (`SUBDOMAIN_FLOOD_WINDOW`) und einen eigenen Schwellwert (`SUBDOMAIN_FLOOD_MAX_UNIQUE`), unabhängig von den Rate-Limit-Einstellungen.

## iptables Strategie

Das Tool erstellt eine eigene Chain `ADGUARD_SHIELD`:

```
INPUT Chain
  ├── ... (bestehende Regeln bleiben unberührt)
  ├── -p tcp --dport 53  → ADGUARD_SHIELD
  ├── -p udp --dport 53  → ADGUARD_SHIELD
  ├── -p tcp --dport 443 → ADGUARD_SHIELD
  ├── -p udp --dport 443 → ADGUARD_SHIELD
  ├── -p tcp --dport 853 → ADGUARD_SHIELD
  ├── -p udp --dport 853 → ADGUARD_SHIELD
  └── ...

ADGUARD_SHIELD Chain
  ├── -s 192.168.1.50 → DROP  (gesperrter Client)
  ├── -s 10.0.0.25    → DROP  (gesperrter Client)
  └── RETURN                   (alle anderen passieren)
```

**Vorteile der eigenen Chain:**
- Greift nicht in bestehende Firewall-Regeln ein
- Kann komplett geflusht werden ohne andere Regeln zu beeinflussen
- Einfaches Debugging per `iptables -L ADGUARD_SHIELD`

## State-Management

Jede aktive Sperre wird als Datei gespeichert:

```
/var/lib/adguard-shield/192.168.1.50.ban
```

Inhalt:
```
CLIENT_IP=192.168.1.50
DOMAIN=microsoft.com
COUNT=45
BAN_TIME=2026-03-03 14:30:00
BAN_UNTIL_EPOCH=1741012200
BAN_UNTIL=2026-03-03 15:30:00
BAN_DURATION=3600
OFFENSE_LEVEL=1
IS_PERMANENT=false
REASON=rate-limit
```

Zusätzlich wird für jede IP ein Offense-Tracker gespeichert:

```
/var/lib/adguard-shield/192.168.1.50.offenses
```

Inhalt:
```
CLIENT_IP=192.168.1.50
OFFENSE_LEVEL=2
LAST_OFFENSE_EPOCH=1741008600
LAST_OFFENSE=2026-03-03 14:30:00
FIRST_OFFENSE=2026-03-03 12:15:00
```

Das ermöglicht:
- Persistenz über Script-Neustarts hinweg
- Statusabfragen jederzeit möglich
- Automatisches Aufräumen per Cron-Job
- Progressive Sperrzeiten über mehrere Ban-Zyklen hinweg

## Dateistruktur nach Installation

```
/opt/adguard-shield/
├── adguard-shield.sh              # Haupt-Monitor-Script
├── adguard-shield.conf            # Konfiguration (chmod 600)
├── adguard-shield.conf.old        # Backup der Konfig nach Update
├── iptables-helper.sh             # iptables Verwaltung
├── external-blocklist-worker.sh   # Externer Blocklist-Worker
└── unban-expired.sh               # Cron-basiertes Entsperren

/etc/systemd/system/
└── adguard-shield.service         # systemd Service (Autostart aktiv)

/var/lib/adguard-shield/
├── *.ban                          # State-Dateien aktiver Sperren
├── *.offenses                     # Offense-Zähler (Progressive Sperren)
└── external-blocklist/            # Cache für externe Blocklisten

/var/log/
├── adguard-shield.log             # Laufzeit-Log
└── adguard-shield-bans.log        # Ban-History (alle Sperren/Entsperrungen)
```

## Installer-Architektur

Der Installer (`install.sh`) bietet ein interaktives Menü und folgende Funktionen:

| Befehl | Beschreibung |
|--------|--------------|
| `install` | Vollständige Neuinstallation (Abhängigkeiten, Dateien, Konfiguration, Service) |
| `update` | Update mit automatischer Konfigurations-Migration und Service-Neustart |
| `uninstall` | Deinstallation mit optionalem Behalten der Konfiguration |
| `status` | Installationsstatus, Version und Service-Status anzeigen |
| `--help` | Hilfe und Befehlsübersicht |

### Konfigurations-Migration beim Update

```
┌─────────────────────────┐     ┌─────────────────────────┐
│   Bestehende Konfig     │     │   Neue Konfig (Repo)    │
│   (Benutzer-Settings)   │     │  (mit neuen Parametern) │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │                               │
            ▼                               ▼
     ┌──────────────────────────────────────────┐
     │        Konfigurations-Migration          │
     │  1. Backup als .conf.old erstellen       │
     │  2. Alle Schlüssel vergleichen           │
     │  3. Neue Schlüssel zur Konfig ergänzen   │
     │  4. Bestehende Werte NICHT ändern        │
     └──────────────────────┬───────────────────┘
                            ▼
              ┌──────────────────────────┐
              │  Aktualisierte Konfig    │
              │ (alte Werte + neue Keys) │
              └──────────────────────────┘
```

## Ban-History

Jede Sperre und Entsperrung wird dauerhaft in der Ban-History protokolliert (`/var/log/adguard-shield-bans.log`). Das ermöglicht eine lückenlose Nachvollziehbarkeit, auch nachdem State-Dateien bereits gelöscht wurden.

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
| `subdomain-flood` | Sperre wegen zu vieler eindeutiger Subdomains einer Basisdomain |
| `dry-run` | Im Dry-Run erkannt (nicht wirklich gesperrt) |
| `dry-run (subdomain-flood)` | Subdomain-Flood im Dry-Run erkannt |
| `expired` | Automatisch entsperrt nach Ablauf der Sperrdauer |
| `expired-cron` | Entsperrt durch den Cron-Job (`unban-expired.sh`) |
| `manual` | Manuell entsperrt per `unban`-Befehl |
| `manual-flush` | Entsperrt durch `flush`-Befehl (alle Sperren aufgehoben) |

**History anzeigen:**
```bash
sudo /opt/adguard-shield/adguard-shield.sh history       # letzte 50
sudo /opt/adguard-shield/adguard-shield.sh history 200   # letzte 200
```
