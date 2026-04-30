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

### DNS-Flood-Watchlist-Sperre

1. Client `10.0.0.42` fragt `microsoft.com` 35x in 60 Sekunden an
2. Monitor erkennt: 35 > 30 (Limit überschritten)
3. Domain `microsoft.com` steht auf der DNS-Flood-Watchlist → **sofortige permanente Sperre**
4. Progressive-Ban-Stufe wird ignoriert — kein stufenweises Hochstufen
5. IP wird an AbuseIPDB gemeldet (falls aktiviert)
6. Permanente Sperre bleibt bis zur manuellen Freigabe aktiv

> **Hinweis:** Die Watchlist greift sowohl bei normalen Rate-Limit-Verstößen als auch bei Subdomain-Flood-Erkennungen. Subdomains werden automatisch erkannt: `foo.microsoft.com` matcht den Watchlist-Eintrag `microsoft.com`.

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

## State-Management (SQLite)

Alle Laufzeitdaten werden in einer zentralen SQLite-Datenbank gespeichert:

```
/var/lib/adguard-shield/adguard-shield.db
```

Die Datenbank enthält folgende Tabellen:

| Tabelle | Beschreibung |
|---------|--------------|
| `active_bans` | Aktive Sperren (IP, Domain, Sperrdauer, Offense-Level, Grund, Quelle, GeoIP) |
| `offense_tracking` | Offense-Zähler für progressive Sperren (Level, letztes/erstes Vergehen) |
| `ban_history` | Vollständige Ban-History (alle Sperren und Entsperrungen) |
| `whitelist_cache` | Cache der aufgelösten externen Whitelist-IPs |
| `schema_version` | Datenbank-Schema-Version für zukünftige Migrationen |

**Vorteile gegenüber Flat-Files:**
- Schnellere Abfragen, besonders bei vielen aktiven Sperren
- Atomare Transaktionen — kein Datenverlust bei Stromausfall
- WAL-Modus für parallelen Lese-/Schreibzugriff
- Indexierte Suche nach IP, Zeitstempel, Quelle und Aktion
- Kompakte Speicherung statt tausender Einzeldateien

Die zentrale Datenbankbibliothek (`db.sh`) wird von allen Scripts per `source db.sh` eingebunden und stellt typisierte Funktionen für alle Tabellen bereit (z.B. `db_ban_insert`, `db_offense_get_level`, `db_history_add`).

### Migration von Flat-Files

Beim Update auf die SQLite-Version werden bestehende Flat-File-Daten (`.ban`, `.offenses`, Ban-History-Log, Whitelist-Cache) automatisch in die Datenbank migriert. Die alten Dateien werden als Backup nach `/var/lib/adguard-shield/.backup_pre_sqlite/` verschoben. Die Migration läuft einmalig beim Update und zeigt den Fortschritt im Terminal an.

## Dateistruktur nach Installation

```
/opt/adguard-shield/
├── adguard-shield.sh              # Haupt-Monitor-Script
├── adguard-shield.conf            # Konfiguration (chmod 600)
├── adguard-shield.conf.old        # Backup der Konfig nach Update
├── adguard-shield-watchdog.sh     # Watchdog Health-Check-Script
├── iptables-helper.sh             # iptables Verwaltung
├── external-blocklist-worker.sh   # Externer Blocklist-Worker
├── external-whitelist-worker.sh   # Externer Whitelist-Worker (DNS-Auflösung)
├── geoip-worker.sh                # GeoIP-Länderfilter-Worker
├── offense-cleanup-worker.sh      # Aufräumen abgelaufener Offense-Zähler (nice 19, idle I/O)
├── db.sh                          # SQLite Datenbank-Bibliothek (wird von allen Scripts eingebunden)
├── unban-expired.sh               # Cron-basiertes Entsperren
└── geoip/                         # Auto-Download MaxMind GeoLite2 DB (optional)

/etc/systemd/system/
├── adguard-shield.service         # systemd Service (Autostart aktiv)
├── adguard-shield-watchdog.service # systemd Watchdog-Unit (oneshot)
└── adguard-shield-watchdog.timer  # systemd Timer (alle 5 Min.)

/var/lib/adguard-shield/
├── adguard-shield.db              # SQLite-Datenbank (Bans, Offenses, History, Whitelist-Cache)
├── .migration_v1_complete         # Marker: Flat-File-Migration abgeschlossen
├── .backup_pre_sqlite/            # Backup der alten Flat-Files nach Migration
├── external-blocklist/            # Cache für externe Blocklisten
├── external-whitelist/            # Cache für externe Whitelisten
└── geoip-cache/                   # Cache für GeoIP-Lookups (24h)

/var/log/
├── adguard-shield.log             # Laufzeit-Log
└── adguard-shield-bans.log        # Ban-History (Legacy, wird nach Migration nicht mehr geschrieben)
```

## Installer-Architektur

Der Installer (`install.sh`) bietet ein interaktives Menü und folgende Funktionen:

| Befehl | Beschreibung |
|--------|--------------|
| `install` | Vollständige Neuinstallation (Abhängigkeiten, Dateien, Konfiguration, Service, Watchdog) |
| `update` | Update mit automatischer Konfigurations-Migration, Datenbank-Migration, Watchdog-Aktivierung und Service-Neustart |
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

Jede Sperre und Entsperrung wird dauerhaft in der SQLite-Datenbank protokolliert (Tabelle `ban_history`). Das ermöglicht eine lückenlose Nachvollziehbarkeit mit indexierter Suche nach IP, Zeitstempel und Aktion.

**Gespeicherte Felder pro Eintrag:**
| Feld | Beschreibung |
|------|--------------|
| `timestamp_epoch` | Unix-Zeitstempel |
| `timestamp_text` | Lesbarer Zeitstempel |
| `action` | `BAN` oder `UNBAN` |
| `client_ip` | Betroffene IP-Adresse |
| `domain` | Angefragte Domain |
| `count` | Anzahl der Anfragen |
| `duration` | Sperrdauer |
| `protocol` | Verwendetes DNS-Protokoll |
| `reason` | Sperrgrund |

**Mögliche Gründe (GRUND-Spalte):**
| Grund | Bedeutung |
|-------|----------|
| `rate-limit` | Automatische Sperre wegen Limit-Überschreitung |
| `subdomain-flood` | Sperre wegen zu vieler eindeutiger Subdomains einer Basisdomain |
| `dns-flood-watchlist` | Sofortige permanente Sperre + AbuseIPDB-Meldung (Domain auf der Watchlist) |
| `dry-run` | Im Dry-Run erkannt (nicht wirklich gesperrt) |
| `dry-run (subdomain-flood)` | Subdomain-Flood im Dry-Run erkannt |
| `dry-run (dns-flood-watchlist)` | Watchlist-Treffer im Dry-Run erkannt |
| `expired` | Automatisch entsperrt nach Ablauf der Sperrdauer |
| `expired-cron` | Entsperrt durch den Cron-Job (`unban-expired.sh`) |
| `manual` | Manuell entsperrt per `unban`-Befehl |
| `manual-flush` | Entsperrt durch `flush`-Befehl (alle Sperren aufgehoben) |

**History anzeigen:**
```bash
sudo /opt/adguard-shield/adguard-shield.sh history       # letzte 50
sudo /opt/adguard-shield/adguard-shield.sh history 200   # letzte 200
```
