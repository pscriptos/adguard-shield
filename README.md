<p align="center">
  <a href="https://techniverse.net">
    <img src="https://assets.techniverse.net/f1/git/graphics/repo-techniverse-logo.png" alt="Techniverse Community" height="70" />
  </a>
</p>

<h1 align="center">AdGuard Shield</h1>

<h4 align="center">
  Automatischer Schutz für AdGuard Home: erkennt auffällige DNS-Clients, sperrt sie per Firewall und hebt temporäre Sperren selbstständig wieder auf.
</h4>

<h6 align="center">
  <a href="https://www.cleveradmin.de">🏰 Website</a>
  ·
  <a href="https://techniverse.net">📰 Community</a>
  ·
  <a href="https://social.techniverse.net/@donnerwolke">🐘 Mastodon</a>
  ·
  <a href="https://matrix.to/#/#support:techniverse.net">💬 Support</a>
</h6>
<br><br>


## ✨ Was ist AdGuard Shield?

AdGuard Shield ist ein Go-basierter Sicherheitsdaemon, der das Query Log deiner AdGuard-Home-Instanz kontinuierlich überwacht. Er erkennt Clients, die eine Domain oder viele zufällige Subdomains in kurzer Zeit übermäßig oft anfragen, und sperrt sie automatisch über eine eigene `iptables`/`ip6tables`-Chain auf DNS-relevanten Ports.

Das Projekt schützt klassische DNS-Anfragen genauso wie DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ) und DNSCrypt, ohne deine bestehenden Firewall-Regeln anzufassen. AdGuard Shield arbeitet nicht direkt am Netzwerkverkehr, sondern wertet das Querylog von AdGuard Home über dessen API aus. Dadurch werden auch verschlüsselte DNS-Protokolle zuverlässig erfasst, solange sie in AdGuard Home sichtbar sind.

Das gesamte Projekt ist als einzelnes, statisch kompiliertes Go-Binary realisiert, das gleichzeitig als Daemon, CLI-Werkzeug, Installer und Report-Generator fungiert. Es ersetzt die frühere Shell-basierte Implementierung mit mehreren Skripten, Cron-Jobs und einem separaten Watchdog.

## 🚀 Highlights

| Bereich | Funktionen |
|---|---|
| **Erkennung** | Rate-Limit-Überwachung pro Client und Domain, Random-Subdomain-Flood-Erkennung (z.B. `abc123.example.com`), DNS-Flood-Watchlist für sofortigen Permanent-Ban |
| **Sperren** | Progressive Sperren für Wiederholungstäter (fail2ban-ähnlich), temporäre und permanente Sperren, automatische Freigabe abgelaufener Sperren |
| **Protokolle** | DNS, DoH, DoT, DoQ und DNSCrypt, IPv4 und IPv6 |
| **Firewall** | Eigene Chain mit `ipset`-Sets für performante Sperren, Firewall-Modi für Host, Docker Host Network, Docker Bridge und Hybrid |
| **Listen** | Externe Blocklisten und dynamische externe Whitelists mit automatischer DNS-Auflösung |
| **GeoIP** | Länderbasierte Filterung mit Blocklist- oder Allowlist-Modus über MaxMind GeoLite2 |
| **Meldungen** | AbuseIPDB-Reporting für permanent gesperrte IPs |
| **Benachrichtigungen** | Ntfy, Discord, Slack, Gotify oder Generic Webhook |
| **Reports** | E-Mail-Reports als HTML oder Text mit konfigurierbarem Versandintervall |
| **Betrieb** | systemd-Service mit Restart-Policy, Terminal-Live-Ansicht, Dry-Run-Modus, SQLite-State |

## ✅ Voraussetzungen

| Komponente | Beschreibung |
|---|---|
| **Betriebssystem** | Linux-Server (Debian, Ubuntu oder kompatible Distribution) |
| **AdGuard Home** | Laufende Instanz mit erreichbarer Web-API (Standard: `http://127.0.0.1:3000`) |
| **Root-Zugriff** | Erforderlich für Firewall-Steuerung und Service-Management |
| **Systempakete** | `iptables`, `ip6tables`, `ipset` und `systemd` |
| **Optional** | `msmtp` für E-Mail-Reports, MaxMind-Account für GeoIP-Daten |

Die benötigten Pakete werden vom Installer auf Ubuntu/Debian automatisch installiert, sofern `apt-get` verfügbar ist.

> **Hinweis:** Go wird auf dem Server nicht benötigt, wenn du ein fertiges Linux-Binary verwendest. Zum Erzeugen des Binarys brauchst du Go auf dem Build-Rechner oder alternativ Docker/CI/Release-Artefakte.

## ⚡ Schnellstart

### Variante A: Fertiges Release-Binary

```bash
# Release-Archiv herunterladen und entpacken
curl -fL -o adguard-shield-linux-amd64.tar.gz \
  https://git.techniverse.net/scriptos/adguard-shield/releases/download/v1.0.0/adguard-shield-linux-amd64.tar.gz
tar -xzf adguard-shield-linux-amd64.tar.gz
chmod +x ./adguard-shield
```

### Variante B: Lokal mit Go bauen

```bash
git clone https://git.techniverse.net/scriptos/adguard-shield.git
cd adguard-shield
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o adguard-shield ./cmd/adguard-shieldd
```

### Variante C: Ohne lokales Go per Docker bauen

```bash
git clone https://git.techniverse.net/scriptos/adguard-shield.git
cd adguard-shield
docker run --rm -v "$PWD":/src -w /src -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.22 \
  go build -o adguard-shield ./cmd/adguard-shieldd
```

### Installation und erster Start

```bash
# Binary auf dem Server installieren
sudo ./adguard-shield install
# Der Installer fragt am Ende, ob AdGuard Shield direkt gestartet werden soll.

# Konfiguration anpassen (mindestens API-Zugangsdaten und Whitelist)
sudo nano /opt/adguard-shield/adguard-shield.conf

# API-Verbindung testen
sudo /opt/adguard-shield/adguard-shield test

# Dry-Run: loggt Erkennungen, sperrt aber nicht
sudo /opt/adguard-shield/adguard-shield dry-run

# Service starten und prüfen
sudo systemctl start adguard-shield
sudo systemctl status adguard-shield
```

> Beim Installieren wird der systemd-Service für den Autostart registriert und am Ende nach dem direkten Start gefragt. Die Go-Version nutzt `Restart=on-failure`; einen separaten Watchdog-Timer wie in der alten Shell-Version gibt es nicht mehr.

> **Bestehende Shell-Installation?** Der Go-Installer bricht ab und meldet die gefundenen Script-Artefakte. Die alte Version muss zuerst deinstalliert werden (Konfiguration behalten). Details unter [docs/update.md](docs/update.md).

[![asciicast](https://asciinema.techniverse.net/a/77.svg)](https://asciinema.techniverse.net/a/77)

## 🔧 Befehlsübersicht

AdGuard Shield wird über ein einzelnes Binary bedient. Die Grundform lautet:

```bash
sudo /opt/adguard-shield/adguard-shield <befehl>
```

### Installation & Updates

| Befehl | Beschreibung |
|---|---|
| `install` | Binary, Konfiguration und systemd-Service installieren |
| `install --skip-deps` | Installation ohne automatische Paketprüfung |
| `install --no-enable` | Installation ohne systemd-Autostart |
| `install --config-source <pfad>` | Bestehende Konfiguration als Vorlage übernehmen |
| `update` | Binary, Service und Konfiguration aktualisieren |
| `install-status` | Installationsstatus anzeigen (Binary, Service, Version) |
| `uninstall` | Vollständige Deinstallation |
| `uninstall --keep-config` | Deinstallation mit Erhalt der Konfiguration |

### Daemon & Service

| Befehl | Beschreibung |
|---|---|
| `run` / `start` | Daemon im Vordergrund starten |
| `dry-run` | Daemon starten, der nur loggt aber nicht sperrt |
| `stop` | Laufenden Daemon über PID-Datei stoppen |
| `test` | API-Verbindung zu AdGuard Home testen |
| `version` | Installierte Version anzeigen |

### Status & Monitoring

| Befehl | Beschreibung |
|---|---|
| `status` | Aktive Sperren und Konfigurationsübersicht anzeigen |
| `live` / `watch` | Terminal-Live-Ansicht mit Queries, Top-Clients, Sperren und Logs |
| `live --interval 2` | Live-Ansicht mit benutzerdefiniertem Aktualisierungsintervall |
| `live --top 20` | Live-Ansicht mit mehr Top-Einträgen |
| `live --recent 25` | Mehr letzte Queries und Logs anzeigen |
| `live --logs debug` | DEBUG-Logs in der Live-Ansicht einblenden |
| `live --logs off` | Log-Bereich in der Live-Ansicht ausblenden |
| `live --once` | Einmaligen Snapshot ausgeben |
| `history [N]` | Ban-History anzeigen (Standard: 50 Einträge) |
| `logs` | Daemon-Logeinträge anzeigen |
| `logs --level warn --limit 100` | Gefilterte Logs anzeigen |
| `logs-follow` | Logs in Echtzeit verfolgen |

### Sperren & Freigaben

| Befehl | Beschreibung |
|---|---|
| `ban <IP>` | IP-Adresse manuell permanent sperren |
| `unban <IP>` | Sperre für eine IP-Adresse aufheben |
| `flush` | Alle aktiven Sperren aufheben |

### Progressive Sperren (Offense-Tracking)

| Befehl | Beschreibung |
|---|---|
| `offense-status` | Offense-Zähler und Statistik anzeigen |
| `offense-cleanup` | Abgelaufene Offense-Zähler entfernen |
| `reset-offenses` | Alle Offense-Zähler zurücksetzen |
| `reset-offenses <IP>` | Offense-Zähler für eine bestimmte IP zurücksetzen |

### Firewall

| Befehl | Beschreibung |
|---|---|
| `firewall-create` | Firewall-Chain und ipsets anlegen |
| `firewall-status` | Aktuelle Firewall-Regeln und ipsets anzeigen |
| `firewall-flush` | ipsets leeren (Sperren entfernen, Struktur bleibt) |
| `firewall-remove` | Chain, Regeln und ipsets vollständig entfernen |
| `firewall-save` | Aktuelle iptables-Regeln in Datei sichern |
| `firewall-restore` | Gesicherte Regeln wiederherstellen |

### GeoIP

| Befehl | Beschreibung |
|---|---|
| `geoip-status` | GeoIP-Konfiguration und Status anzeigen |
| `geoip-lookup <IP>` | Land einer IP-Adresse nachschlagen |
| `geoip-sync` | Aktuelle Querylog-Clients einmalig gegen GeoIP prüfen |
| `geoip-flush` | Alle GeoIP-Sperren aufheben |
| `geoip-flush-cache` | GeoIP-Cache leeren |

### Externe Listen

| Befehl | Beschreibung |
|---|---|
| `blocklist-status` | Status der externen Blocklist anzeigen |
| `blocklist-sync` | Externe Blocklist sofort synchronisieren |
| `blocklist-flush` | Alle Sperren aus externer Blocklist aufheben |
| `whitelist-status` | Status der externen Whitelist anzeigen |
| `whitelist-sync` | Externe Whitelist sofort synchronisieren |
| `whitelist-flush` | Aufgelöste externe Whitelist-Einträge entfernen |

### E-Mail-Reports

| Befehl | Beschreibung |
|---|---|
| `report-status` | Report-Konfiguration und Cron-Status anzeigen |
| `report-generate html <datei>` | HTML-Report in Datei schreiben |
| `report-generate txt` | Text-Report auf stdout ausgeben |
| `report-test` | Testmail senden |
| `report-send` | Aktuellen Report erzeugen und per E-Mail versenden |
| `report-install` | Cron-Job für automatischen Versand installieren |
| `report-remove` | Cron-Job entfernen |

Die vollständige Befehlsreferenz mit Beispielen und typischen Betriebsabläufen steht in [docs/befehle.md](docs/befehle.md).

## ⚙️ Konfiguration

Die zentrale Konfigurationsdatei liegt nach der Installation hier:

```text
/opt/adguard-shield/adguard-shield.conf
```

Die Datei verwendet ein einfaches Shell-ähnliches Key-Value-Format. Nach Änderungen muss der Service neu gestartet werden:

```bash
sudo systemctl restart adguard-shield
```

### Wichtigste Parameter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `ADGUARD_URL` | `https://dns1.domain.com` | URL der AdGuard-Home-API |
| `ADGUARD_USER` | `admin` | API-Benutzername |
| `ADGUARD_PASS` | `changeme` | API-Passwort |
| `RATE_LIMIT_MAX_REQUESTS` | `30` | Maximale Anfragen pro Client/Domain im Zeitfenster |
| `RATE_LIMIT_WINDOW` | `60` | Zeitfenster in Sekunden |
| `CHECK_INTERVAL` | `10` | Abstand zwischen Querylog-Abfragen in Sekunden |
| `BAN_DURATION` | `3600` | Basis-Sperrdauer in Sekunden (1 Stunde) |
| `FIREWALL_MODE` | `host` | `host`, `docker-host`, `docker-bridge` oder `hybrid` |
| `WHITELIST` | `127.0.0.1,::1` | IPs, die nie gesperrt werden (kommagetrennt) |
| `DRY_RUN` | `false` | Testmodus: nur loggen, nicht sperren |

### Optionale Module

| Modul | Aktivierung | Beschreibung |
|---|---|---|
| Subdomain-Flood | `SUBDOMAIN_FLOOD_ENABLED=true` | Erkennung von Random-Subdomain-Angriffen |
| DNS-Flood-Watchlist | `DNS_FLOOD_WATCHLIST_ENABLED=true` | Sofortiger Permanent-Ban für definierte Domains |
| Progressive Sperren | `PROGRESSIVE_BAN_ENABLED=true` | Stufenweise längere Sperren für Wiederholungstäter |
| GeoIP-Länderfilter | `GEOIP_ENABLED=true` | Ländersperre per MaxMind-Datenbank |
| Externe Blocklist | `EXTERNAL_BLOCKLIST_ENABLED=true` | IP-Sperren aus externen Listen |
| Externe Whitelist | `EXTERNAL_WHITELIST_ENABLED=true` | Dynamische Whitelist mit DNS-Auflösung |
| Benachrichtigungen | `NOTIFY_ENABLED=true` | Push-Benachrichtigungen bei Sperrereignissen |
| E-Mail-Reports | `REPORT_ENABLED=true` | Periodische Statistik-Reports per E-Mail |
| AbuseIPDB | `ABUSEIPDB_ENABLED=true` | Automatische Meldung permanenter Sperren |

Bei Updates migriert der Installer die bestehende Konfiguration automatisch: vorhandene Werte bleiben erhalten, neue Parameter werden ergänzt und die alte Datei wird als `adguard-shield.conf.old` gesichert.

Die vollständige Parameterbeschreibung mit Beispielkonfigurationen findest du in [docs/konfiguration.md](docs/konfiguration.md).

## 🧩 Wie AdGuard Shield arbeitet

```text
DNS-Clients
  │
  │ DNS, DoH, DoT, DoQ, DNSCrypt
  ▼
AdGuard Home
  │
  │ /control/querylog API
  ▼
AdGuard Shield Daemon (pollt alle CHECK_INTERVAL Sekunden)
  │
  ├── Rate-Limit-Prüfung (Client + Domain)
  ├── Subdomain-Flood-Erkennung (Client + Basisdomain)
  ├── DNS-Flood-Watchlist-Abgleich
  ├── Whitelist-Prüfung (statisch + extern)
  ├── GeoIP-Prüfung (falls aktiviert)
  ├── Progressive Ban-Berechnung
  └── History-Protokollierung
  │
  ▼
SQLite-Datenbank (active_bans, ban_history, offense_tracking)
  │
  ▼
ipset + iptables/ip6tables
  │
  ▼
DNS-relevante Ports (53, 443, 853) werden für gesperrte Clients blockiert
```

1. AdGuard Shield liest regelmäßig das AdGuard-Home-Query-Log über die API.
2. Anfragen werden pro Client, Domain und Protokoll ausgewertet.
3. Überschreitet ein Client die konfigurierten Limits, wird er gegen Whitelist, GeoIP und Sonderregeln geprüft.
4. Die Sperre landet in der eigenen Firewall-Chain `ADGUARD_SHIELD` und wird in SQLite gespeichert.
5. Ban-History, Logs und optionale Benachrichtigungen dokumentieren das Ereignis.
6. Temporäre Sperren werden automatisch entfernt, permanente Sperren bleiben bis zur manuellen Freigabe aktiv.
7. Bei einem Neustart werden alle aktiven Sperren aus SQLite wieder in die Firewall übertragen.

## 🧭 Dokumentation

| Thema | Link | Beschreibung |
|---|---|---|
| Architektur & Funktionsweise | [docs/architektur.md](docs/architektur.md) | Aufbau, Datenfluss, Firewall-Modell, SQLite-Schema, Hintergrundjobs und Sperrlogik |
| Befehle & Nutzung | [docs/befehle.md](docs/befehle.md) | Vollständige CLI-Referenz mit Beispielen und typischen Betriebsabläufen |
| Konfiguration | [docs/konfiguration.md](docs/konfiguration.md) | Alle Parameter aus `adguard-shield.conf` mit Beispielen und Empfehlungen |
| Docker-Installationen | [docs/docker.md](docs/docker.md) | Firewall-Modi für klassische Installation, Docker Host Network und Docker Bridge |
| Benachrichtigungen | [docs/benachrichtigungen.md](docs/benachrichtigungen.md) | Einrichtung von Ntfy, Discord, Slack, Gotify und Generic Webhooks |
| E-Mail Report | [docs/report.md](docs/report.md) | Report-Inhalte, Mailversand, Cron-Job und manuelle Tests |
| Updates | [docs/update.md](docs/update.md) | Update-Ablauf, Konfigurationsmigration und Migration von der Shell-Version |
| Tipps & Troubleshooting | [docs/tipps-und-troubleshooting.md](docs/tipps-und-troubleshooting.md) | Diagnosewege für API, Firewall, GeoIP, Reports, Listen und falsche Sperren |

## 📜 Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](./LICENSE).

<br><br>
<p align="center">
  <img src="https://assets.techniverse.net/f1/git/graphics/gray0-catonline.svg" alt="">
</p>

<p align="center">
  <sub>
    Patrick Asmus · Techniverse Network · <a href="./LICENSE">Lizenz</a>
  </sub>
</p>
