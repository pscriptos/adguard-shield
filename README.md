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

AdGuard Shield überwacht das Query Log deiner AdGuard-Home-Instanz und erkennt Clients, die eine Domain oder viele zufällige Subdomains in kurzer Zeit übermäßig oft anfragen. Auffällige Clients werden über eine eigene `iptables`/`ip6tables`-Chain auf DNS-relevanten Ports blockiert.

Das schützt klassische DNS-Anfragen genauso wie DoH, DoT und DoQ, ohne deine bestehenden Firewall-Regeln unnötig anzufassen.

## 🚀 Highlights

- Automatische Sperren bei Rate-Limit-Verstößen
- Erkennung von Random-Subdomain-Floods, z.B. `abc123.example.com`
- DNS-Flood-Watchlist: sofortiger permanenter Ban + AbuseIPDB-Meldung für definierte Domains
- Progressive Sperren für Wiederholungstäter, ähnlich wie bei fail2ban
- Unterstützung für DNS, DoH, DoT, DoQ und DNSCrypt
- IPv4 und IPv6
- Go-Daemon mit einem zentralen Querylog-Poller statt mehrerer Shell-Worker
- Eigene Firewall-Chain mit `ipset`-Sets für schnelle Sperren bei vielen IPs
- Firewall-Modi für klassische Installation, Docker Host Network und Docker mit veröffentlichten Ports
- Externe Blocklisten und dynamische externe Whitelists
- GeoIP-Länderfilter mit Blocklist- oder Allowlist-Modus
- AbuseIPDB-Reporting für permanent gesperrte IPs
- Benachrichtigungen über Ntfy, Discord, Slack, Gotify oder Generic Webhook
- E-Mail-Reports als HTML oder Text direkt aus dem Go-Binary
- systemd-Service mit Restart-Policy, ohne Shell-Worker

## ✅ Voraussetzungen

- Linux-Server mit AdGuard Home
- Root-Zugriff per `sudo`
- Erreichbare AdGuard Home Web-API, standardmäßig `http://127.0.0.1:3000`
- `iptables`, `ip6tables`, `ipset` und `systemd`

Die benötigten Pakete werden vom Go-Installer auf Ubuntu/Debian automatisch installiert.

Wichtig: Go wird auf dem Server nicht benötigt, wenn du ein fertiges Linux-Binary installierst. Zum Erzeugen dieses Binarys brauchst du Go aber auf dem Rechner, auf dem du baust, oder alternativ Docker/CI/Release-Artefakte.

## ⚡ Schnellstart

```bash
git clone https://git.techniverse.net/scriptos/adguard-shield.git /tmp/adguard-shield
cd /tmp/adguard-shield

# Variante A: fertiges Release-Binary laden
curl -fL -o adguard-shield-linux-amd64.tar.gz \
  https://git.techniverse.net/scriptos/adguard-shield/releases/download/v1.0.0/adguard-shield-linux-amd64.tar.gz
tar -xzf adguard-shield-linux-amd64.tar.gz

# Variante B: Linux-Binary lokal bauen, wenn Go installiert ist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o adguard-shield ./cmd/adguard-shieldd

# Variante C: ohne lokale Go-Installation per Docker bauen
docker run --rm -v "$PWD":/src -w /src -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.22 \
  go build -o adguard-shield ./cmd/adguard-shieldd

# Fertiges Binary auf dem Server installieren
chmod +x ./adguard-shield
sudo ./adguard-shield install
# Der Installer fragt am Ende, ob AdGuard Shield direkt gestartet werden soll.

# Bestehende Shell-Installation?
# Der Go-Installer bricht ab und meldet die gefundenen Script-Artefakte.
# Die alte Version zuerst deinstallieren und die adguard-shield.conf behalten.

# Vor dem produktiven Start testen: loggt nur, sperrt nichts
sudo /opt/adguard-shield/adguard-shield dry-run

# Service starten, falls du die Nachfrage verneint hast, und prüfen
sudo systemctl start adguard-shield
sudo systemctl status adguard-shield
```

> Beim Installieren wird der systemd-Service für den Autostart registriert und am Ende nach dem direkten Start gefragt. Die Go-Version nutzt `Restart=on-failure`; einen separaten Watchdog-Timer wie in der alten Shell-Version gibt es nicht mehr.

[![asciicast](https://asciinema.techniverse.net/a/77.svg)](https://asciinema.techniverse.net/a/77)

## 🔧 Wichtigste Befehle

### Installation & Updates

```bash
sudo ./adguard-shield install        # Go-Binary installieren
sudo ./adguard-shield update         # Binary, Service und Config-Migration aktualisieren
sudo ./adguard-shield install-status # Installationsstatus prüfen
sudo /opt/adguard-shield/adguard-shield uninstall --keep-config
```

### Betrieb & Diagnose

```bash
sudo systemctl status adguard-shield
sudo systemctl restart adguard-shield
sudo journalctl -u adguard-shield -f

sudo /opt/adguard-shield/adguard-shield status
sudo /opt/adguard-shield/adguard-shield live
sudo /opt/adguard-shield/adguard-shield history
sudo /opt/adguard-shield/adguard-shield logs --level warn
sudo /opt/adguard-shield/adguard-shield test
sudo /opt/adguard-shield/adguard-shield unban 192.0.2.10
sudo /opt/adguard-shield/adguard-shield flush
```

`live` zeigt eine Terminal-Ansicht mit aktuellen Queries, Top-Client/Domain-Zählungen, Subdomain-Flood-Kandidaten, aktiven Sperren und Systemereignissen. Query-Inhalte werden dabei nicht dauerhaft ins Systemlog geschrieben; `logs` und `logs-follow` sind für Daemon-, Worker- und Fehlerereignisse gedacht.

### Optionale Module

```bash
sudo /opt/adguard-shield/adguard-shield blocklist-status
sudo /opt/adguard-shield/adguard-shield whitelist-status
sudo /opt/adguard-shield/adguard-shield geoip-status

sudo /opt/adguard-shield/adguard-shield report-status
sudo /opt/adguard-shield/adguard-shield report-generate html /tmp/adguard-shield-report.html
sudo /opt/adguard-shield/adguard-shield report-send
```

Die vollständige Befehlsreferenz steht in [docs/befehle.md](docs/befehle.md).

## ⚙️ Konfiguration

Die zentrale Konfiguration liegt nach der Installation hier:

```text
/opt/adguard-shield/adguard-shield.conf
```

Wichtige Startpunkte:

- `ADGUARD_URL`, `ADGUARD_USER`, `ADGUARD_PASS` für die AdGuard-Home-API
- `RATE_LIMIT_MAX_REQUESTS`, `RATE_LIMIT_WINDOW` und `CHECK_INTERVAL` für die Erkennung
- `BAN_DURATION` und `PROGRESSIVE_BAN_*` für temporäre und progressive Sperren
- `FIREWALL_MODE` für klassische Installationen, Docker Host Network oder Docker Bridge
- `WHITELIST` für vertrauenswürdige Clients wie Router, Management-IPs oder lokale Resolver
- `DNS_FLOOD_WATCHLIST_*` für sofortigen Permanent-Ban bei bekannten Flood-Domains
- `NOTIFY_*`, `REPORT_*`, `GEOIP_*`, `EXTERNAL_BLOCKLIST_*` und `EXTERNAL_WHITELIST_*` für optionale Funktionen

Bei Updates migriert der Installer die bestehende Konfiguration automatisch: vorhandene Werte bleiben erhalten, neue Parameter werden ergänzt und die alte Datei wird als `adguard-shield.conf.old` gesichert.

Mehr Details findest du in [docs/konfiguration.md](docs/konfiguration.md).

## 🧭 Dokumentation

| Thema | Link |
|---|---|
| Architektur & Funktionsweise | [docs/architektur.md](docs/architektur.md) |
| Befehle & Nutzung | [docs/befehle.md](docs/befehle.md) |
| Konfiguration | [docs/konfiguration.md](docs/konfiguration.md) |
| Docker-Installationen | [docs/docker.md](docs/docker.md) |
| Benachrichtigungen | [docs/benachrichtigungen.md](docs/benachrichtigungen.md) |
| E-Mail Report | [docs/report.md](docs/report.md) |
| Updates | [docs/update.md](docs/update.md) |
| Tipps & Troubleshooting | [docs/tipps-und-troubleshooting.md](docs/tipps-und-troubleshooting.md) |

## 🧩 Wie es arbeitet

1. AdGuard Shield liest regelmäßig das AdGuard-Home-Query-Log über die API.
2. Anfragen werden pro Client, Domain und Protokoll ausgewertet.
3. Überschreitet ein Client die konfigurierten Limits, wird er gegen Whitelist und Sonderregeln geprüft.
4. Die Sperre landet in der eigenen Firewall-Chain `ADGUARD_SHIELD`.
5. Ban-History, Logs und optionale Benachrichtigungen dokumentieren das Ereignis.
6. Temporäre Sperren werden automatisch entfernt, permanente Sperren bleiben bis zur manuellen Freigabe aktiv.

<br><br>
<p align="center">
  <img src="https://assets.techniverse.net/f1/git/graphics/gray0-catonline.svg" alt="">
</p>

<p align="center">
  <sub>
    Patrick Asmus · Techniverse Network · <a href="./LICENSE">Lizenz</a>
  </sub>
</p>
