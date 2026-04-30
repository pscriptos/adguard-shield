# Docker-Installationen

AdGuard Shield läuft auf dem Host und liest weiterhin das Querylog von AdGuard Home über die API. Der Unterschied zwischen klassischer Installation und Docker-Setup betrifft nur die Stelle, an der die Firewall eine gesperrte Client-IP abfangen muss.

## Modus wählen

Die Wahl des Firewall-Modus hängt davon ab, wie AdGuard Home betrieben wird:

| Installation | Einstellung | Parent-Chain |
|---|---|---|
| AdGuard Home direkt auf dem Host | `FIREWALL_MODE="host"` | `INPUT` |
| Docker mit `network_mode: host` | `FIREWALL_MODE="docker-host"` | `INPUT` |
| Docker Bridge mit veröffentlichten Ports | `FIREWALL_MODE="docker-bridge"` | `DOCKER-USER` |
| Gemischtes Setup oder Migration | `FIREWALL_MODE="hybrid"` | `INPUT` + `DOCKER-USER` |

### Warum verschiedene Modi?

**Host und Docker Host Network:** DNS-Pakete landen direkt in der `INPUT`-Chain des Hosts. Die Firewall-Regeln werden dort eingehängt.

**Docker Bridge mit Port-Publishing:** Docker veröffentlicht Ports über NAT (DNAT). Die Pakete durchlaufen nach dem DNAT die `FORWARD`-Chain, nicht die `INPUT`-Chain. Docker stellt dafür die Chain `DOCKER-USER` bereit, die genau für eigene Admin-Regeln vor Dockers Container-Regeln vorgesehen ist.

**Hybrid:** Hängt Regeln in beide Chains ein. Nützlich bei Migrationen oder wenn unklar ist, welcher Weg die Pakete nehmen.

---

## Konfigurationsbeispiele

### Klassisch oder Docker Host Network

```bash
FIREWALL_MODE="host"
BLOCKED_PORTS="53 443 853"
```

`docker-host` verhält sich technisch identisch zu `host`:

```bash
FIREWALL_MODE="docker-host"
BLOCKED_PORTS="53 443 853"
```

### Docker Bridge mit Port-Publishing

```bash
FIREWALL_MODE="docker-bridge"
BLOCKED_PORTS="53 443 853"
```

### Unklarer Übergangszustand

```bash
FIREWALL_MODE="hybrid"
BLOCKED_PORTS="53 443 853"
```

---

## Regelstruktur nach Modus

### Host / Docker Host Network

```text
INPUT
  ├── tcp/53  → ADGUARD_SHIELD
  ├── udp/53  → ADGUARD_SHIELD
  ├── tcp/443 → ADGUARD_SHIELD
  ├── udp/443 → ADGUARD_SHIELD
  ├── tcp/853 → ADGUARD_SHIELD
  └── udp/853 → ADGUARD_SHIELD

ADGUARD_SHIELD
  ├── src in adguard_shield_v4 → DROP
  └── src in adguard_shield_v6 → DROP
```

### Docker Bridge

```text
DOCKER-USER
  ├── tcp/53  → ADGUARD_SHIELD
  ├── udp/53  → ADGUARD_SHIELD
  ├── tcp/443 → ADGUARD_SHIELD
  ├── udp/443 → ADGUARD_SHIELD
  ├── tcp/853 → ADGUARD_SHIELD
  └── udp/853 → ADGUARD_SHIELD

ADGUARD_SHIELD
  ├── src in adguard_shield_v4 → DROP
  └── src in adguard_shield_v6 → DROP
```

### Hybrid

Beide Strukturen gleichzeitig: `INPUT` und `DOCKER-USER` springen in `ADGUARD_SHIELD`.

---

## Wichtige Details

| Thema | Beschreibung |
|---|---|
| **DOCKER-USER Chain** | `docker-bridge` benötigt eine vorhandene IPv4-Chain `DOCKER-USER`. Wenn Docker nicht läuft oder iptables für Docker deaktiviert ist, meldet `firewall-create` einen Fehler. |
| **IPv6 in Docker** | IPv6 über Docker wird nur eingehängt, wenn Docker auch eine `ip6tables`-Chain `DOCKER-USER` angelegt hat. Fehlt sie, wird IPv4 trotzdem geschützt. |
| **Port-Mapping** | In `DOCKER-USER` wird nach Dockers DNAT gematcht. Bei ungewöhnlichen Port-Mappings sollten `BLOCKED_PORTS` die Container-Zielports enthalten (nicht die Host-Ports). |
| **Hybrid-Warnung** | `hybrid` kann mehr Verkehr treffen, weil sowohl Host-Ports als auch Docker-Forwarding geprüft werden. Nur bei Migrationen oder unklaren Setups verwenden. |
| **API-URL** | Die `ADGUARD_URL` muss vom Host aus erreichbar sein. Bei Docker Bridge ist das oft `http://127.0.0.1:<host-port>`. |

---

## Typisches Docker-Bridge-Setup

### docker-compose.yml (AdGuard Home)

```yaml
services:
  adguardhome:
    image: adguard/adguardhome
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "443:443/tcp"
      - "853:853/tcp"
      - "3000:3000/tcp"
    volumes:
      - ./data:/opt/adguardhome/work
      - ./conf:/opt/adguardhome/conf
    restart: unless-stopped
```

### adguard-shield.conf

```bash
ADGUARD_URL="http://127.0.0.1:3000"
ADGUARD_USER="admin"
ADGUARD_PASS="geheim"
FIREWALL_MODE="docker-bridge"
BLOCKED_PORTS="53 443 853"
```

---

## Nach einer Änderung prüfen

```bash
sudo systemctl restart adguard-shield
sudo /opt/adguard-shield/adguard-shield firewall-status
sudo /opt/adguard-shield/adguard-shield status
```

## Firewall neu aufbauen

Falls der Modus gewechselt wurde:

```bash
sudo /opt/adguard-shield/adguard-shield firewall-remove
sudo systemctl restart adguard-shield
sudo /opt/adguard-shield/adguard-shield firewall-status
```

Der Daemon erstellt die Firewall-Struktur beim Start automatisch neu und überträgt aktive Sperren aus SQLite.
