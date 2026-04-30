# Docker-Installationen

AdGuard Shield liest weiterhin das Querylog von AdGuard Home. Der Unterschied zwischen klassisch und Docker betrifft nur die Stelle, an der die Firewall eine gesperrte Client-IP abfangen muss.

## Modus wählen

| Installation | Einstellung |
|---|---|
| AdGuard Home direkt auf dem Host | `FIREWALL_MODE="host"` |
| Docker mit `network_mode: host` | `FIREWALL_MODE="docker-host"` |
| Docker Bridge mit veröffentlichten Ports | `FIREWALL_MODE="docker-bridge"` |
| gemischtes Setup oder Migration | `FIREWALL_MODE="hybrid"` |

`docker-host` verhält sich technisch wie `host`: Die DNS-Pakete landen in der Host-`INPUT`-Chain.

Bei Docker Bridge mit `ports:` oder `-p` landen veröffentlichte Ports nach Dockers NAT-Regeln im Forwarding-Pfad. Deshalb nutzt AdGuard Shield dort `DOCKER-USER`. Diese Chain ist genau für eigene Admin-Regeln vor Dockers Container-Regeln vorgesehen.

## Beispiele

Klassisch oder Docker Host Network:

```bash
FIREWALL_MODE="host"
BLOCKED_PORTS="53 443 853"
```

Docker Bridge mit Port-Publishing:

```bash
FIREWALL_MODE="docker-bridge"
BLOCKED_PORTS="53 443 853"
```

Unklarer Übergangszustand:

```bash
FIREWALL_MODE="hybrid"
```

## Wichtige Details

- `docker-bridge` benötigt eine vorhandene IPv4-Chain `DOCKER-USER`. Wenn Docker nicht läuft oder iptables für Docker deaktiviert ist, meldet `firewall-create` einen Fehler.
- IPv6 über Docker wird nur eingehängt, wenn Docker auch eine `ip6tables`-Chain `DOCKER-USER` angelegt hat. Fehlt sie, wird IPv4 trotzdem geschützt.
- In `DOCKER-USER` wird nach Dockers DNAT gematcht. Wenn du ungewöhnliche Port-Mappings nutzt, sollten `BLOCKED_PORTS` die Container-Zielports enthalten.
- `hybrid` ist praktisch für Migrationen, kann aber mehr Verkehr treffen, weil sowohl Host-Ports als auch Docker-Forwarding geprüft werden.

Nach einer Änderung:

```bash
sudo systemctl restart adguard-shield
sudo /opt/adguard-shield/adguard-shield firewall-status
```
