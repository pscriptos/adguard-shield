# Web-Statusseite

AdGuard Shield kann optional eine kleine Statusseite im Browser anzeigen. Sie zeigt live, was der Daemon gerade tut, und aktualisiert sich alle 5 Sekunden selbst.

Die Seite ist **schreibgeschützt**: Es gibt keine Knöpfe, Formulare oder API-Aufrufe, die etwas verändern. Sperren aufheben, Listen synchronisieren usw. geht weiterhin nur über die [CLI](befehle.md).

## Inhalt

| Bereich | Inhalt |
|---|---|
| Kopf | Version, Hostname, Laufzeit des Daemons, Dry-Run-Hinweis, Umschalter Hell/Dunkel |
| Kacheln | Aktive Sperren gesamt, davon permanent, Sperren heute und in den letzten 7 Tagen, Offense-Zähler, Whitelist-Einträge (statisch + extern, doppelte Einträge einfach gezählt), letzter erfolgreicher Querylog-Poll mit Anzahl Einträgen bzw. letzter Poll-Fehler |
| Module | Rate-Limit, Subdomain-Flood, DNS-Flood-Watchlist, GeoIP (Modus, Länder), externe Blocklist/Whitelist (Anzahl URLs, Intervall, letzter Lauf und Ergebnis), Progressive Ban, AbuseIPDB, Benachrichtigungen (Typ), E-Mail-Report, Firewall, Dry-Run |
| Live | Top Client/Domain im Rate-Limit-Fenster (Anzahl/Limit mit Balken), Subdomain-Flood-Kandidaten, letzte Queries |
| Sperren | Die 15 neuesten aktiven Sperren (IP, Quelle, Grund, Domain, Land, Ablauf) und die 15 letzten Ereignisse aus der History |
| Systemereignisse | Die letzten 15 Logzeilen ab Level INFO |

Die Live-Daten stammen aus dem Analysefenster, das der Daemon beim normalen Polling ohnehin im Speicher hält. Die Statusseite löst **keine zusätzlichen Abfragen** an die AdGuard-Home-API aus. Der zusammengestellte Status (auch ein Fehler) wird 2 Sekunden zwischengespeichert, mehrere offene Tabs belasten die Datenbank also nicht zusätzlich. Auch bei sehr vielen Sperren werden nie alle Sperren geladen, sondern nur Zählwerte und die neuesten 15 Einträge.

Geheimnisse werden nie angezeigt: Passwörter, API-Keys, Tokens, der MaxMind-License-Key, Webhook-URLs, das ntfy-Topic und die URLs der externen Listen tauchen in der Statusseite nicht auf. Externe Listen werden im Log nur als `Quelle #<Nr> (<schema>://<host>)` genannt, ohne Pfad, Query oder Zugangsdaten. Fehlermeldungen und Logzeilen werden vor der Ausgabe zusätzlich geschwärzt (`***`), falls sie einen dieser Werte enthalten (bei URLs auch Query-String, Zugangsdaten und kodierte Schreibweisen).

Hell/Dunkel folgt standardmäßig der Systemeinstellung (`prefers-color-scheme`). Die Auswahl über den Umschalter wird im Browser gespeichert (`localStorage`).

## Konfiguration

Der eingebaute Webserver spricht nur HTTP und lauscht auf allen Schnittstellen. Einen eigenen Webserver braucht es dafür nicht. Soll die Seite per HTTPS oder unter einem Hostnamen erreichbar sein, übernimmt das ein Reverse-Proxy (nginx, Caddy, Traefik, ...), wie bei den meisten selbst gehosteten Anwendungen.

| Parameter | Standard | Beschreibung |
|---|---|---|
| `WEB_ENABLED` | `false` | Statusseite aktivieren |
| `WEB_PORT` | `8080` | HTTP-Port der Statusseite (1–65535) |
| `WEB_BASE_PATH` | `/` | Basispfad, z.B. `/adguard-shield/`, wenn der Reverse-Proxy die Seite in einem Unterordner ausliefert. Wird automatisch auf führenden und abschließenden `/` ergänzt |
| `WEB_USER` | `admin` | Benutzername für HTTP Basic Auth |
| `WEB_PASSWORD` | *(leer)* | Passwort für HTTP Basic Auth. **Leer = Statusseite ohne Anmeldung** |

Beispiel:

```bash
WEB_ENABLED=true
WEB_PORT=8080
WEB_PASSWORD='ein-langes-zufaelliges-passwort'
```

Nach Änderungen:

```bash
sudo systemctl restart adguard-shield
sudo adguard-shield logs --limit 20
```

Im Log steht beim Start z.B.:

```text
[INFO] [ADGUARD-SHIELDD] Web-Statusseite gestartet: http://[::]:8080/ (Anmeldung: Basic Auth)
```

Die Seite ist dann unter `http://<server-ip>:8080/` erreichbar.

### Prüfungen und Warnungen

| Situation | Verhalten |
|---|---|
| `WEB_PORT` ist keine Zahl von 1–65535 | Warnung, Standard `8080` wird verwendet |
| `WEB_BASE_PATH` enthält andere Zeichen als Buchstaben, Ziffern, `- _ . ~ /` oder `.`/`..`-Segmente | Warnung, Standard `/` wird verwendet |
| Port belegt | Fehler im Log, die Statusseite läuft nicht, der Daemon läuft normal weiter |
| `WEB_PASSWORD` leer | Warnung: `Web-Statusseite ohne Anmeldung auf … erreichbar – WEB_PASSWORD setzen oder den Port per Firewall auf den Reverse-Proxy beschränken` |
| `WEB_USER` enthält `:` | Warnung, eine Anmeldung ist so nicht möglich (Basic Auth erlaubt keinen Doppelpunkt im Benutzernamen) |
| `WEB_LISTEN`, `WEB_TLS_CERT` oder `WEB_TLS_KEY` gesetzt (bis v1.2.0) | Hinweis, der Wert wird ignoriert (siehe [Update von v1.2.0 auf v1.2.1](update.md#update-von-v120-auf-v121)) |

## Hinter einem Reverse-Proxy

Der Reverse-Proxy terminiert HTTPS und reicht die Anfragen per HTTP an `127.0.0.1:<WEB_PORT>` weiter. Damit Port 8080 nicht direkt aus dem Internet erreichbar ist, den Port in der Firewall sperren, wenn der Proxy auf demselben Server läuft (bzw. nur für den Proxy freigeben, wenn er woanders läuft).

### Eigene Subdomain

Beispiel `https://shield.example.com/`, `WEB_BASE_PATH` bleibt `/`.

nginx:

```nginx
server {
    listen 443 ssl;
    server_name shield.example.com;
    # ssl_certificate / ssl_certificate_key wie gewohnt

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

Caddy (holt das Zertifikat automatisch):

```text
shield.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Unterordner einer bestehenden Domain

Beispiel `https://dns1.example.com/adguard-shield/`, während AdGuard Home unter `https://dns1.example.com/` läuft. Der Proxy reicht den Pfad **unverändert** (mit Präfix) weiter:

```bash
WEB_PORT=8080
WEB_BASE_PATH="/adguard-shield/"
```

nginx:

```nginx
location /adguard-shield/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

Caddy:

```text
handle /adguard-shield/* {
    reverse_proxy 127.0.0.1:8080
}
```

Dafür muss der Reverse-Proxy auch vor AdGuard Home stehen: AdGuard Home belegt sonst selbst Port 443 und kann keine Pfade an andere Dienste weiterreichen. AdGuard Home läuft dann auf einem internen Port (z.B. `127.0.0.1:3000`), und der Proxy leitet `/` dorthin weiter.

### Hinweise

- Von außen nur über HTTPS zugreifen, sonst laufen die Basic-Auth-Zugangsdaten im Klartext über das Netz.
- Die Sperre nach zu vielen Fehlversuchen gilt pro Client-IP. Hinter einem Proxy sieht AdGuard Shield nur die IP des Proxys; `X-Forwarded-For` wird bewusst nicht ausgewertet, weil der Header fälschbar ist. Zehn Fehlversuche irgendeines Nutzers sperren dann für bis zu eine Minute **alle** Anfragen über den Proxy – auch mit gültigen Zugangsdaten, damit das Passwort während der Sperre nicht weiter geraten werden kann.
- Alternativ kann die Anmeldung auch am Proxy erfolgen und `WEB_PASSWORD` leer bleiben, solange Port 8080 per Firewall nur für den Proxy erreichbar ist. Ohne Anmeldung prüft AdGuard Shield den `Host`-Header (Schutz vor DNS-Rebinding): Der Proxy darf dann **keinen** fremden Hostnamen weiterreichen, also bei nginx `proxy_set_header Host $host;` weglassen (bzw. `Host 127.0.0.1` setzen), bei Caddy `header_up Host 127.0.0.1`.

## Zugriff per SSH-Tunnel

Ohne Reverse-Proxy und mit gesperrtem Port 8080 geht es auch per SSH-Tunnel vom eigenen Rechner aus:

```bash
ssh -L 8080:127.0.0.1:8080 root@dns-server
```

Danach im Browser `http://127.0.0.1:8080/` öffnen. Der Tunnel verschlüsselt die Verbindung.

## Sicherheit

| Maßnahme | Details |
|---|---|
| Nur Lesen | Ausschließlich `GET`/`HEAD`; andere Methoden werden mit `405` abgelehnt, unbekannte Pfade (nach der Anmeldung) mit `404` |
| Anmeldung | HTTP Basic Auth (Realm `AdGuard Shield`), sobald `WEB_PASSWORD` gesetzt ist. Gilt für alle Pfade, auch Skripte, Styles und die API. Vergleich in konstanter Zeit über SHA-256-Hashes |
| Drosselung | Nach 10 fehlgeschlagenen Anmeldungen pro Client (IPv4-Adresse bzw. IPv6-/64) innerhalb einer Minute werden Anfragen dieses Clients ohne gültige Zugangsdaten bis zum Ende der Minute mit `429` abgewiesen. Zusätzlich gilt ein globales Limit von 100 Fehlversuchen pro Minute für alle Clients zusammen. Gültige Zugangsdaten werden immer angenommen. Fehlversuche werden gedrosselt als `WARN` geloggt (ohne Benutzername oder Passwort) |
| DNS-Rebinding | Ohne `WEB_PASSWORD` werden nur Anfragen beantwortet, deren `Host`-Header eine IP-Adresse oder `localhost` ist; sonst `421 Misdirected Request`. Mit Anmeldung entfällt die Prüfung (Reverse-Proxys mit eigenem Hostnamen) |
| HTTPS | Übernimmt der Reverse-Proxy; HSTS bei Bedarf dort setzen |
| Browser-Schutz | Strenge Content-Security-Policy (`default-src 'self'`, keine Inline-Skripte oder -Styles, keine externen Quellen), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` für die API |
| Keine externen Abhängigkeiten | HTML, CSS, JavaScript und Icon sind im Programm eingebettet; es werden keine CDNs oder Web-Fonts geladen |
| XSS-Schutz | Daten (Domains, Client-Namen, Logzeilen) werden im Browser nur als Text eingefügt, nie als HTML |
| Zeitlimits | Lese-, Schreib- und Leerlauf-Timeouts sowie begrenzte Header-Größe gegen hängende oder übergroße Anfragen |
| Geordnetes Beenden | Beim Stoppen des Daemons wird die Statusseite mit bis zu 5 Sekunden Wartezeit für laufende Anfragen beendet. Laufende Statusabfragen werden abgebrochen; der Daemon wartet (höchstens 5 Sekunden) auf ihr Ende, bevor er die Datenbank schließt |

## Schnittstelle

Die Seite lädt ihre Daten von `<WEB_BASE_PATH>api/status` (JSON). Die Schnittstelle kann auch direkt abgefragt werden, z.B. für eigene Auswertungen:

```bash
curl -s -u admin:PASSWORT http://127.0.0.1:8080/api/status | jq .tiles
```

| Pfad | Inhalt |
|---|---|
| `<WEB_BASE_PATH>` | Statusseite |
| `<WEB_BASE_PATH>api/status` | Status als JSON |
| `<WEB_BASE_PATH>static/app.css`, `static/app.js`, `static/icon.svg` | Eingebettete Dateien der Seite |

Das JSON-Format ist für die Statusseite gedacht und kann sich zwischen Versionen ändern.
