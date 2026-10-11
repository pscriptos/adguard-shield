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

| Parameter | Standard | Beschreibung |
|---|---|---|
| `WEB_ENABLED` | `false` | Statusseite aktivieren |
| `WEB_LISTEN` | `127.0.0.1:8443` | Adresse und Port (`host:port`). Standard nur lokal (Loopback). `:8443` oder `0.0.0.0:8443` = alle Schnittstellen |
| `WEB_BASE_PATH` | `/` | Basispfad, z.B. `/adguard-shield/` hinter einem Reverse-Proxy. Wird automatisch auf führenden und abschließenden `/` ergänzt |
| `WEB_USER` | `admin` | Benutzername für HTTP Basic Auth |
| `WEB_PASSWORD` | *(leer)* | Passwort für HTTP Basic Auth. **Leer = Statusseite ohne Anmeldung** |
| `WEB_TLS_CERT` | *(leer)* | Pfad zum TLS-Zertifikat (PEM). Zusammen mit `WEB_TLS_KEY` = HTTPS |
| `WEB_TLS_KEY` | *(leer)* | Pfad zum privaten Schlüssel (PEM) |

Beispiel:

```bash
WEB_ENABLED=true
WEB_LISTEN="127.0.0.1:8443"
WEB_BASE_PATH="/"
WEB_USER="admin"
WEB_PASSWORD='ein-langes-zufaelliges-passwort'
```

Nach Änderungen:

```bash
sudo systemctl restart adguard-shield
sudo adguard-shield logs --limit 20
```

Im Log steht beim Start z.B.:

```text
[INFO] [ADGUARD-SHIELDD] Web-Statusseite gestartet: http://127.0.0.1:8443/ (Anmeldung: Basic Auth)
```

### Prüfungen und Warnungen

| Situation | Verhalten |
|---|---|
| `WEB_LISTEN` ist kein gültiges `host:port` oder der Port liegt nicht in 1–65535 | Warnung, Standard `127.0.0.1:8443` wird verwendet |
| `WEB_BASE_PATH` enthält andere Zeichen als Buchstaben, Ziffern, `- _ . ~ /` oder `.`/`..`-Segmente | Warnung, Standard `/` wird verwendet |
| Nur `WEB_TLS_CERT` oder nur `WEB_TLS_KEY` gesetzt | Warnung, die Statusseite wird **nicht** gestartet (der Daemon läuft normal weiter) |
| Zertifikat/Schlüssel nicht lesbar oder Port belegt | Fehler im Log, die Statusseite läuft nicht, der Daemon läuft normal weiter |
| `WEB_PASSWORD` leer und `WEB_LISTEN` nicht auf Loopback | Warnung: `Web-Statusseite ohne Anmeldung auf … erreichbar – WEB_PASSWORD setzen oder an 127.0.0.1 binden` |
| `WEB_PASSWORD` gesetzt, kein TLS und `WEB_LISTEN` nicht auf Loopback | Warnung: Basic-Auth-Zugangsdaten werden im Klartext übertragen |
| `WEB_USER` enthält `:` | Warnung, eine Anmeldung ist so nicht möglich (Basic Auth erlaubt keinen Doppelpunkt im Benutzernamen) |

## Zugriff per SSH-Tunnel (empfohlen)

Mit dem Standard `WEB_LISTEN="127.0.0.1:8443"` ist die Seite nur auf dem Server selbst erreichbar. Vom eigenen Rechner aus:

```bash
ssh -L 8443:127.0.0.1:8443 root@dns-server
```

Danach im Browser `http://127.0.0.1:8443/` öffnen. Der Tunnel verschlüsselt die Verbindung, TLS ist dafür nicht nötig. Auf einem Server, auf dem nur Administratoren per SSH arbeiten, kann `WEB_PASSWORD` in diesem Fall auch leer bleiben.

## Hinter einem Reverse-Proxy

`WEB_BASE_PATH` muss dem Pfad entsprechen, unter dem der Proxy die Seite ausliefert. Der Proxy reicht den Pfad **unverändert** (mit Präfix) weiter.

```bash
WEB_LISTEN="127.0.0.1:8443"
WEB_BASE_PATH="/adguard-shield/"
WEB_PASSWORD='ein-langes-zufaelliges-passwort'
```

nginx:

```nginx
location /adguard-shield/ {
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host $host;
}
```

Caddy:

```text
handle /adguard-shield/* {
    reverse_proxy 127.0.0.1:8443
}
```

Hinweise:

- Der Proxy sollte HTTPS terminieren, sonst laufen die Basic-Auth-Zugangsdaten im Klartext über das Netz.
- Die Sperre nach zu vielen Fehlversuchen gilt pro Client-IP. Hinter einem Proxy sieht AdGuard Shield nur die IP des Proxys; `X-Forwarded-For` wird bewusst nicht ausgewertet, weil der Header fälschbar ist. Zehn Fehlversuche irgendeines Nutzers sperren dann für bis zu eine Minute **alle** Anfragen über den Proxy – auch mit gültigen Zugangsdaten, damit das Passwort während der Sperre nicht weiter geraten werden kann.
- Alternativ kann die Anmeldung auch am Proxy erfolgen und `WEB_PASSWORD` leer bleiben, solange `WEB_LISTEN` auf `127.0.0.1` gebunden ist. Ohne Anmeldung prüft AdGuard Shield den `Host`-Header (Schutz vor DNS-Rebinding): Der Proxy darf dann **keinen** fremden Hostnamen weiterreichen, also bei nginx `proxy_set_header Host $host;` weglassen (bzw. `Host 127.0.0.1` setzen), bei Caddy `header_up Host 127.0.0.1`.

## Direkt mit HTTPS

```bash
WEB_LISTEN="0.0.0.0:8443"
WEB_PASSWORD='ein-langes-zufaelliges-passwort'
WEB_TLS_CERT="/etc/ssl/adguard-shield/cert.pem"
WEB_TLS_KEY="/etc/ssl/adguard-shield/key.pem"
```

Es wird mindestens TLS 1.2 verwendet, zusätzlich wird `Strict-Transport-Security: max-age=31536000` gesendet. Zertifikat und Schlüssel werden beim Start gelesen; der Daemon prüft höchstens einmal pro Minute, ob sich die Dateien geändert haben (Änderungszeit/Größe), und lädt ein erneuertes Zertifikat (z.B. Let's Encrypt) ohne Neustart. Ist das neue Paar unvollständig oder defekt, bleibt das bisherige Zertifikat aktiv und es wird eine Warnung geloggt. Den Port bei Bedarf in der Firewall freigeben, und zwar nur für vertrauenswürdige Netze.

## Sicherheit

| Maßnahme | Details |
|---|---|
| Nur Lesen | Ausschließlich `GET`/`HEAD`; andere Methoden werden mit `405` abgelehnt, unbekannte Pfade (nach der Anmeldung) mit `404` |
| Anmeldung | HTTP Basic Auth (Realm `AdGuard Shield`), sobald `WEB_PASSWORD` gesetzt ist. Gilt für alle Pfade, auch Skripte, Styles und die API. Vergleich in konstanter Zeit über SHA-256-Hashes |
| Drosselung | Nach 10 fehlgeschlagenen Anmeldungen pro Client (IPv4-Adresse bzw. IPv6-/64) innerhalb einer Minute werden Anfragen dieses Clients ohne gültige Zugangsdaten bis zum Ende der Minute mit `429` abgewiesen. Zusätzlich gilt ein globales Limit von 100 Fehlversuchen pro Minute für alle Clients zusammen. Gültige Zugangsdaten werden immer angenommen. Fehlversuche werden gedrosselt als `WARN` geloggt (ohne Benutzername oder Passwort) |
| DNS-Rebinding | Ohne `WEB_PASSWORD` werden nur Anfragen beantwortet, deren `Host`-Header eine IP-Adresse, `localhost` oder der Host aus `WEB_LISTEN` ist; sonst `421 Misdirected Request`. Mit Anmeldung entfällt die Prüfung (Reverse-Proxys mit eigenem Hostnamen) |
| HTTPS | Mit `WEB_TLS_CERT`/`WEB_TLS_KEY` wird `Strict-Transport-Security` gesendet |
| Browser-Schutz | Strenge Content-Security-Policy (`default-src 'self'`, keine Inline-Skripte oder -Styles, keine externen Quellen), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` für die API |
| Keine externen Abhängigkeiten | HTML, CSS, JavaScript und Icon sind im Programm eingebettet; es werden keine CDNs oder Web-Fonts geladen |
| XSS-Schutz | Daten (Domains, Client-Namen, Logzeilen) werden im Browser nur als Text eingefügt, nie als HTML |
| Zeitlimits | Lese-, Schreib- und Leerlauf-Timeouts sowie begrenzte Header-Größe gegen hängende oder übergroße Anfragen |
| Geordnetes Beenden | Beim Stoppen des Daemons wird die Statusseite mit bis zu 5 Sekunden Wartezeit für laufende Anfragen beendet. Laufende Statusabfragen werden abgebrochen; der Daemon wartet (höchstens 5 Sekunden) auf ihr Ende, bevor er die Datenbank schließt |

## Schnittstelle

Die Seite lädt ihre Daten von `<WEB_BASE_PATH>api/status` (JSON). Die Schnittstelle kann auch direkt abgefragt werden, z.B. für eigene Auswertungen:

```bash
curl -s -u admin:PASSWORT http://127.0.0.1:8443/api/status | jq .tiles
```

| Pfad | Inhalt |
|---|---|
| `<WEB_BASE_PATH>` | Statusseite |
| `<WEB_BASE_PATH>api/status` | Status als JSON |
| `<WEB_BASE_PATH>static/app.css`, `static/app.js`, `static/icon.svg` | Eingebettete Dateien der Seite |

Das JSON-Format ist für die Statusseite gedacht und kann sich zwischen Versionen ändern.
