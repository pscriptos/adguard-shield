# Update-Anleitung

## Voraussetzungen

- AdGuard Shield ist bereits installiert (`/opt/adguard-shield/`)
- Git ist installiert (`sudo apt install git`)
- Zugriff auf den Server per SSH mit Root-Rechten

## Update durchführen

### 1. Git-Repository aktualisieren

Wechsle in das Verzeichnis, in dem du das Repository geklont hast, und hole die neueste Version:

```bash
cd /pfad/zum/adguard-shield
git pull
```

> **Hinweis:** Falls du das Repository z.B. nach `/opt/adguard-shield-repo` geklont hast:
> ```bash
> cd /opt/adguard-shield-repo
> git pull
> ```

### 2. Update-Script ausführen

```bash
sudo bash install.sh update
```

Das Update-Script macht automatisch folgendes:

1. **Abhängigkeiten prüfen** — Fehlende Pakete werden nachinstalliert
2. **Scripts aktualisieren** — Alle `.sh`-Dateien werden nach `/opt/adguard-shield/` kopiert
3. **Konfigurations-Migration** — Neue Parameter werden automatisch zur bestehenden Konfiguration hinzugefügt, bestehende Einstellungen bleiben **unverändert**
4. **Backup erstellen** — Die alte Konfiguration wird als `adguard-shield.conf.old` gesichert
5. **Service aktualisieren** — Die systemd Service-Datei und Watchdog-Dateien werden aktualisiert und `daemon-reload` ausgeführt
6. **Watchdog aktivieren** — Der Watchdog-Timer wird automatisch aktiviert (falls noch nicht aktiv)
7. **Service neustarten** — Der Service wird automatisch neu gestartet (falls er vorher lief)

### 3. Neue Parameter prüfen (optional)

Nach dem Update empfiehlt es sich, eventuell neu hinzugefügte Konfigurationsparameter zu prüfen:

```bash
sudo nano /opt/adguard-shield/adguard-shield.conf
```

Falls etwas nicht stimmt, kann das Backup wiederhergestellt werden:

```bash
sudo cp /opt/adguard-shield/adguard-shield.conf.old /opt/adguard-shield/adguard-shield.conf
sudo systemctl restart adguard-shield
```

## Kurzfassung (Copy & Paste)

```bash
cd /pfad/zum/adguard-shield
git pull
sudo bash install.sh update
```

## Versionsprüfung

Installierte Version anzeigen:

```bash
sudo /opt/adguard-shield/adguard-shield.sh status
```

Oder über den Installer:

```bash
sudo bash install.sh status
```
