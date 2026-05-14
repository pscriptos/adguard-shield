package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"adguard-shield/internal/appinfo"
	"adguard-shield/internal/config"
	"adguard-shield/internal/daemon"
	"adguard-shield/internal/installer"
	"adguard-shield/internal/report"
)

const statusBanLimit = 50

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FEHLER:", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	confPath := config.DefaultPath()
	if len(args) >= 2 && args[0] == "-config" {
		confPath = args[1]
		args = args[2:]
	}
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println(appinfo.Version)
		return nil
	case "install":
		return installCommand(args)
	case "update":
		return updateCommand(args)
	case "uninstall":
		return uninstallCommand(args)
	case "install-status":
		return installStatusCommand(args)
	}
	cfg, err := config.Load(confPath)
	if err != nil {
		return err
	}
	d, err := daemon.New(cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := commandContext(d, cmd == "run" || cmd == "start" || cmd == "dry-run")
	defer stop()
	switch cmd {
	case "run", "start", "dry-run":
		if cmd == "dry-run" {
			cfg.DryRun = true
		}
		if err := writePID(cfg.PIDFile); err != nil {
			return err
		}
		defer os.Remove(cfg.PIDFile)
		err := d.Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case "stop":
		return stopDaemon(cfg.PIDFile)
	case "test":
		items, err := d.FetchQueryLog(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Verbindung erfolgreich. %d Querylog-Einträge gefunden.\n", len(items))
	case "status":
		return status(d)
	case "live", "watch":
		return liveCommand(ctx, d, args)
	case "logs":
		return logsCommand(d, args)
	case "logs-follow":
		return logsFollowCommand(ctx, d, args)
	case "history":
		limit := 50
		if len(args) > 0 {
			if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
				limit = n
			}
		}
		lines, err := d.Store.RecentHistory(limit)
		if err != nil {
			return err
		}
		for _, l := range lines {
			fmt.Println(l)
		}
	case "flush":
		bans, err := d.Store.ActiveBans()
		if err != nil {
			return err
		}
		for _, b := range bans {
			_ = d.UnbanQuiet(ctx, b.IP, "manual-flush")
		}
		d.NotifyBulkUnban(ctx, "manual-flush", len(bans))
		fmt.Printf("%d Sperren aufgehoben\n", len(bans))
	case "unban":
		if len(args) < 1 {
			return fmt.Errorf("Nutzung: adguard-shield unban <IP>")
		}
		return d.Unban(ctx, args[0], "manual")
	case "ban":
		if len(args) < 1 {
			return fmt.Errorf("Nutzung: adguard-shield ban <IP>")
		}
		return d.Ban(ctx, args[0], "manual", 0, "-", "manual", "manual", "", true)
	case "reset-offenses":
		ip := ""
		if len(args) > 0 {
			ip = args[0]
		}
		return d.Store.ResetOffense(ip)
	case "offense-cleanup":
		n, err := d.Store.CleanupOffenses(cfg.ProgressiveBanResetAfter)
		if err != nil {
			return err
		}
		fmt.Printf("%d abgelaufene Offense-Zaehler entfernt\n", n)
	case "offense-status":
		total, err := d.Store.CountOffenses()
		if err != nil {
			return err
		}
		expired, err := d.Store.CountExpiredOffenses(cfg.ProgressiveBanResetAfter)
		if err != nil {
			return err
		}
		fmt.Println("Offense-Cleanup")
		fmt.Printf("Aktiv im Daemon: %v\n", cfg.ProgressiveBanEnabled)
		fmt.Printf("Reset nach: %ds\n", cfg.ProgressiveBanResetAfter)
		fmt.Printf("Offense-Zaehler gesamt: %d\n", total)
		fmt.Printf("Davon abgelaufen: %d\n", expired)
	case "geoip-lookup":
		if len(args) < 1 {
			return fmt.Errorf("Nutzung: adguard-shield geoip-lookup <IP>")
		}
		if err := d.Geo.Open(ctx); err != nil {
			return err
		}
		cc, err := d.Geo.Lookup(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("IP: %s -> Land: %s\n", args[0], empty(cc, "unbekannt"))
	case "geoip-sync":
		if err := d.Geo.Open(ctx); err != nil {
			return err
		}
		items, err := d.FetchQueryLog(ctx)
		if err != nil {
			return err
		}
		events := d.ToEventsForCommand(items)
		seen := map[string]bool{}
		for _, ev := range events {
			if seen[ev] {
				continue
			}
			seen[ev] = true
			d.CheckGeoIPForCommand(ctx, ev)
		}
		fmt.Printf("GeoIP-Sync abgeschlossen: %d Clients geprüft\n", len(seen))
	case "geoip-status":
		return geoipStatus(d)
	case "geoip-flush":
		bans, err := d.Store.ActiveBans()
		if err != nil {
			return err
		}
		n := 0
		for _, b := range bans {
			if b.Reason == "geoip" || b.Source == "geoip" {
				_ = d.UnbanQuiet(ctx, b.IP, "geoip-flush")
				n++
			}
		}
		d.NotifyBulkUnban(ctx, "geoip-flush", n)
		fmt.Printf("%d GeoIP-Sperren aufgehoben\n", n)
	case "geoip-flush-cache":
		n, err := d.Store.ClearGeoIPCache()
		if err != nil {
			return err
		}
		fmt.Printf("%d GeoIP-Cache-Einträge entfernt\n", n)
	case "blocklist-sync":
		return d.SyncBlocklist(ctx)
	case "whitelist-sync":
		return d.SyncWhitelist(ctx)
	case "blocklist-status":
		return blocklistStatus(d)
	case "whitelist-status":
		return whitelistStatus(d)
	case "blocklist-flush":
		return flushSource(ctx, d, "external-blocklist")
	case "whitelist-flush":
		return d.Store.ReplaceWhitelist(nil, "external")
	case "report-status":
		fmt.Print(report.Status(cfg))
	case "report-generate":
		format := ""
		output := ""
		if len(args) > 0 {
			format = args[0]
		}
		if len(args) > 1 {
			output = args[1]
		}
		body, err := report.Generate(cfg, d.Store, format)
		if err != nil {
			return err
		}
		if output != "" {
			return os.WriteFile(output, []byte(body), 0644)
		}
		fmt.Print(body)
	case "report-send":
		return report.Send(ctx, cfg, d.Store)
	case "report-test":
		return report.SendTest(ctx, cfg)
	case "report-install":
		binary := "/opt/adguard-shield/adguard-shield"
		if _, err := os.Stat(installer.CLICommandPath); err == nil {
			binary = installer.CLICommandPath
		}
		return report.InstallCron(binary, cfg.Path, cfg)
	case "report-remove":
		return report.RemoveCron()
	case "firewall-create":
		return d.FW.Setup(ctx)
	case "firewall-remove":
		return d.FW.Remove(ctx)
	case "firewall-flush":
		return d.FW.Flush(ctx)
	case "firewall-status":
		return firewallStatus(ctx, d)
	case "firewall-save":
		return d.SaveFirewallRules(ctx)
	case "firewall-restore":
		return restoreFirewallRules(ctx, d)
	default:
		usage()
	}
	return nil
}

func status(d *daemon.Daemon) error {
	bans, err := d.Store.ActiveBans()
	if err != nil {
		return err
	}
	fmt.Println("AdGuard Shield Daemon Status")
	fmt.Printf("Config: %s\n", d.Config.Path)
	fmt.Printf("Firewall: %s/%s (Chain: %s)\n", d.Config.FirewallBackend, d.Config.FirewallMode, d.Config.Chain)
	fmt.Printf("GeoIP: %v (%s %v)\n", d.Config.GeoIPEnabled, d.Config.GeoIPMode, d.Config.GeoIPCountries)
	fmt.Printf("Externe Blocklist: %v (%d URLs)\n", d.Config.ExternalBlocklistEnabled, len(d.Config.ExternalBlocklistURLs))
	fmt.Printf("Externe Whitelist: %v (%d URLs)\n", d.Config.ExternalWhitelistEnabled, len(d.Config.ExternalWhitelistURLs))
	fmt.Printf("Aktive Sperren: %d\n", len(bans))
	limit := min(len(bans), statusBanLimit)
	for _, b := range bans[:limit] {
		until := "permanent"
		if !b.Permanent && b.BanUntil > 0 {
			until = time.Unix(b.BanUntil, 0).Format("2006-01-02 15:04:05")
		}
		fmt.Printf("  %s | %s | %s | %s\n", b.IP, b.Source, b.Reason, until)
	}
	if len(bans) > limit {
		fmt.Printf("  ... %d weitere Sperren. Details mit: adguard-shield history oder direkt in SQLite.\n", len(bans)-limit)
	}
	return nil
}

func blocklistStatus(d *daemon.Daemon) error {
	count, err := d.Store.CountBySource("external-blocklist")
	if err != nil {
		return err
	}
	fmt.Println("Externe Blocklist")
	fmt.Printf("Aktiv: %v\n", d.Config.ExternalBlocklistEnabled)
	fmt.Printf("Intervall: %ds\n", d.Config.ExternalBlocklistInterval)
	fmt.Printf("Auto-Unban: %v\n", d.Config.ExternalBlocklistAutoUnban)
	fmt.Printf("Cache: %s\n", d.Config.ExternalBlocklistCacheDir)
	fmt.Printf("Aktive Sperren: %d\n", count)
	for i, u := range d.Config.ExternalBlocklistURLs {
		fmt.Printf("  [%d] %s\n", i, u)
	}
	return nil
}

func whitelistStatus(d *daemon.Daemon) error {
	wl, err := d.Store.AllWhitelist()
	if err != nil {
		return err
	}
	fmt.Println("Externe Whitelist")
	fmt.Printf("Aktiv: %v\n", d.Config.ExternalWhitelistEnabled)
	fmt.Printf("Intervall: %ds\n", d.Config.ExternalWhitelistInterval)
	fmt.Printf("Cache: %s\n", d.Config.ExternalWhitelistCacheDir)
	fmt.Printf("Aufgelöste IPs: %d\n", len(wl))
	for i, u := range d.Config.ExternalWhitelistURLs {
		fmt.Printf("  [%d] %s\n", i, u)
	}
	return nil
}

func geoipStatus(d *daemon.Daemon) error {
	fmt.Println("GeoIP Status")
	fmt.Printf("Aktiv: %v\n", d.Config.GeoIPEnabled)
	fmt.Printf("Modus: %s\n", d.Config.GeoIPMode)
	fmt.Printf("Länder: %v\n", d.Config.GeoIPCountries)
	fmt.Printf("Cache TTL: %ds\n", d.Config.GeoIPCacheTTL)
	fmt.Printf("MMDB: %s\n", empty(d.Config.GeoIPMMDBPath, "<auto/falls License-Key gesetzt>"))
	bans, err := d.Store.BansByReason("geoip")
	if err != nil {
		return err
	}
	fmt.Printf("Aktive GeoIP-Sperren: %d\n", len(bans))
	return nil
}

func flushSource(ctx context.Context, d *daemon.Daemon, source string) error {
	bans, err := d.Store.BansBySource(source)
	if err != nil {
		return err
	}
	for _, b := range bans {
		_ = d.UnbanQuiet(ctx, b.IP, source+"-flush")
	}
	d.NotifyBulkUnban(ctx, source+"-flush", len(bans))
	fmt.Printf("%d Sperren aufgehoben\n", len(bans))
	return nil
}

func writePID(path string) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

func commandContext(d *daemon.Daemon, notifyServiceStop bool) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		select {
		case <-signals:
			if notifyServiceStop {
				d.NotifyServiceStop(context.Background())
			}
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		close(done)
		signal.Stop(signals)
		cancel()
	}
}

func stopDaemon(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Daemon läuft nicht oder PID-Datei fehlt: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	fmt.Printf("Daemon gestoppt (PID %d)\n", pid)
	return nil
}

func firewallStatus(ctx context.Context, d *daemon.Daemon) error {
	fmt.Printf("Firewall Backend: %s\n", d.Config.FirewallBackend)
	fmt.Printf("Firewall Modus: %s\n", d.Config.FirewallMode)
	fmt.Printf("Chain: %s\n", d.Config.Chain)
	for _, cmd := range [][]string{
		{"ipset", "list", "adguard_shield_v4"},
		{"ipset", "list", "adguard_shield_v6"},
		{"iptables", "-n", "-L", d.Config.Chain, "--line-numbers", "-v"},
		{"ip6tables", "-n", "-L", d.Config.Chain, "--line-numbers", "-v"},
	} {
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		fmt.Printf("\n--- %s ---\n", cmd[0])
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		fmt.Print(string(out))
	}
	return nil
}

func restoreFirewallRules(ctx context.Context, d *daemon.Daemon) error {
	files := []struct {
		path string
		cmd  string
	}{
		{filepath.Join(d.Config.StateDir, "iptables-rules.v4"), "iptables-restore"},
		{filepath.Join(d.Config.StateDir, "iptables-rules.v6"), "ip6tables-restore"},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		c := exec.CommandContext(ctx, f.cmd)
		stdin, err := c.StdinPipe()
		if err != nil {
			return err
		}
		if err := c.Start(); err != nil {
			return err
		}
		_, _ = stdin.Write(data)
		_ = stdin.Close()
		if err := c.Wait(); err != nil {
			return err
		}
	}
	return nil
}

func empty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func usage() {
	fmt.Println(`AdGuard Shield Daemon

Nutzung:
  adguard-shield version
  adguard-shield install [--config-source PATH] [--skip-deps] [--no-register]
  adguard-shield update [--config-source PATH] [--skip-deps] [--no-register]
  adguard-shield uninstall [--keep-config]
  adguard-shield install-status
  adguard-shield [-config PATH] run|start|stop|dry-run
  adguard-shield status|history [N]|test|flush|ban IP|unban IP|reset-offenses [IP]
  adguard-shield live [--interval N] [--top N] [--recent N] [--logs LEVEL] [--once]
  adguard-shield logs [--level LEVEL] [--limit N]|logs-follow [--level LEVEL]
  adguard-shield offense-status|offense-cleanup
  adguard-shield geoip-status|geoip-sync|geoip-flush|geoip-flush-cache|geoip-lookup IP
  adguard-shield blocklist-status|blocklist-sync|blocklist-flush
  adguard-shield whitelist-status|whitelist-sync|whitelist-flush
  adguard-shield report-status|report-generate [html|txt] [OUTPUT]|report-send|report-test|report-install|report-remove
  adguard-shield firewall-create|firewall-remove|firewall-flush|firewall-status|firewall-save|firewall-restore`)
}

func liveCommand(ctx context.Context, d *daemon.Daemon, args []string) error {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	interval := fs.Int("interval", d.Config.CheckInterval, "Aktualisierungsintervall in Sekunden")
	top := fs.Int("top", 10, "Anzahl Top-Einträge")
	recent := fs.Int("recent", 12, "Anzahl letzter Queries und Logs")
	logLevel := fs.String("logs", "INFO", "Systemlogs ab Level anzeigen: DEBUG, INFO, WARN, ERROR oder off")
	once := fs.Bool("once", false, "Nur einen Snapshot anzeigen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	err := d.Live(ctx, os.Stdout, daemon.LiveOptions{
		Interval: time.Duration(*interval) * time.Second,
		Top:      *top,
		Recent:   *recent,
		LogLevel: *logLevel,
		Once:     *once,
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func logsCommand(d *daemon.Daemon, args []string) error {
	level, limit, err := parseLogArgs("logs", args, "INFO", 80)
	if err != nil {
		return err
	}
	lines := daemon.RecentLogLines(d.Config.LogFile, level, limit)
	if len(lines) == 0 {
		fmt.Printf("Keine Logeinträge ab Level %s in %s gefunden.\n", strings.ToUpper(level), d.Config.LogFile)
		return nil
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}

func logsFollowCommand(ctx context.Context, d *daemon.Daemon, args []string) error {
	level, limit, err := parseLogArgs("logs-follow", args, "INFO", 40)
	if err != nil {
		return err
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("AdGuard Shield Logs | %s | %s ab %s | Strg+C beendet\n", time.Now().Format("2006-01-02 15:04:05"), d.Config.LogFile, strings.ToUpper(level))
		fmt.Println(strings.Repeat("=", 92))
		lines := daemon.RecentLogLines(d.Config.LogFile, level, limit)
		if len(lines) == 0 {
			fmt.Println("Keine passenden Logeinträge.")
		} else {
			for _, line := range lines {
				fmt.Println(line)
			}
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return ctx.Err()
		case <-t.C:
		}
	}
}

func parseLogArgs(name string, args []string, defaultLevel string, defaultLimit int) (string, int, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	level := fs.String("level", defaultLevel, "Mindestlevel: DEBUG, INFO, WARN, ERROR")
	limit := fs.Int("limit", defaultLimit, "Anzahl der letzten Logzeilen")
	if err := fs.Parse(args); err != nil {
		return "", 0, err
	}
	rest := fs.Args()
	if len(rest) > 0 {
		if isLogLevel(rest[0]) {
			*level = rest[0]
		} else if n, err := strconv.Atoi(rest[0]); err == nil && n > 0 {
			*limit = n
		}
	}
	if len(rest) > 1 {
		if n, err := strconv.Atoi(rest[1]); err == nil && n > 0 {
			*limit = n
		}
	}
	if !isLogLevel(*level) {
		return "", 0, fmt.Errorf("ungültiges Log-Level %q (erlaubt: DEBUG, INFO, WARN, ERROR)", *level)
	}
	if *limit <= 0 {
		*limit = defaultLimit
	}
	return strings.ToUpper(*level), *limit, nil
}

func isLogLevel(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "ERR":
		return true
	default:
		return false
	}
}

func installCommand(args []string) error {
	opts, err := parseInstallFlags("install", args)
	if err != nil {
		return err
	}
	err = installer.Install(opts)
	if le, ok := installer.IsLegacyError(err); ok {
		return fmt.Errorf("%s", installer.FormatLegacyMessage(le, opts.InstallDir))
	}
	if err != nil {
		return err
	}
	fmt.Println("AdGuard Shield Go-Installation abgeschlossen.")
	fmt.Println(installer.PrintStatus(installer.GetStatus(opts.InstallDir)))
	return nil
}

func updateCommand(args []string) error {
	opts, err := parseInstallFlags("update", args)
	if err != nil {
		return err
	}
	err = installer.Update(opts)
	if le, ok := installer.IsLegacyError(err); ok {
		return fmt.Errorf("%s", installer.FormatLegacyMessage(le, opts.InstallDir))
	}
	if err != nil {
		return err
	}
	fmt.Println("AdGuard Shield Go-Update abgeschlossen.")
	fmt.Println(installer.PrintStatus(installer.GetStatus(opts.InstallDir)))
	return nil
}

func uninstallCommand(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	opts := installer.DefaultOptions()
	fs.StringVar(&opts.InstallDir, "install-dir", opts.InstallDir, "Installationsverzeichnis")
	fs.BoolVar(&opts.KeepConfig, "keep-config", false, "Konfiguration behalten")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := installer.Uninstall(opts); err != nil {
		return err
	}
	fmt.Println("AdGuard Shield wurde deinstalliert.")
	return nil
}

func installStatusCommand(args []string) error {
	fs := flag.NewFlagSet("install-status", flag.ContinueOnError)
	installDir := installer.DefaultInstallDir
	fs.StringVar(&installDir, "install-dir", installDir, "Installationsverzeichnis")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Print(installer.PrintStatus(installer.GetStatus(installDir)))
	return nil
}

func parseInstallFlags(name string, args []string) (installer.Options, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	opts := installer.DefaultOptions()
	fs.StringVar(&opts.InstallDir, "install-dir", opts.InstallDir, "Installationsverzeichnis")
	fs.StringVar(&opts.ConfigSource, "config-source", "", "Konfiguration fuer Neuinstallation uebernehmen")
	fs.BoolVar(&opts.SkipDeps, "skip-deps", false, "Paketpruefung ueberspringen")
	noEnable := fs.Bool("no-enable", false, "systemd Autostart nicht aktivieren")
	noRegister := fs.Bool("no-register", false, "CLI-Befehl nicht in /usr/local/bin registrieren")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	opts.Enable = !*noEnable
	opts.RegisterCLI = !*noRegister
	return opts, nil
}
