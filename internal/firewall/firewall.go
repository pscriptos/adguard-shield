package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

const defaultBatchSize = 5000

var hookParents = []string{"INPUT", "DOCKER-USER"}

type Executor interface {
	Run(ctx context.Context, name string, args ...string) error
	RunInput(ctx context.Context, input string, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func (OSExecutor) RunInput(ctx context.Context, input string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (OSExecutor) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type Firewall struct {
	Exec   Executor
	Chain  string
	Ports  []string
	Mode   string
	DryRun bool
	Set4   string
	Set6   string

	batchSize int
}

type Entry struct {
	IP      string
	Timeout int64
}

func New(exec Executor, chain string, ports []string, mode string, dry bool) *Firewall {
	return &Firewall{Exec: exec, Chain: chain, Ports: ports, Mode: normalizeMode(mode), DryRun: dry, Set4: "adguard_shield_v4", Set6: "adguard_shield_v6"}
}

func (f *Firewall) Setup(ctx context.Context) error {
	if f.DryRun {
		return nil
	}
	if len(f.hooks("iptables")) == 0 {
		return fmt.Errorf("unsupported firewall mode %q", f.Mode)
	}
	_ = f.Exec.Run(ctx, "ipset", "create", f.Set4, "hash:net", "family", "inet", "timeout", "0", "-exist")
	_ = f.Exec.Run(ctx, "ipset", "create", f.Set6, "hash:net", "family", "inet6", "timeout", "0", "-exist")
	_ = f.Exec.Run(ctx, "iptables", "-N", f.Chain)
	_ = f.Exec.Run(ctx, "ip6tables", "-N", f.Chain)
	if err := ensureSetDrop(ctx, f.Exec, "iptables", f.Chain, f.Set4); err != nil {
		return err
	}
	if err := ensureSetDrop(ctx, f.Exec, "ip6tables", f.Chain, f.Set6); err != nil {
		return err
	}
	if err := f.ensureHooks(ctx, "iptables"); err != nil {
		return err
	}
	if err := f.ensureHooks(ctx, "ip6tables"); err != nil {
		return err
	}
	f.cleanupHooks(ctx, "iptables", f.keepHook)
	f.cleanupHooks(ctx, "ip6tables", f.keepHook)
	return nil
}

func ensureRule(ctx context.Context, ex Executor, bin string, args ...string) bool {
	return ex.Run(ctx, bin, args...) == nil
}

func ensureSetDrop(ctx context.Context, ex Executor, bin, chain, set string) error {
	check := []string{"-C", chain, "-m", "set", "--match-set", set, "src", "-j", "DROP"}
	if ex.Run(ctx, bin, check...) == nil {
		return nil
	}
	return ex.Run(ctx, bin, "-I", chain, "-m", "set", "--match-set", set, "src", "-j", "DROP")
}

type hook struct {
	Chain           string
	OptionalMissing bool
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "host", "classic", "native", "docker-host":
		return "host"
	case "docker", "docker-bridge", "docker-published", "published":
		return "docker-bridge"
	case "hybrid", "both":
		return "hybrid"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func (f *Firewall) hooks(bin string) []hook {
	docker := hook{Chain: "DOCKER-USER", OptionalMissing: bin == "ip6tables"}
	switch f.Mode {
	case "host":
		return []hook{{Chain: "INPUT"}}
	case "docker-bridge":
		return []hook{docker}
	case "hybrid":
		return []hook{{Chain: "INPUT"}, docker}
	default:
		return nil
	}
}

func (f *Firewall) ensureHooks(ctx context.Context, bin string) error {
	for _, h := range f.hooks(bin) {
		if !chainExists(ctx, f.Exec, bin, h.Chain) {
			if h.OptionalMissing {
				continue
			}
			return fmt.Errorf("%s chain %s not found", bin, h.Chain)
		}
		for _, p := range f.Ports {
			for _, proto := range []string{"tcp", "udp"} {
				check := []string{"-C", h.Chain, "-p", proto, "--dport", p, "-j", f.Chain}
				if ensureRule(ctx, f.Exec, bin, check...) {
					continue
				}
				_ = f.Exec.Run(ctx, bin, "-I", h.Chain, "-p", proto, "--dport", p, "-j", f.Chain)
			}
		}
	}
	return nil
}

func chainExists(ctx context.Context, ex Executor, bin, chain string) bool {
	return ex.Run(ctx, bin, "-n", "-L", chain) == nil
}

func (f *Firewall) Add(ctx context.Context, ip string, timeout int64) error {
	if f.DryRun {
		return nil
	}
	set, canon, err := f.target(ip)
	if err != nil {
		return err
	}
	return f.Exec.Run(ctx, "ipset", addArgs(set, canon, timeout)...)
}

// maxIPSetTimeout ist der groesste Timeout-Wert, den ipset akzeptiert.
const maxIPSetTimeout = 2147483

// clampTimeout liefert 0 (ohne Ablauf) fuer Werte ueber dem ipset-Maximum. Die
// Sperre wird dann vom Ablauf-Job anhand der Datenbank rechtzeitig aufgehoben,
// statt nach ~24,8 Tagen vorzeitig aus dem ipset zu fallen.
func clampTimeout(t int64) int64 {
	if t > maxIPSetTimeout {
		return 0
	}
	return t
}

func addArgs(set, ip string, timeout int64) []string {
	args := []string{"add", set, ip, "-exist"}
	if timeout > 0 {
		args = append(args, "timeout", strconv.FormatInt(clampTimeout(timeout), 10))
	}
	return args
}

type batchLine struct {
	set, ip string
	timeout int64
}

func (l batchLine) restore() string {
	line := "add " + l.set + " " + l.ip
	if l.timeout > 0 {
		line += " timeout " + strconv.FormatInt(clampTimeout(l.timeout), 10)
	}
	return line
}

// AddBatch fuegt alle gueltigen Eintraege per "ipset restore -exist" in Bloecken
// hinzu. Ungueltige IPs/Prefixe werden uebersprungen. Scheitert ein Block (ipset
// restore bricht bei der ersten fehlerhaften Zeile ab), werden seine Eintraege
// einzeln per "ipset add" gesetzt. Der Fehler nennt ungueltige und fehlgeschlagene
// Eintraege (errors.Join), gueltige Eintraege werden trotzdem gesetzt.
func (f *Firewall) AddBatch(ctx context.Context, entries []Entry) error {
	var lines []batchLine
	var invalid []string
	for _, e := range entries {
		set, canon, err := f.target(e.IP)
		if err != nil {
			invalid = append(invalid, e.IP)
			continue
		}
		lines = append(lines, batchLine{set: set, ip: canon, timeout: e.Timeout})
	}
	var errs []error
	if len(invalid) > 0 {
		errs = append(errs, invalidEntriesError(invalid))
	}
	if !f.DryRun {
		size := f.batchSize
		if size <= 0 {
			size = defaultBatchSize
		}
		for start := 0; start < len(lines); start += size {
			end := min(start+size, len(lines))
			var b strings.Builder
			for _, l := range lines[start:end] {
				b.WriteString(l.restore())
				b.WriteByte('\n')
			}
			if err := f.Exec.RunInput(ctx, b.String(), "ipset", "restore", "-exist"); err != nil {
				if ferr := f.addEach(ctx, lines[start:end]); ferr != nil {
					errs = append(errs, fmt.Errorf("ipset restore (entries %d-%d): %w; %w", start+1, end, err, ferr))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// addEach setzt Eintraege einzeln, damit ein fehlerhafter Eintrag die uebrigen
// nicht verhindert.
func (f *Firewall) addEach(ctx context.Context, lines []batchLine) error {
	var failed []string
	var firstErr error
	for i, l := range lines {
		if ctx.Err() != nil {
			return fmt.Errorf("per-entry fallback aborted after %d of %d entries: %w", i, len(lines), ctx.Err())
		}
		if err := f.Exec.Run(ctx, "ipset", addArgs(l.set, l.ip, l.timeout)...); err != nil {
			failed = append(failed, l.ip)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if len(failed) == 0 {
		return nil
	}
	shown := failed
	if len(shown) > 10 {
		shown = shown[:10]
	}
	msg := fmt.Sprintf("per-entry fallback: %d of %d entries failed: %q", len(failed), len(lines), shown)
	if len(failed) > len(shown) {
		msg += " ..."
	}
	return fmt.Errorf("%s (first error: %w)", msg, firstErr)
}

func invalidEntriesError(invalid []string) error {
	shown := invalid
	if len(shown) > 10 {
		shown = shown[:10]
	}
	msg := fmt.Sprintf("skipped %d invalid IP/prefix entries: %q", len(invalid), shown)
	if len(invalid) > len(shown) {
		msg += " ..."
	}
	return errors.New(msg)
}

// hookRules liefert die Regeln einer Parent-Chain, die nach f.Chain springen,
// jeweils als Argumente ohne "-A <parent>".
func (f *Firewall) hookRules(ctx context.Context, bin, parent string) [][]string {
	out, err := f.Exec.Output(ctx, bin, "-S", parent)
	if err != nil {
		return nil
	}
	var rules [][]string
	for _, line := range strings.Split(string(out), "\n") {
		fields := splitRule(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != parent {
			continue
		}
		args := fields[2:]
		for i := 0; i+1 < len(args); i++ {
			if (args[i] == "-j" || args[i] == "--jump") && args[i+1] == f.Chain {
				rules = append(rules, args)
				break
			}
		}
	}
	return rules
}

// cleanupHooks entfernt Sprungregeln nach f.Chain aus INPUT/DOCKER-USER, die
// keep nicht behalten will (keep == nil entfernt alle).
func (f *Firewall) cleanupHooks(ctx context.Context, bin string, keep func(bin, parent string, args []string) bool) {
	for _, parent := range hookParents {
		for _, args := range f.hookRules(ctx, bin, parent) {
			if keep != nil && keep(bin, parent, args) {
				continue
			}
			_ = f.Exec.Run(ctx, bin, append([]string{"-D", parent}, args...)...)
		}
	}
}

// ownHook erkennt Regeln, die nur aus den von ensureHooks erzeugten Optionen
// bestehen ("-p <proto> [-m <proto>] --dport <port> -j <chain>"), und liefert
// Protokoll und Port. Regeln mit weiteren Optionen (z.B. -i, -s, Kommentare)
// gelten als manuell angelegt.
func (f *Firewall) ownHook(args []string) (proto, port string, ok bool) {
	var target string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return "", "", false
		}
		val := args[i+1]
		switch args[i] {
		case "-p", "--protocol":
			proto = val
		case "-m", "--match":
			if val != "tcp" && val != "udp" {
				return "", "", false
			}
		case "--dport", "--destination-port":
			port = val
		case "-j", "--jump":
			target = val
		default:
			return "", "", false
		}
	}
	if target != f.Chain || (proto != "tcp" && proto != "udp") || port == "" {
		return "", "", false
	}
	return proto, port, true
}

// keepHook entscheidet in Setup, welche Sprungregeln bleiben: alle fremd
// aussehenden Regeln und die eigenen Hooks des aktuellen Modus und der
// aktuellen Ports.
func (f *Firewall) keepHook(bin, parent string, args []string) bool {
	_, port, ok := f.ownHook(args)
	if !ok {
		return true
	}
	return f.wantedHook(bin, parent, port)
}

func (f *Firewall) wantedHook(bin, parent, port string) bool {
	parentOK := false
	for _, h := range f.hooks(bin) {
		if h.Chain == parent {
			parentOK = true
			break
		}
	}
	if !parentOK {
		return false
	}
	for _, p := range f.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// splitRule zerlegt eine Zeile aus "iptables -S" und beachtet dabei
// doppelte Anfuehrungszeichen (z.B. bei --comment).
func splitRule(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote, escaped, has := false, false, false
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
			has = true
		case (r == ' ' || r == '\t') && !inQuote:
			if has {
				fields = append(fields, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		fields = append(fields, cur.String())
	}
	return fields
}

func (f *Firewall) Del(ctx context.Context, ip string) error {
	if f.DryRun {
		return nil
	}
	set, canon, err := f.target(ip)
	if err != nil {
		return err
	}
	_ = f.Exec.Run(ctx, "ipset", "del", set, canon)
	return nil
}

func (f *Firewall) Flush(ctx context.Context) error {
	if f.DryRun {
		return nil
	}
	_ = f.Exec.Run(ctx, "ipset", "flush", f.Set4)
	_ = f.Exec.Run(ctx, "ipset", "flush", f.Set6)
	return nil
}

func (f *Firewall) Remove(ctx context.Context) error {
	if f.DryRun {
		return nil
	}
	for _, p := range f.Ports {
		for _, proto := range []string{"tcp", "udp"} {
			for _, parent := range hookParents {
				_ = f.Exec.Run(ctx, "iptables", "-D", parent, "-p", proto, "--dport", p, "-j", f.Chain)
				_ = f.Exec.Run(ctx, "ip6tables", "-D", parent, "-p", proto, "--dport", p, "-j", f.Chain)
			}
		}
	}
	f.cleanupHooks(ctx, "iptables", nil)
	f.cleanupHooks(ctx, "ip6tables", nil)
	_ = f.Exec.Run(ctx, "iptables", "-F", f.Chain)
	_ = f.Exec.Run(ctx, "ip6tables", "-F", f.Chain)
	_ = f.Exec.Run(ctx, "iptables", "-X", f.Chain)
	_ = f.Exec.Run(ctx, "ip6tables", "-X", f.Chain)
	_ = f.Exec.Run(ctx, "ipset", "destroy", f.Set4)
	_ = f.Exec.Run(ctx, "ipset", "destroy", f.Set6)
	return nil
}

// target prueft eine IP bzw. ein Netz und liefert das passende Set sowie die
// kanonische Schreibweise. Zonen und /0-Netze werden abgelehnt, damit Rohwerte
// (z.B. aus der Datenbank) weder die restore-Eingabe manipulieren noch eine
// ganze Adressfamilie sperren koennen.
func (f *Firewall) target(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Bits() == 0 || p.Addr().Zone() != "" {
			return "", "", fmt.Errorf("invalid IP/prefix %q", s)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			return f.Set4, p.String(), nil
		}
		return f.Set6, p.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", "", fmt.Errorf("invalid IP/prefix %q", s)
	}
	if a.Is4() {
		return f.Set4, a.String(), nil
	}
	return f.Set6, a.String(), nil
}
