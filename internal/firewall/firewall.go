package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

type Executor interface {
	Run(ctx context.Context, name string, args ...string) error
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

type Firewall struct {
	Exec   Executor
	Chain  string
	Ports  []string
	Mode   string
	DryRun bool
	Set4   string
	Set6   string
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
	set, err := f.setFor(ip)
	if err != nil {
		return err
	}
	args := []string{"add", set, ip, "-exist"}
	if timeout > 0 {
		args = append(args, "timeout", strconv.FormatInt(timeout, 10))
	}
	return f.Exec.Run(ctx, "ipset", args...)
}

func (f *Firewall) Del(ctx context.Context, ip string) error {
	if f.DryRun {
		return nil
	}
	set, err := f.setFor(ip)
	if err != nil {
		return err
	}
	_ = f.Exec.Run(ctx, "ipset", "del", set, ip)
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
			for _, parent := range []string{"INPUT", "DOCKER-USER"} {
				_ = f.Exec.Run(ctx, "iptables", "-D", parent, "-p", proto, "--dport", p, "-j", f.Chain)
				_ = f.Exec.Run(ctx, "ip6tables", "-D", parent, "-p", proto, "--dport", p, "-j", f.Chain)
			}
		}
	}
	_ = f.Exec.Run(ctx, "iptables", "-F", f.Chain)
	_ = f.Exec.Run(ctx, "ip6tables", "-F", f.Chain)
	_ = f.Exec.Run(ctx, "iptables", "-X", f.Chain)
	_ = f.Exec.Run(ctx, "ip6tables", "-X", f.Chain)
	_ = f.Exec.Run(ctx, "ipset", "destroy", f.Set4)
	_ = f.Exec.Run(ctx, "ipset", "destroy", f.Set6)
	return nil
}

func (f *Firewall) setFor(s string) (string, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4() {
			return f.Set4, nil
		}
		return f.Set6, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP/prefix %q", s)
	}
	if a.Is4() {
		return f.Set4, nil
	}
	return f.Set6, nil
}
