package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func (d *Daemon) SaveFirewallRules(ctx context.Context) error {
	if err := os.MkdirAll(d.Config.StateDir, 0755); err != nil {
		return err
	}
	if err := saveCommand(ctx, filepath.Join(d.Config.StateDir, "iptables-rules.v4"), "iptables-save"); err != nil {
		return err
	}
	return saveCommand(ctx, filepath.Join(d.Config.StateDir, "iptables-rules.v6"), "ip6tables-save")
}

func saveCommand(ctx context.Context, path, name string) error {
	out, err := exec.CommandContext(ctx, name).Output()
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0644)
}
