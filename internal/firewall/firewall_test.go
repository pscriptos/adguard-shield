package firewall

import (
	"context"
	"strings"
	"testing"
)

type fakeExec struct {
	calls      []string
	failChecks bool
	missing    map[string]bool
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.missing != nil && f.missing[call] {
		return errFake
	}
	if f.failChecks && len(args) > 0 && args[0] == "-C" {
		return errFake
	}
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

var errFake = fakeErr("missing")

func TestFirewallSetupCreatesSetsAndRules(t *testing.T) {
	ex := &fakeExec{failChecks: true}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"ipset create adguard_shield_v4 hash:net family inet timeout 0 -exist",
		"iptables -I INPUT -p tcp --dport 53 -j ADGUARD_SHIELD",
		"iptables -I ADGUARD_SHIELD -m set --match-set adguard_shield_v4 src -j DROP",
		"ip6tables -I ADGUARD_SHIELD -m set --match-set adguard_shield_v6 src -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing call %q in:\n%s", want, joined)
		}
	}
}

func TestFirewallSetupUsesDockerUserForBridgeMode(t *testing.T) {
	ex := &fakeExec{failChecks: true}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "docker-bridge", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	if !strings.Contains(joined, "iptables -I DOCKER-USER -p udp --dport 53 -j ADGUARD_SHIELD") {
		t.Fatalf("missing docker hook in:\n%s", joined)
	}
	if strings.Contains(joined, "iptables -I INPUT -p udp --dport 53 -j ADGUARD_SHIELD") {
		t.Fatalf("unexpected INPUT hook in docker-bridge mode:\n%s", joined)
	}
}

func TestFirewallSetupHybridUsesInputAndDockerUser(t *testing.T) {
	ex := &fakeExec{failChecks: true}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "hybrid", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"iptables -I INPUT -p tcp --dport 53 -j ADGUARD_SHIELD",
		"iptables -I DOCKER-USER -p tcp --dport 53 -j ADGUARD_SHIELD",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing call %q in:\n%s", want, joined)
		}
	}
}

func TestFirewallSetupRequiresDockerUserForIPv4BridgeMode(t *testing.T) {
	ex := &fakeExec{missing: map[string]bool{"iptables -n -L DOCKER-USER": true}}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "docker-bridge", false)
	if err := fw.Setup(context.Background()); err == nil || !strings.Contains(err.Error(), "DOCKER-USER") {
		t.Fatalf("expected DOCKER-USER error, got %v", err)
	}
}

func TestFirewallSetupSkipsMissingIPv6DockerUser(t *testing.T) {
	ex := &fakeExec{
		failChecks: true,
		missing:    map[string]bool{"ip6tables -n -L DOCKER-USER": true},
	}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "docker-bridge", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	if strings.Contains(joined, "ip6tables -I DOCKER-USER") {
		t.Fatalf("unexpected IPv6 docker hook with missing DOCKER-USER:\n%s", joined)
	}
}

func TestFirewallSetupRejectsUnknownMode(t *testing.T) {
	fw := New(&fakeExec{}, "ADGUARD_SHIELD", []string{"53"}, "surprise", false)
	err := fw.Setup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFirewallAddChoosesFamily(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Add(context.Background(), "2001:db8::1", 30); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ex.calls, "\n")
	if !strings.Contains(got, "ipset add adguard_shield_v6 2001:db8::1 -exist timeout 30") {
		t.Fatalf("unexpected calls:\n%s", got)
	}
}

func TestFirewallRemoveDeletesAllKnownHooks(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"iptables -D INPUT -p tcp --dport 53 -j ADGUARD_SHIELD",
		"iptables -D DOCKER-USER -p tcp --dport 53 -j ADGUARD_SHIELD",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing cleanup call %q in:\n%s", want, joined)
		}
	}
}
