package firewall

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeExec struct {
	calls      []string
	failChecks bool
	missing    map[string]bool
	outputs    map[string]string
	inputs     []string
	inputErr   error
	failAdds   map[string]bool
}

func (f *fakeExec) RunInput(_ context.Context, input string, name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.inputs = append(f.inputs, input)
	return f.inputErr
}

func (f *fakeExec) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	out, ok := f.outputs[call]
	if !ok {
		return nil, errFake
	}
	return []byte(out), nil
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.missing != nil && f.missing[call] {
		return errFake
	}
	if len(args) > 2 && args[0] == "add" && f.failAdds[args[2]] {
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

var _ Executor = OSExecutor{}

func TestAddBatchSplitsFamiliesAndTimeouts(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	err := fw.AddBatch(context.Background(), []Entry{
		{IP: "203.0.113.7", Timeout: 60},
		{IP: "2001:db8::1"},
		{IP: "198.51.100.0/24"},
		{IP: "2001:db8:1::/48", Timeout: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.inputs) != 1 {
		t.Fatalf("expected one restore call, got %d", len(ex.inputs))
	}
	if ex.calls[0] != "ipset restore -exist" {
		t.Fatalf("unexpected call %q", ex.calls[0])
	}
	want := "add adguard_shield_v4 203.0.113.7 timeout 60\n" +
		"add adguard_shield_v6 2001:db8::1\n" +
		"add adguard_shield_v4 198.51.100.0/24\n" +
		"add adguard_shield_v6 2001:db8:1::/48 timeout 5\n"
	if ex.inputs[0] != want {
		t.Fatalf("restore input:\n%s\nwant:\n%s", ex.inputs[0], want)
	}
}

func TestAddBatchSkipsInvalidEntries(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	err := fw.AddBatch(context.Background(), []Entry{
		{IP: "203.0.113.7"},
		{IP: "not-an-ip"},
		{IP: "1.2.3.4\nflush adguard_shield_v4"},
		{IP: "10.0.0.0/33"},
	})
	if err == nil || !strings.Contains(err.Error(), "skipped 3 invalid") || !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ex.inputs) != 1 || ex.inputs[0] != "add adguard_shield_v4 203.0.113.7\n" {
		t.Fatalf("valid entry must still be added, inputs=%q", ex.inputs)
	}
}

func TestAddBatchOnlyInvalidRunsNothing(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.AddBatch(context.Background(), []Entry{{IP: "x"}}); err == nil {
		t.Fatal("expected error")
	}
	if len(ex.calls) != 0 {
		t.Fatalf("unexpected calls: %v", ex.calls)
	}
	if err := fw.AddBatch(context.Background(), nil); err != nil || len(ex.calls) != 0 {
		t.Fatalf("empty batch: err=%v calls=%v", err, ex.calls)
	}
}

func TestAddBatchDryRun(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", true)
	if err := fw.AddBatch(context.Background(), []Entry{{IP: "203.0.113.7"}}); err != nil {
		t.Fatal(err)
	}
	if len(ex.calls) != 0 {
		t.Fatalf("dry-run must not execute: %v", ex.calls)
	}
}

func TestAddBatchChunksAndFallsBackPerEntry(t *testing.T) {
	ex := &fakeExec{inputErr: errFake}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	fw.batchSize = 2
	var entries []Entry
	for i := 1; i <= 5; i++ {
		entries = append(entries, Entry{IP: fmt.Sprintf("192.0.2.%d", i)})
	}
	if err := fw.AddBatch(context.Background(), entries); err != nil {
		t.Fatalf("successful per-entry fallback must not report an error: %v", err)
	}
	if len(ex.inputs) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(ex.inputs))
	}
	if strings.Count(ex.inputs[0], "\n") != 2 || strings.Count(ex.inputs[2], "\n") != 1 {
		t.Fatalf("unexpected chunking: %q", ex.inputs)
	}
	joined := strings.Join(ex.calls, "\n")
	for i := 1; i <= 5; i++ {
		want := fmt.Sprintf("ipset add adguard_shield_v4 192.0.2.%d -exist", i)
		if !strings.Contains(joined, want) {
			t.Fatalf("missing fallback %q in:\n%s", want, joined)
		}
	}
}

func TestAddBatchFallbackAppliesGoodEntriesAndReportsBadOnes(t *testing.T) {
	ex := &fakeExec{inputErr: errFake, failAdds: map[string]bool{"192.0.2.2": true}}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	err := fw.AddBatch(context.Background(), []Entry{
		{IP: "192.0.2.1", Timeout: 60},
		{IP: "192.0.2.2"},
		{IP: "2001:db8::1"},
	})
	if err == nil || !strings.Contains(err.Error(), "entries 1-3") || !strings.Contains(err.Error(), "1 of 3 entries failed") || !strings.Contains(err.Error(), "192.0.2.2") {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"ipset add adguard_shield_v4 192.0.2.1 -exist timeout 60",
		"ipset add adguard_shield_v6 2001:db8::1 -exist",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("good entry %q not applied:\n%s", want, joined)
		}
	}
}

func TestAddBatchFallbackCapsListedFailures(t *testing.T) {
	ex := &fakeExec{inputErr: errFake, failAdds: map[string]bool{}}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	var entries []Entry
	for i := 1; i <= 15; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		ex.failAdds[ip] = true
		entries = append(entries, Entry{IP: ip})
	}
	err := fw.AddBatch(context.Background(), entries)
	if err == nil || !strings.Contains(err.Error(), "15 of 15") || !strings.Contains(err.Error(), "192.0.2.10") || strings.Contains(err.Error(), "192.0.2.11") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddBatchFallbackStopsOnCancel(t *testing.T) {
	ex := &fakeExec{inputErr: errFake}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := fw.AddBatch(ctx, []Entry{{IP: "192.0.2.1"}, {IP: "192.0.2.2"}})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(strings.Join(ex.calls, "\n"), "ipset add") {
		t.Fatalf("cancelled fallback must not add: %v", ex.calls)
	}
}

func TestTimeoutClamped(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Add(context.Background(), "192.0.2.1", 1<<40); err != nil {
		t.Fatal(err)
	}
	if err := fw.AddBatch(context.Background(), []Entry{{IP: "192.0.2.2", Timeout: 1 << 40}, {IP: "192.0.2.3", Timeout: maxIPSetTimeout}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ex.calls, "\n"), "ipset add adguard_shield_v4 192.0.2.1 -exist timeout 0") {
		t.Fatalf("Add timeout not clamped: %v", ex.calls)
	}
	want := "add adguard_shield_v4 192.0.2.2 timeout 0\nadd adguard_shield_v4 192.0.2.3 timeout 2147483\n"
	if len(ex.inputs) != 1 || ex.inputs[0] != want {
		t.Fatalf("AddBatch timeout not clamped: %q", ex.inputs)
	}
}

func TestTargetRejectsZonesAndZeroPrefixes(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	bad := []string{"fe80::1%eth0", "fe80::1%eth0\nflush adguard_shield_v6", "fe80::1%a b", "0.0.0.0/0", "::/0", "10.0.0.1/0", "1.2.3.4 5.6.7.8"}
	for _, ip := range bad {
		if err := fw.Add(context.Background(), ip, 0); err == nil {
			t.Errorf("Add(%q) must fail", ip)
		}
	}
	if len(ex.calls) != 0 {
		t.Fatalf("invalid entries must not execute anything: %v", ex.calls)
	}
	err := fw.AddBatch(context.Background(), append(entriesOf(bad), Entry{IP: "192.0.2.1"}))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("skipped %d invalid", len(bad))) {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ex.inputs) != 1 || ex.inputs[0] != "add adguard_shield_v4 192.0.2.1\n" {
		t.Fatalf("unexpected restore input: %q", ex.inputs)
	}
}

func TestTargetEmitsCanonicalForm(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	err := fw.AddBatch(context.Background(), []Entry{
		{IP: " 10.1.2.3/8 "},
		{IP: "2001:0DB8:0000::0001"},
		{IP: "2001:db8::1:2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "add adguard_shield_v4 10.0.0.0/8\nadd adguard_shield_v6 2001:db8::1\nadd adguard_shield_v6 2001:db8::/32\n"
	if ex.inputs[0] != want {
		t.Fatalf("restore input:\n%s\nwant:\n%s", ex.inputs[0], want)
	}
	if err := fw.Del(context.Background(), "2001:0DB8::0001"); err != nil {
		t.Fatal(err)
	}
	if last := ex.calls[len(ex.calls)-1]; last != "ipset del adguard_shield_v6 2001:db8::1" {
		t.Fatalf("Del must use canonical form: %q", last)
	}
}

func entriesOf(ips []string) []Entry {
	out := make([]Entry, 0, len(ips))
	for _, ip := range ips {
		out = append(out, Entry{IP: ip})
	}
	return out
}

func TestAddBatchDefaultChunkSize(t *testing.T) {
	ex := &fakeExec{}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	entries := make([]Entry, defaultBatchSize+1)
	for i := range entries {
		entries[i] = Entry{IP: "192.0.2.1"}
	}
	if err := fw.AddBatch(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
	if len(ex.inputs) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(ex.inputs))
	}
}

const inputRules = `-P INPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ADGUARD_SHIELD
-A INPUT -p udp -m udp --dport 53 -j ADGUARD_SHIELD
-A INPUT -p udp -m udp --dport 5353 -j ADGUARD_SHIELD
-A INPUT -s 192.0.2.0/24 -m comment --comment "custom shield hook" -j ADGUARD_SHIELD
-A INPUT -i eth1 -p udp -m udp --dport 5353 -j ADGUARD_SHIELD
-A INPUT -p tcp -m tcp --dport 53 -j ADGUARD_SHIELD_OTHER
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
`

const dockerRules = `-N DOCKER-USER
-A DOCKER-USER -p tcp -m tcp --dport 53 -j ADGUARD_SHIELD
-A DOCKER-USER -p udp -m udp --dport 53 -j ADGUARD_SHIELD
-A DOCKER-USER -j RETURN
`

func hookOutputs() map[string]string {
	return map[string]string{
		"iptables -S INPUT":        inputRules,
		"iptables -S DOCKER-USER":  dockerRules,
		"ip6tables -S INPUT":       "-P INPUT ACCEPT\n-A INPUT -p udp -m udp --dport 853 -j ADGUARD_SHIELD\n",
		"ip6tables -S DOCKER-USER": "",
	}
}

func TestSetupRemovesStaleHooks(t *testing.T) {
	ex := &fakeExec{outputs: hookOutputs()}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"iptables -D INPUT -p udp -m udp --dport 5353 -j ADGUARD_SHIELD",
		"iptables -D DOCKER-USER -p tcp -m tcp --dport 53 -j ADGUARD_SHIELD",
		"iptables -D DOCKER-USER -p udp -m udp --dport 53 -j ADGUARD_SHIELD",
		"ip6tables -D INPUT -p udp -m udp --dport 853 -j ADGUARD_SHIELD",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing cleanup %q in:\n%s", want, joined)
		}
	}
	for _, unwanted := range []string{
		"iptables -D INPUT -p tcp -m tcp --dport 53 -j ADGUARD_SHIELD",
		"iptables -D INPUT -p udp -m udp --dport 53 -j ADGUARD_SHIELD",
		"ADGUARD_SHIELD_OTHER",
		"-D INPUT -i lo",
		"-D DOCKER-USER -j RETURN",
		"-D INPUT -s 192.0.2.0/24",
		"-D INPUT -i eth1",
	} {
		if strings.Contains(joined, unwanted) {
			t.Fatalf("unexpected call containing %q in:\n%s", unwanted, joined)
		}
	}
}

func TestSetupHybridKeepsDockerHooks(t *testing.T) {
	ex := &fakeExec{outputs: hookOutputs()}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "hybrid", false)
	if err := fw.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	if strings.Contains(joined, "-D DOCKER-USER") {
		t.Fatalf("hybrid mode must keep DOCKER-USER hooks:\n%s", joined)
	}
	if !strings.Contains(joined, "iptables -D INPUT -p udp -m udp --dport 5353 -j ADGUARD_SHIELD") {
		t.Fatalf("old port hook not removed:\n%s", joined)
	}
}

func TestRemoveDeletesListedHooks(t *testing.T) {
	ex := &fakeExec{outputs: hookOutputs()}
	fw := New(ex, "ADGUARD_SHIELD", []string{"53"}, "host", false)
	if err := fw.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	var deletes []string
	for _, c := range ex.calls {
		if strings.Contains(c, " -D ") && strings.Contains(c, " -m ") {
			deletes = append(deletes, c)
		}
	}
	if len(deletes) != 8 {
		t.Fatalf("expected 8 listed hook deletions, got %d:\n%s", len(deletes), strings.Join(deletes, "\n"))
	}
	joined := strings.Join(ex.calls, "\n")
	if strings.Contains(joined, "ADGUARD_SHIELD_OTHER") || strings.Contains(joined, "-j ACCEPT") {
		t.Fatalf("foreign rule touched:\n%s", joined)
	}
	for _, want := range []string{"iptables -D INPUT -s 192.0.2.0/24", "iptables -D INPUT -i eth1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Remove must delete every jump to the chain, missing %q:\n%s", want, joined)
		}
	}
}

func TestSplitRuleHandlesQuotes(t *testing.T) {
	got := splitRule(`-A INPUT -m comment --comment "a \"b\" c" -j X`)
	want := []string{"-A", "INPUT", "-m", "comment", "--comment", `a "b" c`, "-j", "X"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}
