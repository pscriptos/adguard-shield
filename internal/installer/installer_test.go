package installer

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"adguard-shield/internal/config"
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDefaultConfigMatchesRepoConfig(t *testing.T) {
	repo := readRepoFile(t, "adguard-shield.conf")
	got := sortedKeys(configKeys([]byte(defaultConfig)))
	want := sortedKeys(configKeys([]byte(repo)))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Schluessel weichen ab:\ndefaultConfig: %v\nadguard-shield.conf: %v", got, want)
	}
	if repo != defaultConfig {
		t.Fatal("defaultConfig weicht inhaltlich von adguard-shield.conf ab")
	}
}

func TestDefaultConfigKeysAreKnown(t *testing.T) {
	known := map[string]bool{}
	for _, k := range config.KnownKeys() {
		known[k] = true
	}
	defaults := configKeys([]byte(defaultConfig))
	for _, k := range sortedKeys(defaults) {
		if !known[k] {
			t.Errorf("defaultConfig enthaelt Schluessel %s, den config.Load nicht kennt", k)
		}
	}
	for _, k := range sortedKeys(known) {
		if !defaults[k] {
			t.Errorf("config.Load kennt Schluessel %s, der in defaultConfig fehlt", k)
		}
	}
}

func directives(unit string) []string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func TestServiceUnitMatchesRepoService(t *testing.T) {
	repo := readRepoFile(t, "adguard-shield.service")
	unit := serviceUnit(DefaultInstallDir)
	if got, want := directives(unit), directives(repo); !reflect.DeepEqual(got, want) {
		t.Fatalf("Direktiven weichen ab:\nserviceUnit: %q\nadguard-shield.service: %q", got, want)
	}
	if strings.Contains(unit, "ExecReload") {
		t.Fatal("ExecReload darf nicht gesetzt sein (SIGHUP beendet den Daemon nicht)")
	}
}

func TestServiceUnitUsesInstallDir(t *testing.T) {
	unit := serviceUnit("/srv/shield")
	for _, want := range []string{
		"ExecStart=/srv/shield/adguard-shield -config /srv/shield/adguard-shield.conf run",
		"/var/run /srv/shield/geoip",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("serviceUnit enthaelt %q nicht:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "/opt/adguard-shield") {
		t.Fatalf("serviceUnit enthaelt noch den Standardpfad:\n%s", unit)
	}
}

func TestConfigKeys(t *testing.T) {
	data := []byte("# KOMMENTAR=1\n\nA=1\n  B = \"x\" # inline\n=ohne\nkein-gleich\r\nC=3\r\n")
	got := sortedKeys(configKeys(data))
	want := []string{"A", "B", "C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configKeys = %v, want %v", got, want)
	}
}

func TestConfigBlocksAndBlockKey(t *testing.T) {
	data := []byte("# Kopf\n\n# --- A ---\nA=1\nB=2\n# nur Kommentar am Ende\n")
	blocks := configBlocks(data)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d: %q", len(blocks), blocks)
	}
	if string(blocks[0]) != "# Kopf\n\n# --- A ---\nA=1" {
		t.Fatalf("unexpected first block: %q", blocks[0])
	}
	if string(blocks[1]) != "B=2" {
		t.Fatalf("unexpected second block: %q", blocks[1])
	}
	if k := blockKey(blocks[0]); k != "A" {
		t.Fatalf("blockKey = %q, want A", k)
	}
	if k := blockKey([]byte("# nur\n# Kommentare\n")); k != "" {
		t.Fatalf("blockKey for comment-only block = %q", k)
	}
	if k := blockKey([]byte("  KEY = wert  ")); k != "KEY" {
		t.Fatalf("blockKey trims key: %q", k)
	}
}

func TestMergeConfigAddsMissingKeys(t *testing.T) {
	current := []byte("A=eigener-wert\nC=3\n\n\n")
	defaults := []byte("# Kommentar A\nA=1\n# Kommentar B\nB=2\nC=default\n")
	merged, changed := mergeConfig(current, defaults)
	if !changed {
		t.Fatal("expected change")
	}
	want := "A=eigener-wert\nC=3\n\n# Neue Parameter aus der Go-Version\n# Kommentar B\nB=2\n"
	if string(merged) != want {
		t.Fatalf("merged =\n%q\nwant\n%q", merged, want)
	}
	keys := configKeys(merged)
	if !keys["A"] || !keys["B"] || !keys["C"] {
		t.Fatalf("missing keys after merge: %v", keys)
	}
}

func TestMergeConfigNoChange(t *testing.T) {
	current := []byte("A=x\nB=y\n")
	merged, changed := mergeConfig(current, []byte("A=1\nB=2\n"))
	if changed {
		t.Fatal("expected no change")
	}
	if string(merged) != string(current) {
		t.Fatalf("current config modified: %q", merged)
	}
}

func TestMergeConfigWithDefaultConfigIsIdempotent(t *testing.T) {
	merged, changed := mergeConfig([]byte("ADGUARD_URL=\"http://127.0.0.1:3000\"\n"), []byte(defaultConfig))
	if !changed {
		t.Fatal("expected missing keys to be added")
	}
	if got, want := sortedKeys(configKeys(merged)), sortedKeys(configKeys([]byte(defaultConfig))); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged keys %v, want %v", got, want)
	}
	if _, changed := mergeConfig(merged, []byte(defaultConfig)); changed {
		t.Fatal("second merge must not change anything")
	}
}
