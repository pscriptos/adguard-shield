package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestWritePIDCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adguard-shield.pid")
	if err := os.WriteFile(path, []byte("999999999\nalter Inhalt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePID(path); err != nil {
		t.Fatalf("writePID: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(data)), strconv.Itoa(os.Getpid()); got != want {
		t.Fatalf("PID-Datei = %q, want %q", got, want)
	}
}

func TestWritePIDEmptyPath(t *testing.T) {
	if err := writePID(""); err != nil {
		t.Fatalf("writePID(\"\") = %v", err)
	}
}

func TestWritePIDRejectsDirectory(t *testing.T) {
	if err := writePID(t.TempDir()); err == nil {
		t.Fatal("writePID akzeptiert ein Verzeichnis")
	}
}

func TestWritePIDRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlinks/O_NOFOLLOW werden unter Windows nicht geprüft")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "ziel")
	if err := os.WriteFile(target, []byte("unverändert\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "adguard-shield.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePID(link); err == nil {
		t.Fatal("writePID folgt einem Symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unverändert\n" {
		t.Fatalf("Symlink-Ziel wurde verändert: %q", data)
	}
	// Auch ein hängender Symlink darf keine Datei am Ziel anlegen.
	dangling := filepath.Join(dir, "haengend.pid")
	missing := filepath.Join(dir, "fehlt")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	if err := writePID(dangling); err == nil {
		t.Fatal("writePID folgt einem hängenden Symlink")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("Ziel des hängenden Symlinks wurde angelegt: %v", err)
	}
}
