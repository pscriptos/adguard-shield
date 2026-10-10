package syslog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRotatingFileWithoutLimitOnlyAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.log")
	if err := os.WriteFile(path, []byte("alt\n"), 0640); err != nil {
		t.Fatal(err)
	}
	r, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := r.Write([]byte("0123456789\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Close()
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "alt\n") || len(b) != 4+100*11 {
		t.Fatalf("unexpected content length %d", len(b))
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatal("without limit no backup must be created")
	}
}

func TestRotatingFileRotatesAndReplacesBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.log")
	if err := os.WriteFile(path+".1", []byte("sehr alt\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 90), 0640); err != nil {
		t.Fatal(err)
	}
	r, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.SetMaxBytes(100)
	if _, err := r.Write([]byte("0123456789\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("neu\n")); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	backup, _ := os.ReadFile(path + ".1")
	if string(backup) != strings.Repeat("x", 90) {
		t.Fatalf("backup = %q", backup)
	}
	cur, _ := os.ReadFile(path)
	if string(cur) != "0123456789\nneu\n" {
		t.Fatalf("current = %q", cur)
	}
	if _, err := r.Write([]byte("x")); err == nil {
		t.Fatal("write after close must fail")
	}
}

func TestRotatingFileConcurrentWritesKeepLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.log")
	r, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.SetMaxBytes(4096)
	l := New(r, "INFO")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Infof("zeile %d", i)
			}
		}()
	}
	wg.Wait()
	_ = r.Close()
	cur, _ := os.ReadFile(path)
	if len(cur) > 4096+200 {
		t.Fatalf("current log too large after rotation: %d", len(cur))
	}
	for _, f := range []string{path, path + ".1"} {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if !strings.Contains(line, "[INFO] [ADGUARD-SHIELDD] zeile ") {
				t.Fatalf("broken line in %s: %q", f, line)
			}
		}
	}
}
