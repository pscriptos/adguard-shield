package main

import (
	"fmt"
	"os"
	"strconv"
)

// writePID schreibt die PID des laufenden Prozesses nach path. Da der Daemon
// als root läuft und PID_FILE konfigurierbar ist, folgt das Öffnen keinem
// Symlink (O_NOFOLLOW, siehe pidfile_unix.go) und das Ziel muss eine reguläre
// Datei sein. Die Datei ist bewusst für alle lesbar (0644).
func writePID(path string) error {
	if path == "" {
		return nil
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("PID-Datei %s ist keine reguläre Datei (%s)", path, fi.Mode().Type())
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|pidOpenFlags, 0644)
	if err != nil {
		return fmt.Errorf("PID-Datei %s kann nicht geschrieben werden: %w", path, err)
	}
	// Erneut am geöffneten Handle prüfen: Zwischen Lstat und OpenFile könnte
	// die Datei ersetzt worden sein.
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		if err == nil {
			err = fmt.Errorf("keine reguläre Datei (%s)", fi.Mode().Type())
		}
		return fmt.Errorf("PID-Datei %s: %w", path, err)
	}
	if _, err := f.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("PID-Datei %s: %w", path, err)
	}
	return f.Close()
}
