//go:build !unix

package main

// Auf Nicht-Unix-Systemen (z. B. Windows-Entwicklungsbuilds) gibt es kein
// O_NOFOLLOW; dort bleibt nur die Prüfung auf eine reguläre Datei.
const pidOpenFlags = 0
