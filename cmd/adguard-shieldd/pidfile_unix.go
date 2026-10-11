//go:build unix

package main

import "syscall"

// O_NOFOLLOW: ein Symlink als letztes Pfadelement führt zu ELOOP.
// O_NONBLOCK: ein untergeschobenes FIFO blockiert das Öffnen nicht.
const pidOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
