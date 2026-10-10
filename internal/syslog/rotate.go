package syslog

import (
	"os"
	"sync"
)

const logFileMode = 0640

// RotatingFile ist ein threadsicherer Append-Writer für die Logdatei. Ist eine
// Maximalgröße gesetzt, wird die Datei beim Überschreiten nach path+".1"
// verschoben (ein altes .1 wird ersetzt) und neu angelegt.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	size     int64
	closed   bool
}

// OpenFile öffnet path zum Anhängen, zunächst ohne Rotation.
func OpenFile(path string) (*RotatingFile, error) {
	r := &RotatingFile{path: path}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// SetMaxBytes aktiviert die Rotation ab n Bytes; n <= 0 deaktiviert sie.
func (r *RotatingFile) SetMaxBytes(n int64) {
	r.mu.Lock()
	r.maxBytes = n
	r.mu.Unlock()
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, logFileMode)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	if st, err := f.Stat(); err == nil {
		r.size = st.Size()
	}
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.maxBytes > 0 && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.maybeRotate(int64(len(p)))
		if r.f == nil {
			return 0, os.ErrClosed
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// maybeRotate prüft die echte Dateigröße (andere Prozesse oder logrotate
// können die Datei verändert haben) und rotiert nur, wenn sie wirklich zu groß ist.
func (r *RotatingFile) maybeRotate(pending int64) {
	if st, err := r.f.Stat(); err == nil {
		r.size = st.Size()
		if r.size == 0 || r.size+pending <= r.maxBytes {
			return
		}
	}
	_ = r.f.Close()
	r.f = nil
	backup := r.path + ".1"
	_ = os.Remove(backup)
	_ = os.Rename(r.path, backup)
	_ = r.open()
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
