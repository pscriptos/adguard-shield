package daemon

import (
	"context"
	"sync"
	"time"
)

const (
	notifyQueueSize    = 256
	notifyJobTimeout   = 30 * time.Second
	notifyDrainTimeout = 10 * time.Second
)

type notifyJob func(ctx context.Context)

// notifier arbeitet Benachrichtigungen im Daemon-Betrieb asynchron ab. Ohne
// laufenden Worker (CLI-Befehle) werden Jobs synchron ausgeführt.
type notifier struct {
	mu      sync.RWMutex
	queue   chan notifyJob
	running bool
	stopped bool
	done    chan struct{}
}

func (d *Daemon) startNotifier() {
	n := &d.notify
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.running {
		return
	}
	size := d.notifyQueueSize
	if size <= 0 {
		size = notifyQueueSize
	}
	n.queue = make(chan notifyJob, size)
	n.done = make(chan struct{})
	n.running = true
	n.stopped = false
	go func(q chan notifyJob, done chan struct{}) {
		defer close(done)
		for job := range q {
			ctx, cancel := context.WithTimeout(context.Background(), notifyJobTimeout)
			job(ctx)
			cancel()
		}
	}(n.queue, n.done)
}

// stopNotifier nimmt keine neuen Jobs mehr an und wartet höchstens timeout
// darauf, dass die Warteschlange abgearbeitet ist.
func (d *Daemon) stopNotifier(timeout time.Duration) bool {
	n := &d.notify
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return true
	}
	n.running = false
	n.stopped = true
	pending := len(n.queue)
	close(n.queue)
	done := n.done
	n.mu.Unlock()
	if pending > 0 {
		d.info("Warte auf %d ausstehende Benachrichtigungen", pending)
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		d.warn("Benachrichtigungs-Warteschlange nicht vollständig abgearbeitet (Timeout %s)", timeout)
		return false
	}
}

func (d *Daemon) enqueueNotification(what string, job notifyJob) {
	n := &d.notify
	n.mu.RLock()
	if n.running {
		select {
		case n.queue <- job:
		default:
			d.warn("Benachrichtigungs-Warteschlange voll, verwerfe %s", what)
		}
		n.mu.RUnlock()
		return
	}
	stopped := n.stopped
	n.mu.RUnlock()
	if stopped {
		d.warn("Dienst wird beendet, verwerfe Benachrichtigung %s", what)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), notifyJobTimeout)
	defer cancel()
	job(ctx)
}
