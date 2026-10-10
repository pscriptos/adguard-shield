package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	authRealm             = "AdGuard Shield"
	authMaxFailures       = 10
	authGlobalMaxFailures = 100
	authWindow            = time.Minute
	authMaxTracked        = 10000
)

type authenticator struct {
	user, pass [sha256.Size]byte
	log        Logger
	now        func() time.Time
	maxTracked int

	mu sync.Mutex
	// fails ist nach clientKey geschlüsselt (IPv4-Adresse bzw. IPv6-/64).
	fails  map[string]*authFailures
	global authFailures
	// fullUntil: bis dahin ist die Tabelle voll mit gesperrten Clients.
	fullUntil time.Time
}

type authFailures struct {
	start  time.Time
	count  int
	logged bool
}

func (f *authFailures) expired(now time.Time) bool { return now.Sub(f.start) >= authWindow }

func newAuthenticator(user, pass string, log Logger) *authenticator {
	return &authenticator{
		user: sha256.Sum256([]byte(user)), pass: sha256.Sum256([]byte(pass)),
		log: log, now: time.Now, maxTracked: authMaxTracked, fails: map[string]*authFailures{},
	}
}

// check prüft Basic Auth. Nach authMaxFailures Fehlversuchen eines Clients
// bzw. authGlobalMaxFailures Fehlversuchen insgesamt innerhalb von authWindow
// werden alle Anfragen bis zum Ende des Fensters mit 429 abgewiesen – auch mit
// gültigen Zugangsdaten, sonst ließe sich das Passwort trotz Sperre weiter raten.
// Hinter einem Reverse-Proxy (gemeinsame Client-IP) können Fehlversuche Dritter
// daher alle Nutzer bis zu einem Fenster lang aussperren.
func (a *authenticator) check(w http.ResponseWriter, r *http.Request) bool {
	key := clientKey(r)
	if wait := a.blockedFor(key); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		http.Error(w, "Zu viele fehlgeschlagene Anmeldungen, bitte später erneut versuchen", http.StatusTooManyRequests)
		return false
	}
	user, pass, ok := r.BasicAuth()
	if ok && a.match(user, pass) {
		return true
	}
	if ok {
		a.fail(key)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`", charset="UTF-8"`)
	http.Error(w, "Anmeldung erforderlich", http.StatusUnauthorized)
	return false
}

func (a *authenticator) match(user, pass string) bool {
	u := sha256.Sum256([]byte(user))
	p := sha256.Sum256([]byte(pass))
	okUser := subtle.ConstantTimeCompare(u[:], a.user[:])
	okPass := subtle.ConstantTimeCompare(p[:], a.pass[:])
	return okUser&okPass == 1
}

func (a *authenticator) blockedFor(key string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.global.count >= authGlobalMaxFailures {
		if left := authWindow - now.Sub(a.global.start); left > 0 {
			return left
		}
	}
	f := a.fails[key]
	if f == nil {
		if len(a.fails) >= a.maxTracked {
			return a.spaceLocked(now)
		}
		return 0
	}
	left := authWindow - now.Sub(f.start)
	if left <= 0 {
		delete(a.fails, key)
		return 0
	}
	if f.count >= authMaxFailures {
		return left
	}
	return 0
}

// spaceLocked versucht Platz für einen neuen Client zu schaffen und liefert
// die Wartezeit, falls die Tabelle nur gesperrte Clients enthält.
func (a *authenticator) spaceLocked(now time.Time) time.Duration {
	if now.Before(a.fullUntil) {
		return a.fullUntil.Sub(now)
	}
	a.pruneLocked(now)
	if len(a.fails) < a.maxTracked {
		return 0
	}
	var first time.Time
	for _, f := range a.fails {
		if end := f.start.Add(authWindow); first.IsZero() || end.Before(first) {
			first = end
		}
	}
	a.fullUntil = first
	return max(first.Sub(now), time.Second)
}

func (a *authenticator) fail(key string) {
	a.mu.Lock()
	now := a.now()
	if a.global.expired(now) {
		a.global = authFailures{start: now}
	}
	a.global.count++
	globalCount := a.global.count
	globalFirst := globalCount == authGlobalMaxFailures && !a.global.logged
	if globalFirst {
		a.global.logged = true
	}
	f := a.fails[key]
	if f == nil || f.expired(now) {
		if f == nil && len(a.fails) >= a.maxTracked && a.spaceLocked(now) > 0 {
			a.mu.Unlock()
			return
		}
		f = &authFailures{start: now}
		a.fails[key] = f
	}
	f.count++
	first := !f.logged
	f.logged = true
	count := f.count
	a.mu.Unlock()
	if globalFirst {
		a.log.Warnf("Web-Statusseite: %d fehlgeschlagene Anmeldungen insgesamt, Anfragen ohne gültige Zugangsdaten werden für bis zu %s abgewiesen", globalCount, authWindow)
	}
	// Höchstens zwei Logzeilen pro Client und Fenster.
	switch {
	case count == authMaxFailures:
		a.log.Warnf("Web-Statusseite: %d fehlgeschlagene Anmeldungen von %s, weitere Versuche werden für bis zu %s abgewiesen", count, key, authWindow)
	case first:
		a.log.Warnf("Web-Statusseite: fehlgeschlagene Anmeldung von %s", key)
	}
}

// pruneLocked entfernt abgelaufene und, falls nötig, nicht gesperrte
// Einträge. Gesperrte Clients bleiben immer erhalten.
func (a *authenticator) pruneLocked(now time.Time) {
	for k, f := range a.fails {
		if f.expired(now) {
			delete(a.fails, k)
		}
	}
	if len(a.fails) < a.maxTracked {
		return
	}
	for k, f := range a.fails {
		if f.count < authMaxFailures {
			delete(a.fails, k)
		}
	}
}

// clientKey nutzt bewusst nur RemoteAddr; X-Forwarded-For ist fälschbar.
// IPv6-Clients werden pro /64 zusammengefasst, da ein Anschluss meist ein
// ganzes /64 erhält.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
