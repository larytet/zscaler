// Package ratelimit slows down clients that keep presenting bad credentials (GAP-REQ-04). It counts failures
// per client address and scope; after too many in a window the address is refused for a while, and each
// repeated lockout lasts twice as long, up to a ceiling. The state is in memory and bounded; restarting
// the control plane clears it.
//
// Honest scope: the tokens this product issues are 256 random bits, so guessing one is not the threat this
// addresses. It cuts the noise and the work of scanners and broken scripts, makes a loud attack visible, and
// protects any weaker credential added later. Behind a proxy or a shared address (an office behind one
// NAT), every client has the proxy's address: list that network in Exempt, or one broken script locks
// the office out for the lock time.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Limiter struct {
	Max     int           // failures in Window that cause a lockout; 0 disables the limiter
	Window  time.Duration // how far back failures count
	Lock    time.Duration // the first lockout; each repeat doubles it
	MaxLock time.Duration // ceiling for the doubling
	Exempt  []*net.IPNet  // addresses never limited (trusted networks)
	Now     func() time.Time
	// OnLock is called (once per lockout) with the scope, the address and when the lockout ends.
	OnLock func(scope, ip string, until time.Time, failures int)

	mu      sync.Mutex
	entries map[string]*entry
	locks   []time.Time // when each lockout began, for Recent
	pruned  time.Time   // when the table was last cleaned, so a full table is not scanned on every call
}

type entry struct {
	fails   []time.Time
	until   time.Time
	strikes int // lockouts so far, for the doubling
	last    time.Time
}

const maxEntries = 50000

// New returns a limiter with the usual settings: 10 failures in a minute lock an address for 5 minutes,
// doubling to at most an hour.
func New() *Limiter {
	return &Limiter{Max: 10, Window: time.Minute, Lock: 5 * time.Minute, MaxLock: time.Hour}
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Limiter) exempt(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range l.Exempt {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// Blocked reports whether the address is locked out in the scope now, and for how much longer.
func (l *Limiter) Blocked(scope, ip string) (bool, time.Duration) {
	if l == nil || l.Max <= 0 || l.exempt(ip) {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[scope+"|"+ip]
	if e == nil {
		return false, 0
	}
	if d := e.until.Sub(l.now()); d > 0 {
		return true, d
	}
	return false, 0
}

// Fail records one failed attempt and reports whether the address is now locked out.
func (l *Limiter) Fail(scope, ip string) bool {
	if l == nil || l.Max <= 0 || l.exempt(ip) {
		return false
	}
	now := l.now()
	l.mu.Lock()
	if l.entries == nil {
		l.entries = map[string]*entry{}
	}
	if len(l.entries) >= maxEntries && now.Sub(l.pruned) >= l.Window {
		l.pruned = now
		l.prune(now)
	}
	k := scope + "|" + ip
	e := l.entries[k]
	if e == nil {
		if len(l.entries) >= maxEntries { // still full of live entries: refuse to grow, count nothing new
			l.mu.Unlock()
			return false
		}
		e = &entry{}
		l.entries[k] = e
	}
	if now.Sub(e.last) > 24*time.Hour { // a long quiet spell forgives earlier lockouts
		e.strikes = 0
	}
	e.last = now
	cut := now.Add(-l.Window)
	kept := e.fails[:0]
	for _, t := range e.fails {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	e.fails = append(kept, now)
	locked := false
	var until time.Time
	var n int
	if len(e.fails) >= l.Max && !e.until.After(now) {
		d := l.Lock
		for i := 0; i < e.strikes && d < l.MaxLock; i++ {
			d *= 2
		}
		if d > l.MaxLock {
			d = l.MaxLock
		}
		e.until, e.strikes, e.fails = now.Add(d), e.strikes+1, nil
		l.locks = append(l.locks, now)
		locked, until, n = true, e.until, l.Max
	}
	cb := l.OnLock
	l.mu.Unlock()
	if locked && cb != nil {
		cb(scope, ip, until, n)
	}
	return locked
}

// Recent counts the lockouts that began in the last duration (a number only, no addresses).
func (l *Limiter) Recent(d time.Duration) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := l.now().Add(-d)
	n := 0
	kept := l.locks[:0]
	for _, t := range l.locks {
		if t.After(cut) {
			kept = append(kept, t)
			n++
		}
	}
	l.locks = kept
	return n
}

func (l *Limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if !e.until.After(now) && now.Sub(e.last) > l.Window && (e.strikes == 0 || now.Sub(e.last) > 24*time.Hour) {
			delete(l.entries, k)
		}
	}
}

// ClientIP is the address the connection came from. Headers such as X-Forwarded-For are not believed: any
// client can send them.
func ClientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return h
}

// ParseExempt reads a comma-separated list of addresses and networks ("10.0.0.0/8, 192.168.1.5").
func ParseExempt(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				f += "/32"
			} else if ip != nil {
				f += "/128"
			}
		}
		_, n, err := net.ParseCIDR(f)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
