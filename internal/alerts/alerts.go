// Package alerts turns decision and event records into plain-language alerts
// with one recommended action each (DESIGN.md D5.3, SMB-003).
package alerts

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

const (
	DenyThreshold = 10
	DenyWindow    = 10 * time.Minute
	OfflineAfter  = 2 * time.Minute
)

type Alert struct {
	ID      int        `json:"id"`
	Tenant  string     `json:"tenant"`
	Kind    string     `json:"kind"` // repeated-denies | connector-offline | posture-failed
	Key     string     `json:"key"`
	User    string     `json:"user,omitempty"`
	Message string     `json:"message"`
	Action  string     `json:"recommended_action"`
	Opened  time.Time  `json:"opened"`
	Closed  *time.Time `json:"closed,omitempty"`
}

type Engine struct {
	Now func() time.Time
	// Name turns a subject into something a person recognises (email). Optional.
	Name func(tenant, subject string) string
	// OnOpen is called (in its own goroutine) when a new alert opens.
	OnOpen func(Alert)

	mu      sync.Mutex
	next    int
	alerts  []*Alert
	open    map[string]*Alert // by kind|key
	denies  map[string][]time.Time
	posture map[string]bool // last known pass state per device
	conns   map[string]*connState
}

type connState struct {
	tenant, group, name string
	connected           bool
	since               time.Time
}

func New() *Engine {
	return &Engine{open: map[string]*Alert{}, denies: map[string][]time.Time{}, posture: map[string]bool{}, conns: map[string]*connState{}}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) who(tenant, subject string) string {
	if e.Name != nil {
		if n := e.Name(tenant, subject); n != "" {
			return n
		}
	}
	return subject
}

// openAlert creates the alert unless one with the same kind and key is open.
func (e *Engine) openAlert(tenant, kind, key, msg, action string, user ...string) *Alert {
	k := kind + "|" + tenant + "|" + key
	if a, ok := e.open[k]; ok {
		return a
	}
	e.next++
	a := &Alert{ID: e.next, Tenant: tenant, Kind: kind, Key: key, Message: msg, Action: action, Opened: e.now()}
	if len(user) > 0 {
		a.User = user[0]
	}
	e.alerts = append(e.alerts, a)
	e.open[k] = a
	if e.OnOpen != nil {
		cp := *a
		go e.OnOpen(cp)
	}
	return a
}

func (e *Engine) closeAlert(tenant, kind, key string) {
	k := kind + "|" + tenant + "|" + key
	if a, ok := e.open[k]; ok {
		t := e.now()
		a.Closed = &t
		delete(e.open, k)
	}
}

// Ingest handles one record from an enforcement node.
func (e *Engine) Ingest(r broker.Record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch r.Kind {
	case "private":
		if r.Action == "deny" && r.Event == "open" {
			e.onDeny(r)
		}
	case "posture":
		e.onPosture(r)
	case "connector":
		e.onConnector(r)
	}
}

func (e *Engine) onDeny(r broker.Record) {
	// "unknown-app" and bad-target probes also count: repeated blocked tries are worth a look.
	key := r.User + "|" + r.App
	now := e.now()
	cut := now.Add(-DenyWindow)
	ts := e.denies[r.Tenant+"|"+key]
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.denies[r.Tenant+"|"+key] = kept
	if len(kept) >= DenyThreshold {
		rule := r.Rule
		if rule == "" {
			rule = "the default deny"
		}
		e.openAlert(r.Tenant, "repeated-denies", key,
			fmt.Sprintf("%s was blocked %d times from %s in the last %d minutes", e.who(r.Tenant, r.User), len(kept), r.App, int(DenyWindow.Minutes())),
			fmt.Sprintf("Check whether %s should have access (rule: %s), or contact them.", e.who(r.Tenant, r.User), rule), r.User)
	}
}

func (e *Engine) onPosture(r broker.Record) {
	key := r.Tenant + "|" + r.Device
	pass := r.Action == "pass"
	was, seen := e.posture[key]
	e.posture[key] = pass
	if pass {
		e.closeAlert(r.Tenant, "posture-failed", r.Device)
		return
	}
	if seen && was { // pass -> fail is the interesting transition
		e.openAlert(r.Tenant, "posture-failed", r.Device,
			fmt.Sprintf("%s's device %s stopped meeting the security baseline: %s", e.who(r.Tenant, r.User), r.Device, r.Reason),
			fmt.Sprintf("Ask %s to fix it (for example turn disk encryption or the firewall back on). Access to protected apps is blocked until then.", e.who(r.Tenant, r.User)), r.User)
	}
}

func (e *Engine) onConnector(r broker.Record) {
	key := r.Tenant + "|" + r.App + "|" + r.Device
	c, ok := e.conns[key]
	if !ok {
		c = &connState{tenant: r.Tenant, group: r.App, name: r.Device}
		e.conns[key] = c
	}
	c.connected = r.Event == "connected"
	c.since = e.now()
	if c.connected {
		e.closeAlert(r.Tenant, "connector-offline", r.App+"|"+r.Device)
	}
}

// Tick opens alerts for connectors that have been offline long enough.
func (e *Engine) Tick() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	for _, c := range e.conns {
		if !c.connected && now.Sub(c.since) >= OfflineAfter {
			e.openAlert(c.tenant, "connector-offline", c.group+"|"+c.name,
				fmt.Sprintf("The connector %q for site %q is offline", c.name, c.group),
				"Check that the connector host is powered on and can reach the internet. Apps behind it are unavailable.")
		}
	}
}

// List returns a tenant's alerts, newest first.
func (e *Engine) List(tenant string, openOnly bool) []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []Alert{}
	for _, a := range e.alerts {
		if a.Tenant == tenant && (!openOnly || a.Closed == nil) {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// EraseUser removes the alerts about a person, and the counts of their refusals, and returns how many
// alerts it removed. Alerts name the person in their text, so they are removed, not rewritten.
func (e *Engine) EraseUser(tenant string, ids []string) int {
	set := map[string]bool{}
	for _, id := range ids {
		set[strings.ToLower(id)] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	kept := e.alerts[:0]
	for _, a := range e.alerts {
		if a.Tenant == tenant && a.User != "" && set[strings.ToLower(a.User)] {
			n++
			continue
		}
		kept = append(kept, a)
	}
	e.alerts = kept
	for k, a := range e.open {
		if a.Tenant == tenant && a.User != "" && set[strings.ToLower(a.User)] {
			delete(e.open, k)
		}
	}
	for k := range e.denies {
		for id := range set {
			if strings.HasPrefix(strings.ToLower(k), tenant+"|"+id+"|") {
				delete(e.denies, k)
			}
		}
	}
	return n
}
