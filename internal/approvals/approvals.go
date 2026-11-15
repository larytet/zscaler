// Package approvals tracks just-in-time access requests (ZPA-027). A request
// is created when a require_approval rule blocks someone; an admin approves it
// for a limited time or denies it.
package approvals

import (
	"errors"
	"sort"
	"sync"
	"time"
)

type State string

const (
	Pending  State = "pending"
	Approved State = "approved"
	Denied   State = "denied"
)

type Request struct {
	ID        int       `json:"id"`
	Tenant    string    `json:"tenant"`
	User      string    `json:"user"`
	App       string    `json:"app"`
	Rule      string    `json:"rule"`
	Requested time.Time `json:"requested"`
	Attempts  int       `json:"attempts"`
	State     State     `json:"state"`
	DecidedBy string    `json:"decided_by,omitempty"`
	Decided   time.Time `json:"decided,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

var (
	ErrNotFound = errors.New("approvals: not found")
	ErrDecided  = errors.New("approvals: already decided")
)

type Store struct {
	Max int // per tenant, default 1000

	mu   sync.Mutex
	next int
	byT  map[string][]*Request
}

func New() *Store { return &Store{byT: map[string][]*Request{}} }

// Add records a request, or counts another attempt on the pending one for the
// same user and app. It reports whether a new request was created.
func (s *Store) Add(tenant, user, app, rule string, now time.Time) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.byT[tenant] {
		if r.State == Pending && r.User == user && r.App == app {
			r.Attempts++
			return *r, false
		}
	}
	s.next++
	r := &Request{ID: s.next, Tenant: tenant, User: user, App: app, Rule: rule, Requested: now, Attempts: 1, State: Pending}
	max := s.Max
	if max == 0 {
		max = 1000
	}
	l := append(s.byT[tenant], r)
	if len(l) > max { // drop the oldest decided requests first, never a pending one
		for i, x := range l {
			if x.State != Pending {
				l = append(l[:i], l[i+1:]...)
				break
			}
		}
	}
	s.byT[tenant] = l
	return *r, true
}

// List returns a tenant's requests, newest first; state "" means all.
func (s *Store) List(tenant string, state State) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Request{}
	for _, r := range s.byT[tenant] {
		if state == "" || r.State == state {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// Decide approves or denies a pending request of the given tenant.
func (s *Store) Decide(tenant string, id int, st State, by string, until, now time.Time) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.byT[tenant] { // scoped by tenant: another tenant's id is simply not found
		if r.ID == id {
			if r.State != Pending {
				return *r, ErrDecided
			}
			r.State, r.DecidedBy, r.Decided, r.Until = st, by, now, until
			return *r, nil
		}
	}
	return Request{}, ErrNotFound
}
