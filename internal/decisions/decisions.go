// Package decisions keeps a bounded, per-tenant, in-memory history of decision
// records forwarded by enforcement nodes, and answers searches over it
// (DESIGN.md D5.1 /v1/decisions). The EN's JSON-lines file remains the durable copy.
package decisions

import (
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

type Entry struct {
	Seq int `json:"seq"`
	broker.Record
}

type Filter struct {
	User, App, Action, Kind string
	Since                   time.Time
	After                   int // return entries with Seq greater than this
	Limit                   int
}

type Store struct {
	Max int // per tenant, default 50000

	mu      sync.Mutex
	seq     int
	data    map[string][]Entry
	archive *Archive
}

func New() *Store { return &Store{data: map[string][]Entry{}} }

// Archive, when set, also keeps every record on disk for the retention period (see archive.go).
func (s *Store) SetArchive(a *Archive) { s.mu.Lock(); s.archive = a; s.mu.Unlock() }

// Archive returns the archive, or nil.
func (s *Store) Archive() *Archive { s.mu.Lock(); defer s.mu.Unlock(); return s.archive }

// Restore refills the in-memory view from the archive (after a restart).
func (s *Store) Restore(perTenant int) int {
	s.mu.Lock()
	a := s.archive
	s.mu.Unlock()
	if a == nil {
		return 0
	}
	n := 0
	for _, r := range a.Restore(perTenant) {
		s.addMemory(r)
		n++
	}
	return n
}

func (s *Store) Add(r broker.Record) { s.AddFiltered(r, r) }

// AddFiltered keeps r in the live view and archived (what goes to disk) in the archive. They differ when
// the tenant's privacy mode hides user names in what is stored.
func (s *Store) AddFiltered(r, archived broker.Record) {
	s.mu.Lock()
	a := s.archive
	s.mu.Unlock()
	if a != nil {
		a.Append(archived) // a failure to write is not a reason to lose the live view
	}
	s.addMemory(r)
}

func (s *Store) addMemory(r broker.Record) {
	if r.Kind == "posture" || r.Kind == "connector" || r.Kind == "health" || r.Kind == "capture" {
		return // events feed alerts, they are not access decisions
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	max := s.Max
	if max == 0 {
		max = 50000
	}
	s.seq++
	l := append(s.data[r.Tenant], Entry{s.seq, r})
	if len(l) > max {
		l = append([]Entry(nil), l[len(l)-max:]...)
	}
	s.data[r.Tenant] = l
}

// Query returns matching entries oldest first, at most Limit (default 100, cap 500),
// and the Seq to pass as After for the next page ("" semantics: 0 means no more).
func (s *Store) Query(tenant string, f Filter) (out []Entry, next int) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.data[tenant] {
		if e.Seq <= f.After ||
			(f.User != "" && e.User != f.User) || (f.App != "" && e.App != f.App) ||
			(f.Action != "" && e.Action != f.Action) || (f.Kind != "" && e.Kind != f.Kind) ||
			(!f.Since.IsZero() && e.TS.Before(f.Since)) {
			continue
		}
		out = append(out, e)
		if len(out) == f.Limit {
			return out, e.Seq
		}
	}
	return out, 0
}

// Since returns every entry for the tenant at or after t (for reports).
func (s *Store) Since(tenant string, t time.Time) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for _, e := range s.data[tenant] {
		if !e.TS.Before(t) {
			out = append(out, e)
		}
	}
	return out
}
