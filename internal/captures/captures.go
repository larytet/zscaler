// Package captures keeps decrypted exchanges for a short time so an admin can look at them
// (ZIA-022b). They hold content, so the store is small, in memory only, scoped by tenant, and
// everything expires after an hour.
package captures

import (
	"encoding/base64"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

const (
	TTL          = time.Hour
	MaxPerTenant = 100
)

type Entry struct {
	ID      int            `json:"id"`
	Time    time.Time      `json:"time"`
	User    string         `json:"user"`
	Device  string         `json:"device"`
	Capture broker.Capture `json:"capture"`
}

// Summary is what the list shows: no headers and no bodies.
type Summary struct {
	ID        int       `json:"id"`
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Rule      string    `json:"rule"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Verdict   string    `json:"verdict"`
	Status    int       `json:"status"`
	Truncated bool      `json:"truncated"`
	ReqBytes  int       `json:"request_body_bytes"`
	RespBytes int       `json:"response_body_bytes"`
	Expires   time.Time `json:"expires"`
}

type Store struct {
	Now func() time.Time
	mu  sync.Mutex
	seq int
	by  map[string][]Entry
}

func New() *Store { return &Store{by: map[string][]Entry{}} }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) prune(tenant string) {
	cut := s.now().Add(-TTL)
	l := s.by[tenant]
	i := 0
	for i < len(l) && l[i].Time.Before(cut) {
		i++
	}
	s.by[tenant] = l[i:]
}

// Put stores a capture; the oldest are dropped beyond MaxPerTenant.
func (s *Store) Put(tenant string, r broker.Record) {
	if r.Capture == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(tenant)
	s.seq++
	l := append(s.by[tenant], Entry{ID: s.seq, Time: s.now(), User: r.User, Device: r.Device, Capture: *r.Capture})
	if len(l) > MaxPerTenant {
		l = l[len(l)-MaxPerTenant:]
	}
	s.by[tenant] = l
}

func b64len(s string) int {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0
	}
	return len(b)
}

func (s *Store) List(tenant string) []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(tenant)
	out := []Summary{}
	l := s.by[tenant]
	for i := len(l) - 1; i >= 0; i-- { // newest first
		e := l[i]
		c := e.Capture
		out = append(out, Summary{ID: e.ID, Time: e.Time, User: e.User, Rule: c.Rule, Method: c.Method, Host: c.Host, Path: c.Path,
			Verdict: c.Verdict, Status: c.Status, Truncated: c.Truncated, ReqBytes: b64len(c.ReqBody), RespBytes: b64len(c.RespBody), Expires: e.Time.Add(TTL)})
	}
	return out
}

// Get returns one capture of the tenant, or false if it is unknown or expired.
func (s *Store) Get(tenant string, id int) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(tenant)
	for _, e := range s.by[tenant] {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Purge removes all of a tenant's captures and returns how many there were.
func (s *Store) Purge(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.by[tenant])
	delete(s.by, tenant)
	return n
}
