package approvals

import (
	"errors"
	"testing"
	"time"
)

var now = time.Now()

func TestDedupeAndCount(t *testing.T) {
	s := New()
	a, created := s.Add("t1", "alice", "erp", "jit", now)
	if !created || a.Attempts != 1 {
		t.Fatalf("%+v", a)
	}
	b, created := s.Add("t1", "alice", "erp", "jit", now)
	if created || b.ID != a.ID || b.Attempts != 2 {
		t.Fatalf("a repeated attempt must not create a second request: %+v", b)
	}
	if _, created := s.Add("t1", "alice", "wiki", "jit", now); !created {
		t.Fatal("a different app is a different request")
	}
	if _, created := s.Add("t2", "alice", "erp", "jit", now); !created {
		t.Fatal("tenants must not share requests")
	}
}

func TestDecideOnce(t *testing.T) {
	s := New()
	r, _ := s.Add("t1", "alice", "erp", "jit", now)
	until := now.Add(time.Hour)
	d, err := s.Decide("t1", r.ID, Approved, "owner", until, now)
	if err != nil || d.State != Approved || !d.Until.Equal(until) || d.DecidedBy != "owner" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := s.Decide("t1", r.ID, Denied, "other", time.Time{}, now); !errors.Is(err, ErrDecided) {
		t.Fatalf("a decided request was decided again: %v", err)
	}
	// after the decision the next attempt opens a fresh request
	n, created := s.Add("t1", "alice", "erp", "jit", now)
	if !created || n.ID == r.ID {
		t.Fatalf("%+v", n)
	}
}

func TestTenantScopedDecide(t *testing.T) {
	s := New()
	r, _ := s.Add("t1", "alice", "erp", "jit", now)
	if _, err := s.Decide("t2", r.ID, Approved, "mallory", now.Add(time.Hour), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant t2 decided tenant t1's request: %v", err)
	}
	if got := s.List("t2", ""); len(got) != 0 {
		t.Fatal("tenant t2 sees t1's requests")
	}
	if got := s.List("t1", Pending); len(got) != 1 {
		t.Fatal("request lost")
	}
}

func TestListOrderAndFilter(t *testing.T) {
	s := New()
	for _, app := range []string{"a", "b", "c"} {
		s.Add("t1", "u", app, "r", now)
	}
	s.Decide("t1", 2, Denied, "x", time.Time{}, now)
	all := s.List("t1", "")
	if len(all) != 3 || all[0].ID != 3 {
		t.Fatalf("%+v", all)
	}
	if p := s.List("t1", Pending); len(p) != 2 {
		t.Fatalf("%+v", p)
	}
}

func TestBoundKeepsPending(t *testing.T) {
	s := New()
	s.Max = 3
	for i := 0; i < 3; i++ {
		s.Add("t1", "u", string(rune('a'+i)), "r", now)
	}
	s.Decide("t1", 1, Denied, "x", time.Time{}, now)
	s.Add("t1", "u", "z", "r", now)
	got := s.List("t1", "")
	if len(got) != 3 {
		t.Fatalf("%d", len(got))
	}
	for _, r := range got {
		if r.ID == 1 {
			t.Fatal("the decided request should have been dropped first")
		}
	}
	for i := 0; i < 20; i++ { // a flood of new pending requests may exceed the cap, but never discards a pending one
		s.Add("t1", "flood", string(rune('A'+i)), "r", now)
	}
	if p := s.List("t1", Pending); len(p) < 4 {
		t.Fatalf("pending requests were discarded: %d", len(p))
	}
}
