package decisions

import (
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

func rec(tenant, user, app, action string, ts time.Time) broker.Record {
	return broker.Record{Tenant: tenant, Kind: "private", User: user, App: app, Action: action, Event: "open", TS: ts}
}

func TestFilterPageAndIsolation(t *testing.T) {
	s := New()
	now := time.Now()
	for i := 0; i < 10; i++ {
		s.Add(rec("a", "alice", "erp", "allow", now.Add(time.Duration(i)*time.Minute)))
	}
	s.Add(rec("a", "bob", "wiki", "deny", now))
	s.Add(rec("b", "alice", "erp", "allow", now))
	s.Add(broker.Record{Tenant: "a", Kind: "posture", Action: "fail", TS: now}) // events are not decisions

	if got, _ := s.Query("a", Filter{User: "bob"}); len(got) != 1 || got[0].App != "wiki" {
		t.Fatalf("%+v", got)
	}
	if got, _ := s.Query("a", Filter{Action: "deny"}); len(got) != 1 {
		t.Fatal("action filter")
	}
	if got, _ := s.Query("b", Filter{}); len(got) != 1 {
		t.Fatalf("tenant b sees %d entries", len(got))
	}
	if got, _ := s.Query("a", Filter{Kind: "posture"}); len(got) != 0 {
		t.Fatal("posture events were stored as decisions")
	}
	if got, _ := s.Query("a", Filter{Since: now.Add(5 * time.Minute)}); len(got) != 5 {
		t.Fatalf("since filter: %d", len(got))
	}
	// pages are disjoint, ordered, complete
	var seen []int
	after := 0
	for {
		got, next := s.Query("a", Filter{Limit: 4, After: after})
		for _, e := range got {
			seen = append(seen, e.Seq)
		}
		if next == 0 {
			break
		}
		after = next
	}
	if len(seen) != 11 {
		t.Fatalf("paging lost or duplicated entries: %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("out of order: %v", seen)
		}
	}
	if got, _ := s.Query("a", Filter{Limit: 100000}); len(got) != 11 {
		t.Fatal("limit cap")
	}
}

func TestBoundedPerTenant(t *testing.T) {
	s := New()
	s.Max = 5
	for i := 0; i < 20; i++ {
		s.Add(rec("a", "u", "x", "allow", time.Now()))
	}
	s.Add(rec("b", "u", "x", "allow", time.Now()))
	got, _ := s.Query("a", Filter{Limit: 500})
	if len(got) != 5 || got[0].Seq != 16 {
		t.Fatalf("kept %d, oldest seq %d (want the newest 5)", len(got), got[0].Seq)
	}
	if got, _ := s.Query("b", Filter{}); len(got) != 1 {
		t.Fatal("one tenant's volume evicted another's records")
	}
}
