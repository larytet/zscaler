package captures

import (
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

func rec(user string) broker.Record {
	return broker.Record{User: user, Device: "d1", Kind: "capture", Capture: &broker.Capture{Rule: "r", Method: "POST", Host: "x.test", Path: "/p", Verdict: "allow", Status: 200, ReqBody: "aGVsbG8="}}
}

func TestTenantScopedAndNewestFirst(t *testing.T) {
	s := New()
	s.Put("a", rec("alice"))
	s.Put("a", rec("bob"))
	s.Put("b", rec("eve"))
	l := s.List("a")
	if len(l) != 2 || l[0].User != "bob" || l[1].User != "alice" || l[0].ReqBytes != 5 {
		t.Fatalf("%+v", l)
	}
	if _, ok := s.Get("b", l[0].ID); ok {
		t.Fatal("tenant b read tenant a's capture")
	}
	if e, ok := s.Get("a", l[0].ID); !ok || e.Capture.Host != "x.test" {
		t.Fatal("own capture not found")
	}
	if len(s.List("c")) != 0 {
		t.Fatal("unknown tenant")
	}
}

func TestExpiryAndBound(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	s.Put("a", rec("old"))
	now = now.Add(TTL + time.Minute)
	if len(s.List("a")) != 0 {
		t.Fatal("a capture outlived its hour")
	}
	if _, ok := s.Get("a", 1); ok {
		t.Fatal("an expired capture could still be read")
	}
	for i := 0; i < MaxPerTenant+25; i++ {
		s.Put("a", rec("u"))
	}
	if n := len(s.List("a")); n != MaxPerTenant {
		t.Fatalf("%d kept", n)
	}
}

func TestPurgeAndNilCapture(t *testing.T) {
	s := New()
	s.Put("a", rec("x"))
	s.Put("a", broker.Record{User: "no capture"}) // nothing to store
	if s.Purge("a") != 1 || len(s.List("a")) != 0 {
		t.Fatal("purge")
	}
	if s.Purge("a") != 0 {
		t.Fatal("purge of nothing")
	}
}
