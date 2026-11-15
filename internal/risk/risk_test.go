package risk

import (
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
)

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func deny(user, kind string, ago time.Duration, n int) []decisions.Entry {
	var o []decisions.Entry
	for i := 0; i < n; i++ {
		o = append(o, decisions.Entry{Record: broker.Record{User: user, Kind: kind, Action: "deny", Event: "open", TS: now.Add(-ago)}})
	}
	return o
}

func score(r []Score, u string) (Score, bool) {
	for _, s := range r {
		if s.User == u {
			return s, true
		}
	}
	return Score{}, false
}

func TestQuietUsersScoreNothing(t *testing.T) {
	es := deny("alice", "private", time.Minute, 2)
	es = append(es, decisions.Entry{Record: broker.Record{User: "bob", Kind: "private", Action: "allow", Event: "open", TS: now}})
	if r := Compute(now, es, nil); len(r) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSignalsAddUpWithReasons(t *testing.T) {
	es := deny("alice", "private", 5*time.Minute, 12)
	es = append(es, deny("alice", "web", 2*time.Hour, 6)...)
	open := []alerts.Alert{{Kind: "posture-failed", User: "alice"}}
	r := Compute(now, es, open)
	s, ok := score(r, "alice")
	if !ok || s.Score != PostureFailing+ManyDenies+WebBlocks || len(s.Reasons) != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestThresholdsAndWindows(t *testing.T) {
	if s, _ := score(Compute(now, deny("a", "private", time.Minute, 3), nil), "a"); s.Score != SomeDenies {
		t.Fatalf("3 denies: %+v", s)
	}
	if s, _ := score(Compute(now, deny("a", "private", time.Minute, 9), nil), "a"); s.Score != SomeDenies {
		t.Fatalf("9 denies: %+v", s)
	}
	if s, _ := score(Compute(now, deny("a", "private", time.Minute, 10), nil), "a"); s.Score != ManyDenies {
		t.Fatalf("10 denies: %+v", s)
	}
	if _, ok := score(Compute(now, deny("a", "private", 90*time.Minute, 50), nil), "a"); ok {
		t.Fatal("denies older than an hour were counted")
	}
	if _, ok := score(Compute(now, deny("a", "web", 25*time.Hour, 50), nil), "a"); ok {
		t.Fatal("web blocks older than a day were counted")
	}
	if _, ok := score(Compute(now, deny("a", "web", time.Hour, 4), nil), "a"); ok {
		t.Fatal("4 web blocks is below the threshold")
	}
}

func TestClosedAlertsAndCapAndOrder(t *testing.T) {
	closed := now
	open := []alerts.Alert{{Kind: "posture-failed", User: "a", Closed: &closed}, {Kind: "posture-failed", User: "b"}, {Kind: "repeated-denies", User: "b"}}
	r := Compute(now, nil, open)
	if len(r) != 1 || r[0].User != "b" || r[0].Score != PostureFailing {
		t.Fatalf("%+v", r)
	}
	es := deny("c", "private", time.Minute, 20)
	es = append(es, deny("c", "web", time.Minute, 20)...)
	r = Compute(now, es, []alerts.Alert{{Kind: "posture-failed", User: "c"}, {Kind: "posture-failed", User: "c"}})
	if r[0].Score > 100 {
		t.Fatalf("score above 100: %+v", r[0])
	}
	r = Compute(now, append(deny("x", "private", time.Minute, 10), deny("y", "private", time.Minute, 3)...), nil)
	if len(r) != 2 || r[0].User != "x" {
		t.Fatalf("not ordered by score: %+v", r)
	}
}
