package simulate

import (
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/policy"
)

func tr() *bool { b := true; return &b }
func fa() *bool { b := false; return &b }

func entry(user, app, action, reason string, groups []string, disk *bool) decisions.Entry {
	ts := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	e := decisions.Entry{Record: broker.Record{Kind: "private", Event: "open", User: user, App: app, Action: action, Reason: reason, Groups: groups, TS: ts}}
	if disk != nil {
		e.Posture = &broker.PostureSnap{DiskEncrypted: disk, ReportedAt: ts.Add(-time.Minute)}
	}
	return e
}

func pol(t *testing.T, rules ...policy.Rule) *policy.Policy {
	p := &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Rules: rules}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func allow(id string, prio int, group, app string, posture *policy.PostureMatch) policy.Rule {
	return policy.Rule{ID: id, Priority: prio, Action: policy.Allow, Match: policy.Match{Groups: []string{group}, Apps: []string{app}, Posture: posture}}
}

func history() []decisions.Entry {
	return []decisions.Entry{
		entry("alice", "erp", "allow", "", []string{"finance"}, tr()),
		entry("alice", "erp", "allow", "", []string{"finance"}, tr()),
		entry("bob", "erp", "deny", "default", []string{"hr"}, tr()),
		entry("bob", "erp", "deny", "default", []string{"hr"}, tr()),
		entry("carol", "wiki", "deny", "default", []string{"hr"}, fa()),
	}
}

func TestSamePolicyChangesNothing(t *testing.T) {
	p := pol(t, allow("fin", 1, "finance", "erp", &policy.PostureMatch{DiskEncrypted: tr()}))
	r := Run(p, history())
	if r.Replayed != 5 || r.Unchanged != 5 || r.NewlyAllowed+r.NewlyDenied != 0 || len(r.Changes) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestWideningAndNarrowing(t *testing.T) {
	// add HR to the ERP, remove finance
	p := pol(t, allow("hr", 1, "hr", "erp", nil))
	r := Run(p, history())
	if r.NewlyAllowed != 2 || r.NewlyDenied != 2 || r.Unchanged != 1 {
		t.Fatalf("%+v", r)
	}
	var sawBob, sawAlice bool
	for _, c := range r.Changes {
		switch {
		case c.User == "bob" && c.From == "deny" && c.To == "allow" && c.N == 2 && c.Rule == "hr":
			sawBob = true
		case c.User == "alice" && c.From == "allow" && c.To == "deny" && c.N == 2 && c.Why != "":
			sawAlice = true
		}
	}
	if !sawBob || !sawAlice {
		t.Fatalf("%+v", r.Changes)
	}
}

func TestPostureIsReplayedFromTheRecord(t *testing.T) {
	// carol's device had no disk encryption: requiring it must keep her denied, not allow her
	p := pol(t, allow("hr", 1, "hr", "wiki", &policy.PostureMatch{DiskEncrypted: tr()}))
	r := Run(p, []decisions.Entry{entry("carol", "wiki", "deny", "default", []string{"hr"}, fa())})
	if r.NewlyAllowed != 0 || r.Unchanged != 1 {
		t.Fatalf("%+v", r)
	}
	// and with no posture recorded at all, a posture rule fails closed
	r = Run(p, []decisions.Entry{entry("dave", "wiki", "deny", "default", []string{"hr"}, nil)})
	if r.NewlyAllowed != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestMachineryDenialsAreNotPolicyDecisions(t *testing.T) {
	es := []decisions.Entry{
		entry("a", "erp", "deny", "no-connector", []string{"finance"}, tr()),
		entry("a", "ghost", "deny", "unknown-app", []string{"finance"}, tr()),
		entry("a", "erp", "deny", "state-stale", []string{"finance"}, tr()),
	}
	r := Run(pol(t, allow("fin", 1, "finance", "erp", nil)), es)
	if r.Replayed != 0 || r.Skipped != 3 || r.NewlyAllowed != 0 {
		t.Fatalf("an outage must not look like something a new rule would have fixed: %+v", r)
	}
	if len(r.Caveats) < 5 {
		t.Fatal("an empty replay must say it proves nothing")
	}
}

func TestOnlyOpenPrivateRecordsCount(t *testing.T) {
	c := entry("a", "erp", "allow", "", []string{"finance"}, tr())
	c.Event = "close"
	w := entry("a", "erp", "allow", "", []string{"finance"}, tr())
	w.Kind = "web"
	r := Run(pol(t), []decisions.Entry{c, w})
	if r.Replayed != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestChangesAreCappedAndOrdered(t *testing.T) {
	var es []decisions.Entry
	for i := 0; i < 30; i++ {
		for j := 0; j <= i; j++ {
			es = append(es, entry("u"+string(rune('a'+i%26))+string(rune('a'+i/26)), "erp", "deny", "default", []string{"g"}, tr()))
		}
	}
	r := Run(pol(t, policy.Rule{ID: "all", Priority: 1, Action: policy.Allow, Match: policy.Match{Groups: []string{"g"}}}), es)
	if len(r.Changes) != 20 {
		t.Fatalf("%d changes", len(r.Changes))
	}
	for i := 1; i < len(r.Changes); i++ {
		if r.Changes[i].N > r.Changes[i-1].N {
			t.Fatal("not ordered by count")
		}
	}
}
