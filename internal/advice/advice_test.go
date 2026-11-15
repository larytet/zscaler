package advice

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
)

func tr() *bool { b := true; return &b }
func fa() *bool { b := false; return &b }

var ts = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func e(user, app, action, reason string, groups []string, disk *bool) decisions.Entry {
	d := decisions.Entry{Record: broker.Record{Kind: "private", Event: "open", User: user, App: app, Action: action, Reason: reason, Groups: groups, TS: ts}}
	if disk != nil {
		d.Posture = &broker.PostureSnap{DiskEncrypted: disk, FirewallOn: tr()}
	}
	return d
}

func many(n int, x decisions.Entry) []decisions.Entry {
	var o []decisions.Entry
	for i := 0; i < n; i++ {
		o = append(o, x)
	}
	return o
}

func TestSuggestsTheGroupThatCoversMostBlockedUsers(t *testing.T) {
	var es []decisions.Entry
	es = append(es, many(3, e("bob", "erp", "deny", "default", []string{"hr", "all-staff"}, tr()))...)
	es = append(es, many(2, e("carol", "erp", "deny", "default", []string{"hr"}, tr()))...)
	out, dev := Suggest(es)
	if len(dev) != 0 || len(out) != 1 {
		t.Fatalf("%+v %v", out, dev)
	}
	s := out[0]
	if len(s.Draft.Match.Groups) != 1 || s.Draft.Match.Groups[0] != "hr" || s.Draft.Match.Apps[0] != "erp" || s.Attempts != 5 || len(s.Users) != 2 {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(s.Summary, `group "hr"`) || !strings.Contains(s.Caution, "simulate") {
		t.Fatalf("%+v", s)
	}
}

func TestBelowThresholdAndOtherReasonsAreIgnored(t *testing.T) {
	es := many(2, e("bob", "erp", "deny", "default", []string{"hr"}, tr()))
	es = append(es, many(10, e("bob", "erp", "deny", "no-connector", []string{"hr"}, tr()))...)
	es = append(es, many(10, e("bob", "erp", "deny", "user-disabled", []string{"hr"}, tr()))...)
	es = append(es, many(10, e("bob", "erp", "allow", "", []string{"hr"}, tr()))...)
	if out, dev := Suggest(es); len(out)+len(dev) != 0 {
		t.Fatalf("an outage or a disabled account must not produce a suggestion to widen access: %+v %v", out, dev)
	}
}

func TestUnhealthyDevicesAreNotAnAccessProblem(t *testing.T) {
	es := many(4, e("bob", "erp", "deny", "default", []string{"hr"}, fa()))
	out, dev := Suggest(es)
	if len(out) != 0 || len(dev) != 1 || !strings.Contains(dev[0], "Fixing those devices") {
		t.Fatalf("%+v %v", out, dev)
	}
	// no posture at all counts as unhealthy
	es = many(3, e("bob", "erp", "deny", "default", []string{"hr"}, nil))
	if out, dev := Suggest(es); len(out) != 0 || len(dev) != 1 {
		t.Fatalf("%+v %v", out, dev)
	}
}

func TestUsersWithoutGroupsGetANamedRule(t *testing.T) {
	out, _ := Suggest(many(3, e("dave", "wiki", "deny", "default", nil, tr())))
	if len(out) != 1 || len(out[0].Draft.Match.Users) != 1 || out[0].Draft.Match.Users[0] != "dave" || len(out[0].Draft.Match.Groups) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestExplainPlainLanguage(t *testing.T) {
	cases := []struct {
		e              decisions.Entry
		why, fix, what string
	}{
		{e("a", "erp", "allow", "", nil, tr()), "Allowed", "", "Reached erp"},
		{e("a", "erp", "deny", "user-disabled", nil, tr()), "account is disabled", "re-enable", ""},
		{e("a", "erp", "deny", "no-connector", nil, tr()), "connector", "connector host", ""},
		{e("a", "erp", "deny", "default", []string{"hr"}, tr()), `No rule allows group(s) "hr" to reach erp`, "simulate", ""},
		{e("a", "erp", "deny", "default", []string{"hr"}, fa()), "does not meet the security baseline: disk encryption is off", "Changing the rule is not the answer", ""},
		{e("a", "erp", "deny", "default", nil, nil), "no posture report", "Fix the device", ""},
	}
	for i, c := range cases {
		s := Explain(c.e)
		if !strings.Contains(s.Why, c.why) || (c.fix != "" && !strings.Contains(s.Fix, c.fix)) || (c.what != "" && s.What != c.what) {
			t.Errorf("case %d: %+v", i, s)
		}
	}
	w := decisions.Entry{Record: broker.Record{Kind: "web", Action: "deny", Rule: "sd-bad", Target: "evil.test:443", TS: ts}}
	if s := Explain(w); !strings.Contains(s.Why, "rule sd-bad") || s.What != "Tried to reach evil.test:443" {
		t.Errorf("%+v", s)
	}
}

func TestInvestigateSummarises(t *testing.T) {
	var es []decisions.Entry
	es = append(es, many(4, e("alice", "erp", "deny", "default", []string{"hr"}, tr()))...)
	es = append(es, many(1, e("alice", "erp", "allow", "", []string{"hr"}, tr()))...)
	es = append(es, many(9, e("bob", "erp", "deny", "default", []string{"hr"}, tr()))...)
	inv := Investigate("alice", es)
	if len(inv.Timeline) != 2 || inv.Timeline[0].Count+inv.Timeline[1].Count != 5 || !strings.Contains(inv.Summary, "blocked 4 of 5 times") || !strings.Contains(inv.Summary, `No rule allows group(s) "hr"`) {
		t.Fatalf("%+v", inv)
	}
	for _, s := range inv.Timeline {
		if strings.Contains(s.What, "bob") {
			t.Fatal("another user's activity leaked into the timeline")
		}
	}
}

func TestInvestigateEdgeCases(t *testing.T) {
	if inv := Investigate("ghost", nil); !strings.Contains(inv.Summary, "No recorded activity") || !strings.Contains(inv.Summary, "agent is running") {
		t.Fatalf("%+v", inv)
	}
	if inv := Investigate("alice", many(3, e("alice", "erp", "allow", "r", nil, tr()))); !strings.Contains(inv.Summary, "allowed every time") {
		t.Fatalf("%+v", inv)
	}
	if inv := Investigate("alice", many(80, e("alice", "erp", "allow", "r", nil, tr()))); len(inv.Timeline) != 1 || inv.Timeline[0].Count != 80 {
		t.Fatalf("a run of identical attempts must fold into one row: %+v", inv.Timeline)
	}
	var varied []decisions.Entry
	for i := 0; i < 80; i++ {
		varied = append(varied, e("alice", "app"+string(rune('a'+i%26))+string(rune('a'+i/26)), "allow", "r", nil, tr()))
	}
	if inv := Investigate("alice", varied); len(inv.Timeline) != 50 {
		t.Fatalf("timeline length %d", len(inv.Timeline))
	}
	closeRec := e("alice", "erp", "deny", "default", nil, tr())
	closeRec.Event = "close"
	if inv := Investigate("alice", []decisions.Entry{closeRec}); !strings.Contains(inv.Summary, "No recorded activity") {
		t.Fatalf("close records are not attempts: %+v", inv)
	}
}
