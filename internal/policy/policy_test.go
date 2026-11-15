package policy

import (
	"net/netip"
	"sync"
	"testing"
	"testing/quick"
	"time"
)

func bp(b bool) *bool { return &b }

var t0 = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC) // Monday

func mk(t *testing.T, kind Kind, rules ...Rule) *Policy {
	t.Helper()
	p := &Policy{Kind: kind, DefaultAction: Deny, Rules: rules}
	if kind == Web {
		p.DefaultAction = Allow
	}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func req(groups ...string) Request {
	return Request{Kind: Private, App: "seg1", Now: t0,
		User:   User{Email: "alice@example.com", Groups: groups},
		Device: Device{ID: "d1", Posture: &Posture{OS: "windows", OSVersion: "10.0.19045", DiskEncrypted: bp(true), FirewallOn: bp(true), ReportedAt: t0}}}
}

func allowGroup(id string, prio int, g string) Rule {
	return Rule{ID: id, Priority: prio, Action: Allow, Match: Match{Groups: []string{g}}}
}

func TestBasicDecisions(t *testing.T) {
	cases := []struct {
		name  string
		p     *Policy
		r     Request
		want  Action
		rule  string
		cause string
	}{
		{"POL-001 no rules", mk(t, Private), req(), Deny, "", "default"},
		{"POL-002 group allow", mk(t, Private, allowGroup("a", 1, "fin")), req("fin"), Allow, "a", ""},
		{"POL-003 not in group", mk(t, Private, allowGroup("a", 1, "fin")), req("hr"), Deny, "", "default"},
		{"POL-004 user or group", mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Users: []string{"alice@example.com"}, Groups: []string{"fin"}}}), req(), Allow, "a", ""},
		{"POL-005 anyone with app", mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Apps: []string{"seg1"}}}), req(), Allow, "a", ""},
		{"POL-006 priority", mk(t, Private, allowGroup("b", 20, "fin"), Rule{ID: "a", Priority: 10, Action: Deny, Match: Match{Groups: []string{"fin"}}}), req("fin"), Deny, "a", ""},
		{"POL-008 deny first", mk(t, Private, Rule{ID: "d", Priority: 10, Action: Deny, Match: Match{Groups: []string{"fin"}}}, allowGroup("a", 20, "fin")), req("fin"), Deny, "d", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := c.p.Evaluate(c.r)
			if d.Action != c.want || d.RuleID != c.rule || (c.cause != "" && d.Reason != c.cause) {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestPostureFailClosed(t *testing.T) {
	rule := Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"fin"},
		Posture: &PostureMatch{DiskEncrypted: bp(true), MaxAgeSeconds: 3600}}}
	p := mk(t, Private, rule)
	r := req("fin")
	if p.Evaluate(r).Action != Allow {
		t.Fatal("baseline should allow")
	}
	r.Device.Posture.DiskEncrypted = bp(false) // POL-009
	if p.Evaluate(r).Action != Deny {
		t.Fatal("disk off must deny")
	}
	r.Device.Posture.DiskEncrypted = nil // POL-010 unknown
	if p.Evaluate(r).Action != Deny {
		t.Fatal("unknown must deny")
	}
	r.Device.Posture = nil // POL-011
	if p.Evaluate(r).Action != Deny {
		t.Fatal("no report must deny")
	}
	r = req("fin") // POL-012 stale
	r.Now = t0.Add(2 * time.Hour)
	if p.Evaluate(r).Action != Deny {
		t.Fatal("stale must deny")
	}
	r.Now = t0.Add(-time.Minute) // report from the future
	if p.Evaluate(r).Action != Deny {
		t.Fatal("future-dated report must deny")
	}
}

func TestMinOS(t *testing.T) { // POL-013, POL-014
	p := mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Posture: &PostureMatch{MinOS: map[string]string{"windows": "10.0.19045", "macos": "13.0"}}}})
	for _, c := range []struct {
		os, v string
		want  Action
	}{
		{"windows", "10.0.19045", Allow}, {"windows", "10.0.19044", Deny}, {"windows", "10.0.22631", Allow},
		{"macos", "13.0", Allow}, {"macos", "12.7", Deny}, {"macos", "14", Allow}, {"linux", "6.8", Deny},
	} {
		r := req()
		r.Device.Posture.OS, r.Device.Posture.OSVersion = c.os, c.v
		if got := p.Evaluate(r).Action; got != c.want {
			t.Errorf("%s %s: got %s", c.os, c.v, got)
		}
	}
}

func TestDisabledAndRevoked(t *testing.T) { // POL-015, POL-016
	p := mk(t, Private, allowGroup("a", 1, "fin"))
	r := req("fin")
	r.User.Disabled = true
	if d := p.Evaluate(r); d.Action != Deny || d.Reason != "user-disabled" {
		t.Fatalf("%+v", d)
	}
	r = req("fin")
	r.Device.Revoked = true
	if d := p.Evaluate(r); d.Action != Deny || d.Reason != "device-revoked" {
		t.Fatalf("%+v", d)
	}
}

func TestTimeWindow(t *testing.T) { // POL-017..019
	mkT := func(from, to string) *Policy {
		return mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"},
			Time: &TimeMatch{Days: []string{"mon"}, From: from, To: to, TZ: "Europe/Berlin"}}})
	}
	p := mkT("07:00", "20:00")
	at := func(h, m int) Request { // Berlin is UTC+1 in November
		r := req("g")
		r.Now = time.Date(2026, 11, 16, h-1, m, 0, 0, time.UTC)
		return r
	}
	for _, c := range []struct {
		h, m int
		want Action
	}{{6, 59, Deny}, {7, 0, Allow}, {19, 59, Allow}, {20, 0, Deny}} {
		if got := p.Evaluate(at(c.h, c.m)).Action; got != c.want {
			t.Errorf("%02d:%02d got %s", c.h, c.m, got)
		}
	}
	r := at(10, 0)
	r.Now = r.Now.AddDate(0, 0, 1) // Tuesday
	if p.Evaluate(r).Action != Deny {
		t.Error("tuesday should deny")
	}
	night := mkT("22:00", "06:00")
	if night.Evaluate(at(23, 0)).Action != Allow || night.Evaluate(at(12, 0)).Action != Deny {
		t.Error("overnight window wrong")
	}
	// DST: 2026-03-30 is Monday, Berlin is UTC+2 after the 29th.
	r = req("g")
	r.Now = time.Date(2026, 3, 30, 5, 30, 0, 0, time.UTC) // 07:30 local
	if p.Evaluate(r).Action != Allow {
		t.Error("DST local time wrong")
	}
}

func TestNetwork(t *testing.T) { // POL-020
	p := mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Network: &NetworkMatch{SrcCIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}}}})
	for ip, want := range map[string]Action{"203.0.113.9": Allow, "203.0.114.1": Deny, "2001:db8::1": Allow, "2001:dc8::1": Deny, "::ffff:203.0.113.9": Allow} {
		r := req("g")
		r.SrcIP = netip.MustParseAddr(ip)
		if got := p.Evaluate(r).Action; got != want {
			t.Errorf("%s got %s", ip, got)
		}
	}
	if p.Evaluate(req("g")).Action != Deny {
		t.Error("missing source IP must not match")
	}
}

func TestWebDomains(t *testing.T) { // POL-021..025
	p := mk(t, Web,
		Rule{ID: "d", Priority: 1, Action: Deny, Match: Match{Domains: []string{"example.com"}}},
		Rule{ID: "c", Priority: 2, Action: Warn, Match: Match{Categories: []string{"file-sharing"}}})
	host := func(h string, cats ...string) Decision {
		return p.Evaluate(Request{Kind: Web, Host: h, Categories: cats, Now: t0})
	}
	for h, want := range map[string]Action{
		"example.com": Deny, "a.example.com": Deny, "notexample.com": Allow, "example.com.evil.net": Allow,
		"EXAMPLE.com.": Deny, "example.com:443": Deny,
	} {
		if got := host(h).Action; got != want {
			t.Errorf("%s got %s", h, got)
		}
	}
	if d := host("x.test", "news", "file-sharing"); d.Action != Warn || d.RuleID != "c" {
		t.Errorf("%+v", d)
	}
}

func TestEvaluationErrorIsDeny(t *testing.T) { // POL-026
	var p *Policy
	if d := p.Evaluate(req()); d.Action != Deny || d.Reason != "evaluation-error" {
		t.Fatalf("%+v", d)
	}
	uncompiled := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{allowGroup("a", 1, "g")}}
	if uncompiled.Evaluate(req("g")).Action != Deny {
		t.Fatal("uncompiled policy must deny")
	}
}

func TestParallelPurity(t *testing.T) { // POL-027, run with -race
	p := mk(t, Private, allowGroup("a", 1, "g"))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if p.Evaluate(req("g")).Action != Allow {
					t.Error("changed")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRuleOrderIndependent(t *testing.T) { // POL-007
	a, b := allowGroup("a", 10, "g"), Rule{ID: "b", Priority: 5, Action: Deny, Match: Match{Groups: []string{"g"}}}
	if mk(t, Private, a, b).Evaluate(req("g")) != mk(t, Private, b, a).Evaluate(req("g")) {
		t.Fatal("order matters")
	}
}

func BenchmarkEvaluate500(b *testing.B) { // POL-028 / PERF-005
	var rules []Rule
	for i := 0; i < 499; i++ {
		rules = append(rules, allowGroup("r"+time.Duration(i).String(), i, "other"+time.Duration(i).String()))
	}
	rules = append(rules, allowGroup("last", 1000, "g"))
	p := &Policy{Kind: Private, DefaultAction: Deny, Rules: rules}
	if err := p.Compile(nil); err != nil {
		b.Fatal(err)
	}
	r := req("g")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Evaluate(r)
	}
}

// FUZ-003: dropping posture never turns a deny into an allow.
func TestPostureMonotonic(t *testing.T) {
	p := mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Posture: &PostureMatch{FirewallOn: bp(true)}}})
	f := func(fw, disk bool) bool {
		r := req("g")
		r.Device.Posture.FirewallOn, r.Device.Posture.DiskEncrypted = &fw, &disk
		with := p.Evaluate(r).Action
		r.Device.Posture = nil
		without := p.Evaluate(r).Action
		return !(with == Deny && without == Allow)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

// FUZ-002: a top-priority deny always wins for a matching request.
func TestTopDenyWins(t *testing.T) {
	f := func(prio int16, hasGroup bool) bool {
		g := []string{}
		if hasGroup {
			g = []string{"g"}
		}
		p := mk(t, Private, allowGroup("a", int(prio), "g"),
			Rule{ID: "d", Priority: int(prio) - 1, Action: Deny, Match: Match{Groups: []string{"g"}}})
		d := p.Evaluate(req(g...))
		return !hasGroup || d.Action == Deny
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) { // FUZ-004
	f.Add([]byte(`{"kind":"private","default_action":"deny","rules":[]}`))
	f.Add([]byte(`{"kind":"web","rules":[{"id":"a","priority":1,"action":"warn"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err == nil {
			p.Evaluate(req("g"))
		}
	})
}
