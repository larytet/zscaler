package policy

import (
	"fmt"
	"math/rand"
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

func FuzzParse(f *testing.F) { // FUZ-004, and FUZ-001: every accepted policy is evaluated, which must never panic
	f.Add([]byte(`{"kind":"private","default_action":"deny","rules":[]}`))
	f.Add([]byte(`{"kind":"web","rules":[{"id":"a","priority":1,"action":"warn"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err == nil {
			p.Evaluate(req("g"))
		}
	})
}

// The index must never change a decision: compare with a linear scan on random policies.
func TestIndexEqualsLinearScan(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	groups := []string{"a", "b", "c", "d", "e"}
	users := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	pick := func(from []string, max int) []string {
		var out []string
		for i := 0; i < rnd.Intn(max+1); i++ {
			out = append(out, from[rnd.Intn(len(from))])
		}
		return out
	}
	for iter := 0; iter < 300; iter++ {
		p := &Policy{Kind: Private, DefaultAction: Deny}
		for i := 0; i < 1+rnd.Intn(20); i++ {
			act := Allow
			if rnd.Intn(3) == 0 {
				act = Deny
			}
			m := Match{Users: pick(users, 2), Groups: pick(groups, 3)}
			if rnd.Intn(2) == 0 {
				m.Apps = []string{[]string{"s1", "s2"}[rnd.Intn(2)]}
			}
			p.Rules = append(p.Rules, Rule{ID: fmt.Sprint("r", i), Priority: rnd.Intn(1000)*100 + i, Action: act, Match: m})
		}
		if err := p.Compile(nil); err != nil {
			continue // random policy happened to be invalid (for example an allow-all)
		}
		for j := 0; j < 20; j++ {
			r := req(pick(groups, 3)...)
			r.User.Email = users[rnd.Intn(len(users))]
			r.App = []string{"s1", "s2", "s3"}[rnd.Intn(3)]
			want := Decision{Action: Deny, Reason: "default"}
			for k := range p.compiled {
				if c := &p.compiled[k]; c.matches(p.Kind, r) {
					want = Decision{Action: c.Action, RuleID: c.ID, Reason: c.Reason}
					break
				}
			}
			if got := p.Evaluate(r); got != want {
				t.Fatalf("iter %d: indexed %+v, linear %+v", iter, got, want)
			}
		}
	}
}

func TestRiskConditions(t *testing.T) { // ARCH-007
	max, min := 49, 70
	low := mk(t, Private, Rule{ID: "ok", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, MaxRisk: &max}})
	high := mk(t, Private, Rule{ID: "block", Priority: 1, Action: Deny, Match: Match{Groups: []string{"g"}, MinRisk: &min}},
		Rule{ID: "ok", Priority: 2, Action: Allow, Match: Match{Groups: []string{"g"}}})
	for risk, want := range map[int]Action{0: Allow, 49: Allow, 50: Deny, 100: Deny} {
		r := req("g")
		r.User.Risk = risk
		if got := low.Evaluate(r).Action; got != want {
			t.Errorf("max_risk 49 with risk %d: got %s", risk, got)
		}
	}
	for risk, want := range map[int]Action{0: Allow, 69: Allow, 70: Deny, 100: Deny} {
		r := req("g")
		r.User.Risk = risk
		if got := high.Evaluate(r).Action; got != want {
			t.Errorf("min_risk 70 with risk %d: got %s", risk, got)
		}
	}
	bad := 101
	p := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, MaxRisk: &bad}}}}
	if errs := Validate(p, nil); len(errs) == 0 {
		t.Fatal("risk above 100 accepted")
	}
	neg, lo, hi := -1, 80, 20
	for _, m := range []Match{{Groups: []string{"g"}, MinRisk: &neg}, {Groups: []string{"g"}, MinRisk: &lo, MaxRisk: &hi}} {
		if errs := Validate(&Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: m}}}, nil); len(errs) == 0 {
			t.Fatalf("bad risk bounds accepted: %+v", m)
		}
	}
}

func TestPathAndMethodRulesNeedInspection(t *testing.T) { // ZPA-074 (web side)
	p := mk(t, Web,
		Rule{ID: "no-upload", Priority: 1, Action: Deny, Match: Match{Domains: []string{"files.example"}, Paths: []string{"/upload"}, Methods: []string{"post", "PUT"}}},
		Rule{ID: "admin-ro", Priority: 2, Action: Deny, Match: Match{Domains: []string{"files.example"}, Paths: []string{"/admin"}, Methods: []string{"DELETE"}}})
	insp := func(method, path string) Decision {
		return p.Evaluate(Request{Kind: Web, Host: "files.example", Now: t0, Inspected: true, Method: method, Path: path})
	}
	for _, c := range []struct {
		method, path string
		want         Action
	}{
		{"POST", "/upload", Deny}, {"PUT", "/upload/x", Deny}, {"GET", "/upload", Allow}, {"POST", "/other", Allow},
		{"POST", "/uploads", Deny}, // prefix semantics: documented, and the admin should write /upload/ for a directory
		{"DELETE", "/admin/users", Deny}, {"GET", "/admin/users", Allow}, {"POST", "/", Allow},
	} {
		if got := insp(c.method, c.path).Action; got != c.want {
			t.Errorf("%s %s: got %s", c.method, c.path, got)
		}
	}
	// without decryption the proxy cannot see paths: the rule must not match (and must not block everything)
	if d := p.Evaluate(Request{Kind: Web, Host: "files.example", Now: t0}); d.Action != Allow {
		t.Fatalf("a path rule matched traffic that was not inspected: %+v", d)
	}
}

func TestPathRuleValidation(t *testing.T) {
	rule := func(m Match) *Policy {
		return &Policy{Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: m}}}
	}
	if errs := Validate(rule(Match{Paths: []string{"/ok"}, Methods: []string{"get"}}), nil); len(errs) != 0 {
		t.Fatal(errs)
	}
	for name, m := range map[string]Match{
		"no leading slash": {Paths: []string{"upload"}},
		"space in path":    {Paths: []string{"/a b"}},
		"newline in path":  {Paths: []string{"/a\nb"}},
		"unknown method":   {Methods: []string{"TRACE"}},
	} {
		if errs := Validate(rule(m), nil); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	priv := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Paths: []string{"/x"}}}}}
	if errs := Validate(priv, nil); len(errs) == 0 {
		t.Fatal("paths accepted in a private policy")
	}
}

func TestDLPCondition(t *testing.T) { // DATA-001 (basic)
	p := mk(t, Web, Rule{ID: "no-pii", Priority: 1, Action: Deny, Match: Match{DLP: []string{"credit-card", "us-ssn"}}})
	ev := func(inspected bool, hits ...string) Action {
		return p.Evaluate(Request{Kind: Web, Host: "x.test", Now: t0, Inspected: inspected, DLPHits: hits}).Action
	}
	if ev(true, "credit-card") != Deny || ev(true, "aws-access-key", "us-ssn") != Deny {
		t.Fatal("a listed data type must match")
	}
	if ev(true, "aws-access-key") != Allow || ev(true) != Allow {
		t.Fatal("an unlisted or absent data type must not match")
	}
	if !p.UsesDLP() {
		t.Fatal("UsesDLP")
	}
	plain := mk(t, Web, Rule{ID: "x", Priority: 1, Action: Deny, Match: Match{Domains: []string{"x.test"}}})
	if plain.UsesDLP() {
		t.Fatal("scanning must be off when no rule asks for it")
	}
	for name, pol := range map[string]*Policy{
		"unknown type":  {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{DLP: []string{"made-up"}}}}},
		"private rules": {Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, DLP: []string{"credit-card"}}}}},
	} {
		if errs := Validate(pol, nil); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestIsolateAndWorkspaceCondition(t *testing.T) { // WBT-001
	p := mk(t, Private, Rule{ID: "sens", Priority: 1, Action: Isolate, Match: Match{Groups: []string{"g"}, Apps: []string{"hr-db"}}})
	r := req("g")
	r.App = "hr-db"
	if d := p.Evaluate(r); d.Action != Deny || d.Reason != "workspace-required" || d.RuleID != "sens" {
		t.Fatalf("outside the workspace: %+v", d)
	}
	r.Workspace = true
	if d := p.Evaluate(r); d.Action != Allow || d.Reason != "workspace" {
		t.Fatalf("inside the workspace: %+v", d)
	}
	r2 := req("g")
	r2.App = "other"
	if d := p.Evaluate(r2); d.RuleID == "sens" {
		t.Fatal("the isolate rule matched an app it does not name")
	}
	web := mk(t, Web, Rule{ID: "risky", Priority: 1, Action: Isolate, Match: Match{Categories: []string{"uncategorised"}}})
	wr := Request{Kind: Web, Host: "x.test", Categories: []string{"uncategorised"}, Now: t0}
	if d := web.Evaluate(wr); d.Action != Deny || d.Reason != "workspace-required" {
		t.Fatalf("%+v", d)
	}
	wr.Workspace = true
	if d := web.Evaluate(wr); d.Action != Allow {
		t.Fatalf("%+v", d)
	}
	yes, no := true, false
	cond := mk(t, Private,
		Rule{ID: "only-ws", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Workspace: &yes}},
		Rule{ID: "not-ws", Priority: 2, Action: Deny, Match: Match{Groups: []string{"g"}, Workspace: &no}})
	a, b := req("g"), req("g")
	b.Workspace = true
	if cond.Evaluate(a).RuleID != "not-ws" || cond.Evaluate(b).RuleID != "only-ws" {
		t.Fatal("the workspace condition did not split the two sides")
	}
}

func TestIsolateValidation(t *testing.T) { // WBT-002
	bare := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Isolate, Match: Match{Groups: []string{"g"}}}}}
	if errs := Validate(bare, nil); len(errs) == 0 {
		t.Fatal("an isolate rule that names no apps, domains or categories would send everything to the workspace")
	}
	ok := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Isolate, Match: Match{Apps: []string{"x"}}}}}
	if errs := Validate(ok, nil); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := Parse([]byte(`{"kind":"web","rules":[{"id":"a","priority":1,"action":"isolate","match":{"categories":["c"]}}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestResponseDLPRules(t *testing.T) { // AI-003 (response side, basic)
	p := mk(t, Web, Rule{ID: "no-pii-back", Priority: 1, Action: Deny, Match: Match{Domains: []string{"ai.example"}, DLPResponse: []string{"credit-card"}}})
	req := Request{Kind: Web, Host: "ai.example", Now: t0, Inspected: true}
	// the request phase ignores response rules, whatever the request body held
	req.DLPHits = []string{"credit-card"}
	if d := p.Evaluate(req); d.Action != Allow {
		t.Fatalf("a response rule fired on the request: %+v", d)
	}
	if !p.UsesResponseDLP() || p.UsesDLP() {
		t.Fatal("UsesResponseDLP / UsesDLP")
	}
	resp := Request{Kind: Web, Host: "ai.example", Now: t0, Inspected: true, ResponseDLPHits: []string{"credit-card", "us-ssn"}}
	if d := p.EvaluateResponse(resp); d.Action != Deny || d.RuleID != "no-pii-back" {
		t.Fatalf("%+v", d)
	}
	resp.ResponseDLPHits = []string{"aws-access-key"}
	if d := p.EvaluateResponse(resp); d.Action != Allow {
		t.Fatalf("an unlisted type must not match: %+v", d)
	}
	resp.ResponseDLPHits, resp.Host = []string{"credit-card"}, "other.example"
	if d := p.EvaluateResponse(resp); d.Action != Allow {
		t.Fatalf("the rule's other conditions still apply: %+v", d)
	}
	// ordinary rules are never re-run on the response
	other := mk(t, Web, Rule{ID: "block-all-x", Priority: 1, Action: Deny, Match: Match{Domains: []string{"x.test"}}})
	if d := other.EvaluateResponse(Request{Kind: Web, Host: "x.test", Now: t0, Inspected: true}); d.Action != Allow {
		t.Fatalf("a request rule was applied to a response: %+v", d)
	}
}

func TestResponseDLPValidation(t *testing.T) {
	bad := map[string]*Policy{
		"allow action":  {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{DLPResponse: []string{"credit-card"}}}}},
		"warn action":   {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Warn, Match: Match{DLPResponse: []string{"credit-card"}}}}},
		"unknown type":  {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{DLPResponse: []string{"nonsense"}}}}},
		"private rules": {Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{Groups: []string{"g"}, DLPResponse: []string{"credit-card"}}}}},
	}
	for name, p := range bad {
		if errs := Validate(p, nil); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	ok := &Policy{Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{DLPResponse: []string{"credit-card"}}}}}
	if errs := Validate(ok, nil); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestCaptureFlagAndValidation(t *testing.T) { // ZIA-022b
	p := mk(t, Web,
		Rule{ID: "cap", Priority: 1, Action: Allow, Capture: true, Match: Match{Domains: []string{"ai.example"}}},
		Rule{ID: "plain", Priority: 2, Action: Allow, Match: Match{Domains: []string{"other.example"}}})
	if d := p.Evaluate(Request{Kind: Web, Host: "ai.example", Now: t0}); !d.Capture || d.RuleID != "cap" {
		t.Fatalf("%+v", d)
	}
	if d := p.Evaluate(Request{Kind: Web, Host: "other.example", Now: t0}); d.Capture {
		t.Fatal("a rule that did not ask for capture produced one")
	}
	if d := p.Evaluate(Request{Kind: Web, Host: "nobody.example", Now: t0}); d.Capture {
		t.Fatal("the default decision must never capture")
	}
	for name, pol := range map[string]*Policy{
		"capture everything": {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Capture: true, Match: Match{Posture: &PostureMatch{DiskEncrypted: bp(true)}}}}},
		"private rule":       {Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Capture: true, Match: Match{Groups: []string{"g"}}}}},
	} {
		if errs := Validate(pol, nil); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRemovableMediaPostureRule(t *testing.T) { // AGT-019 (DATA-005, basic)
	p := mk(t, Private, Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"fin"},
		Posture: &PostureMatch{RemovableMedia: bp(false)}}})
	r := req("fin")
	r.Device.Posture.RemovableMedia = bp(false)
	if p.Evaluate(r).Action != Allow {
		t.Fatal("no removable drive mounted must be allowed")
	}
	r.Device.Posture.RemovableMedia = bp(true)
	if p.Evaluate(r).Action != Deny {
		t.Fatal("a mounted removable drive must be refused")
	}
	r.Device.Posture.RemovableMedia = nil
	if p.Evaluate(r).Action != Deny {
		t.Fatal("unknown must fail closed, like every other posture check")
	}
}

func TestFileTypeRules(t *testing.T) { // AGT-025 (ZIA-013)
	p := &Policy{Kind: Web, DefaultAction: Allow, Rules: []Rule{
		{ID: "up", Priority: 1, Action: Deny, Match: Match{UploadFileTypes: []string{"executable", "ext:.iso"}}},
		{ID: "down", Priority: 2, Action: Deny, Match: Match{DownloadFileTypes: []string{"archive"}}},
	}}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	if errs := Validate(p, nil); len(errs) > 0 {
		t.Fatal(errs)
	}
	req := func(mod func(*Request)) Request {
		r := Request{Kind: Web, Host: "x.example", Now: t0, User: User{Email: "a@example.com"}, Inspected: true}
		mod(&r)
		return r
	}
	if d := p.Evaluate(req(func(r *Request) { r.UploadFiles = []string{"executable"} })); d.Action != Deny || d.RuleID != "up" {
		t.Fatalf("%+v", d)
	}
	if d := p.Evaluate(req(func(r *Request) { r.UploadFiles = []string{"ext:.iso", "disk-image"} })); d.RuleID != "up" {
		t.Fatalf("an explicit extension: %+v", d)
	}
	if d := p.Evaluate(req(func(r *Request) { r.UploadFiles = []string{"pdf"} })); d.Action != Allow {
		t.Fatalf("%+v", d)
	}
	// an upload rule needs decrypted traffic, and does not apply in the response phase
	if d := p.Evaluate(req(func(r *Request) { r.UploadFiles = []string{"executable"}; r.Inspected = false })); d.Action != Allow {
		t.Fatalf("not inspected: %+v", d)
	}
	// a download rule applies only to the response, and only through EvaluateResponse
	if d := p.Evaluate(req(func(r *Request) { r.DownloadFiles = []string{"archive"} })); d.Action != Allow {
		t.Fatalf("a download rule must not fire on the request: %+v", d)
	}
	if d := p.EvaluateResponse(req(func(r *Request) { r.DownloadFiles = []string{"archive"} })); d.Action != Deny || d.RuleID != "down" {
		t.Fatalf("%+v", d)
	}
	if d := p.EvaluateResponse(req(func(r *Request) { r.DownloadFiles = []string{"pdf"} })); d.Action != Allow {
		t.Fatalf("%+v", d)
	}
	if d := p.EvaluateResponse(req(func(r *Request) { r.UploadFiles = []string{"executable"} })); d.Action != Allow {
		t.Fatalf("an upload rule must not fire on the response: %+v", d)
	}
	if !p.UsesUploadFileTypes() || !p.UsesDownloadFileTypes() || (&Policy{}).UsesUploadFileTypes() {
		t.Fatal("Uses*")
	}
}

func TestFileTypeRuleValidation(t *testing.T) { // AGT-025
	bad := map[string]*Policy{
		"warn":         {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Warn, Match: Match{UploadFileTypes: []string{"executable"}}}}},
		"allow":        {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Allow, Match: Match{DownloadFileTypes: []string{"executable"}}}}},
		"unknown type": {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{UploadFileTypes: []string{"malware"}}}}},
		"bad ext":      {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{DownloadFileTypes: []string{"ext:exe"}}}}},
		"private":      {Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{UploadFileTypes: []string{"executable"}}}}},
	}
	for name, p := range bad {
		if err := p.Compile(nil); err == nil && len(Validate(p, nil)) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestCloudAppRules(t *testing.T) { // AGT-031 (ZIA-011)
	p := &Policy{Kind: Web, DefaultAction: Allow, Rules: []Rule{
		{ID: "no-dropbox-up", Priority: 1, Action: Deny, Match: Match{CloudApps: []string{"dropbox"}, CloudActions: []string{"upload", "share"}}},
		{ID: "no-pastebin", Priority: 2, Action: Deny, Match: Match{CloudApps: []string{"pastebin", "github-gist"}}},
		{ID: "slack-post", Priority: 3, Action: Warn, Match: Match{CloudApps: []string{"slack", "teams"}, CloudActions: []string{"post"}}},
	}}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	if errs := Validate(p, nil); len(errs) > 0 {
		t.Fatal(errs)
	}
	req := func(mod func(*Request)) Request {
		r := Request{Kind: Web, Host: "x.example", Now: t0, User: User{Email: "a@example.com"}}
		mod(&r)
		return r
	}
	cases := []struct {
		name string
		mod  func(*Request)
		want Action
		rule string
	}{
		{"an upload to the app", func(r *Request) { r.CloudApps = []string{"dropbox"}; r.CloudActions = []string{"dropbox:upload"} }, Deny, "no-dropbox-up"},
		{"a share", func(r *Request) { r.CloudApps = []string{"dropbox"}; r.CloudActions = []string{"dropbox:share"} }, Deny, "no-dropbox-up"},
		{"a download from the same app", func(r *Request) { r.CloudApps = []string{"dropbox"}; r.CloudActions = []string{"dropbox:download"} }, Allow, ""},
		{"the app, no action known (a tunnel)", func(r *Request) { r.CloudApps = []string{"dropbox"} }, Allow, ""},
		{"another app's upload", func(r *Request) { r.CloudApps = []string{"box"}; r.CloudActions = []string{"box:upload"} }, Allow, ""},
		{"an app rule with no action: the whole app, in a tunnel", func(r *Request) { r.CloudApps = []string{"pastebin"} }, Deny, "no-pastebin"},
		{"the second app of a list", func(r *Request) { r.CloudApps = []string{"github-gist"} }, Deny, "no-pastebin"},
		{"a post in an app of the list", func(r *Request) { r.CloudApps = []string{"slack"}; r.CloudActions = []string{"slack:post"} }, Warn, "slack-post"},
		{"an action of another app is not this app's", func(r *Request) { r.CloudApps = []string{"slack"}; r.CloudActions = []string{"dropbox:post"} }, Allow, ""},
		{"nothing known", func(r *Request) {}, Allow, ""},
	}
	for _, c := range cases {
		if d := p.Evaluate(req(c.mod)); d.Action != c.want || d.RuleID != c.rule {
			t.Errorf("%s: got %s by %q, want %s by %q", c.name, d.Action, d.RuleID, c.want, c.rule)
		}
	}
}

func TestCloudAppRuleValidation(t *testing.T) { // AGT-031
	bad := map[string]*Policy{
		"actions without apps": {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{CloudActions: []string{"upload"}}}}},
		"unknown action":       {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{CloudApps: []string{"box"}, CloudActions: []string{"explode"}}}}},
		"bad app id":           {Kind: Web, DefaultAction: Allow, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{CloudApps: []string{"Bad App!"}}}}},
		"private policy":       {Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "r", Priority: 1, Action: Deny, Match: Match{CloudApps: []string{"box"}}}}},
	}
	for name, p := range bad {
		if err := p.Compile(nil); err == nil && len(Validate(p, nil)) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
}
