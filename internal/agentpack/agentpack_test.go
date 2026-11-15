package agentpack

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

func compiled(t *testing.T, inspection bool) (*policy.Policy, *Pack) {
	p, err := Build(Options{Agent: "agent:bot", Domains: []string{"api.crm.example"}, Model: []string{"api.model.example"}}, inspection)
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Rules: p.Rules}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	if errs := policy.Validate(pol, nil); len(errs) > 0 {
		t.Fatal(errs)
	}
	return pol, p
}

func eval(pol *policy.Policy, user, host, method string, inspected bool) policy.Decision {
	return pol.Evaluate(policy.Request{Kind: policy.Web, User: policy.User{Subject: user, Email: user}, Host: host,
		Now: time.Now(), Inspected: inspected, Method: method, Path: "/"})
}

func TestReadOnlyPackAndEgress(t *testing.T) { // AGT-007, AGT-008
	pol, _ := compiled(t, true)
	cases := []struct {
		name, user, host, method string
		inspected                bool
		want                     policy.Action
	}{
		{"tunnel to a listed service", "agent:bot", "api.crm.example", "CONNECT", false, policy.Allow},
		{"read", "agent:bot", "api.crm.example", "GET", true, policy.Allow},
		{"write", "agent:bot", "api.crm.example", "POST", true, policy.Deny},
		{"delete", "agent:bot", "api.crm.example", "DELETE", true, policy.Deny},
		{"model call is a POST and allowed", "agent:bot", "api.model.example", "POST", true, policy.Allow},
		{"anything else is refused", "agent:bot", "evil.example", "GET", true, policy.Deny},
		{"tunnel elsewhere refused", "agent:bot", "evil.example", "CONNECT", false, policy.Deny},
		{"people are unaffected", "alice", "evil.example", "POST", true, policy.Allow},
		{"another agent is not covered by this pack", "agent:other", "api.crm.example", "POST", true, policy.Allow},
	}
	for _, c := range cases {
		if d := eval(pol, c.user, c.host, c.method, c.inspected); d.Action != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, d.Action, d.Reason, c.want)
		}
	}
}

func TestPackWarnsWhenInspectionIsOff(t *testing.T) { // AGS-002 limits are stated
	_, off := compiled(t, false)
	_, on := compiled(t, true)
	has := func(p *Pack, s string) bool {
		for _, w := range p.Warnings {
			if strings.Contains(w, s) {
				return true
			}
		}
		return false
	}
	if !has(off, "NOT blocked") || has(on, "NOT blocked") {
		t.Fatalf("off=%v on=%v", off.Warnings, on.Warnings)
	}
	if !has(on, "exempt") {
		t.Fatal("the exempt-list limit must always be stated")
	}
}

func TestPackRejectsBadInput(t *testing.T) {
	for _, o := range []Options{{Agent: "alice", Domains: []string{"a.example"}}, {Agent: "agent:x"},
		{Agent: "agent:x", Domains: []string{"https://a.example/path"}}, {Agent: "agent:x", Domains: []string{"*.example"}}} {
		if _, err := Build(o, true); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}
