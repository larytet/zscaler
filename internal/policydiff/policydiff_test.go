package policydiff

import (
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/policy"
)

func pol(def policy.Action, rules ...policy.Rule) *policy.Policy {
	return &policy.Policy{Kind: policy.Web, DefaultAction: def, Rules: rules}
}

func TestDiffNamesWhatChanged(t *testing.T) { // AGT-021 (ADM-004)
	a := policy.Rule{ID: "a", Priority: 1, Action: policy.Allow, Match: policy.Match{Domains: []string{"x.com"}}}
	b := policy.Rule{ID: "b", Priority: 2, Action: policy.Deny, Match: policy.Match{Categories: []string{"gambling"}}}
	if r := Diff(pol(policy.Allow, a, b), pol(policy.Allow, b, a)); !r.Same || len(r.Changes) != 0 {
		t.Fatalf("the order of the list is not a change by itself: %+v", r)
	}
	a2 := a
	a2.Action = policy.Deny
	c := policy.Rule{ID: "c", Priority: 3, Action: policy.Warn}
	r := Diff(pol(policy.Allow, a, b), pol(policy.Deny, a2, c))
	if r.Same {
		t.Fatal("changes missed")
	}
	got := map[string]string{}
	for _, ch := range r.Changes {
		got[ch.Kind+":"+ch.Rule] = ch.Text
	}
	for _, k := range []string{"default_action:", "rule_changed:a", "rule_removed:b", "rule_added:c"} {
		if got[k] == "" {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	if !strings.Contains(got["rule_removed:b"], "gambling") || !strings.Contains(got["rule_changed:a"], "deny") {
		t.Fatalf("the text should say what the rule was: %v", got)
	}
	if r := Diff(nil, pol(policy.Allow)); r.Same {
		t.Fatal("a missing version is not 'the same'")
	}
}
