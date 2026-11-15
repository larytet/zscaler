package policy

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Rule{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}}}
	cases := []struct {
		id, want string
		p        Policy
	}{
		{"VAL-001", "duplicate id", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{ok, {ID: "a", Priority: 2, Action: Deny}}}},
		{"VAL-002", "duplicate priority", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{ok, {ID: "b", Priority: 1, Action: Deny}}}},
		{"VAL-003", "unknown action", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: "maybe"}}}},
		{"VAL-004", "default_action must be deny", Policy{Kind: Private, DefaultAction: Allow}},
		{"VAL-004b", "default_action must be deny", Policy{Kind: Private}},
		{"VAL-005", "matches everything", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow}}}},
		{"VAL-006a", "bad CIDR", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Network: &NetworkMatch{SrcCIDRs: []string{"10.0.0.0/33"}}}}}}},
		{"VAL-006b", "bad time zone", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Time: &TimeMatch{TZ: "Mars/Base"}}}}}},
		{"VAL-006c", "bad time", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Groups: []string{"g"}, Time: &TimeMatch{From: "25:00", To: "26:00"}}}}}},
		{"VAL-008a", "bad domain", Policy{Kind: Web, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{Domains: []string{"https://x.com"}}}}}},
		{"VAL-008b", "bad domain", Policy{Kind: Web, Rules: []Rule{{ID: "a", Priority: 1, Action: Deny, Match: Match{Domains: []string{"x.com/path"}}}}}},
		{"VAL-warn", "warn is only valid", Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Warn, Match: Match{Groups: []string{"g"}}}}}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			errs := Validate(&c.p, nil)
			if len(errs) == 0 {
				t.Fatal("no error")
			}
			found := false
			for _, e := range errs {
				found = found || strings.Contains(e.Error(), c.want)
			}
			if !found {
				t.Fatalf("want %q in %v", c.want, errs)
			}
		})
	}
}

func TestValidateUnknownSegment(t *testing.T) { // VAL-007
	p := Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{{ID: "a", Priority: 1, Action: Allow, Match: Match{Apps: []string{"nope"}}}}}
	if errs := Validate(&p, map[string]bool{"seg1": true}); len(errs) != 1 || !strings.Contains(errs[0].Error(), "unknown segment") {
		t.Fatal(errs)
	}
	if errs := Validate(&p, nil); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestParseValid(t *testing.T) { // VAL-010 (single sample; corpus comes with the store part)
	_, err := Parse([]byte(`{"kind":"private","default_action":"deny","rules":[{"id":"r","priority":1,"action":"allow","match":{"groups":["finance"],"apps":["seg1"],"posture":{"disk_encrypted":true,"max_age_seconds":3600},"time":{"days":["mon"],"from":"07:00","to":"20:00","tz":"Europe/Berlin"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
}
