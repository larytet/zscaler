package policy

import (
	"math/rand"
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

func TestShadowedRuleWarning(t *testing.T) { // VAL-009
	g := Match{Groups: []string{"g"}}
	p := &Policy{Kind: Private, DefaultAction: Deny, Rules: []Rule{
		{ID: "first", Priority: 1, Action: Deny, Match: g},
		{ID: "dup", Priority: 2, Action: Allow, Match: g},
		{ID: "other", Priority: 3, Action: Allow, Match: Match{Groups: []string{"h"}}},
	}}
	if errs := Validate(p, nil); len(errs) != 0 {
		t.Fatalf("shadowing must not be an error: %v", errs)
	}
	w := Warnings(p)
	if len(w) != 1 || !strings.Contains(w[0], `"dup"`) {
		t.Fatalf("%v", w)
	}
	all := &Policy{Kind: Web, DefaultAction: Allow, Rules: []Rule{
		{ID: "deny-all", Priority: 1, Action: Deny},
		{ID: "later", Priority: 2, Action: Deny, Match: Match{Categories: []string{"x"}}},
	}}
	if w := Warnings(all); len(w) != 1 {
		t.Fatalf("%v", w)
	}
}

// VAL-010: valid policies all compile; VAL-011: each invalid one fails with its own error.
func TestCorpora(t *testing.T) {
	valid := []string{
		`{"kind":"private","default_action":"deny","rules":[]}`,
		`{"kind":"web","default_action":"allow","rules":[]}`,
		`{"kind":"web","rules":[]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"]}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"users":["a@b.c"]}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"apps":["x"]}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"deny"}]}`,
		`{"kind":"web","rules":[{"id":"a","priority":1,"action":"warn","match":{"categories":["c"]}}]}`,
		`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["example.com"]}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"],"posture":{"disk_encrypted":true}}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"],"posture":{"min_os":{"linux":"6.1"},"max_age_seconds":60}}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"],"time":{"days":["mon","fri"]}}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"],"time":{"from":"22:00","to":"06:00","tz":"UTC"}}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"],"network":{"src_cidrs":["10.0.0.0/8","2001:db8::/32"]}}}]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"]}},{"id":"b","priority":2,"action":"deny","match":{"groups":["h"]}}]}`,
		`{"kind":"web","rules":[{"id":"a","priority":-5,"action":"deny","match":{"domains":["a.test","b.test"]}}]}`,
		`{"kind":"private","version":3,"default_action":"deny","rules":[]}`,
		`{"kind":"web","default_action":"warn","rules":[]}`,
		`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","reason":"because","match":{"groups":["g"],"apps":["x","y"]}}]}`,
		`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["xn--bcher-kva.example"]}}]}`,
	}
	for i, j := range valid {
		if _, err := Parse([]byte(j)); err != nil {
			t.Errorf("valid[%d] rejected: %v\n%s", i, err, j)
		}
	}
	type bad struct{ json, want string }
	rule := func(extra string) string {
		return `{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow","match":{"groups":["g"]` + extra + `}}]}`
	}
	invalid := []bad{
		{`{"kind":"other","rules":[]}`, "unknown kind"},
		{`{"rules":[]}`, "unknown kind"},
		{`{"kind":"private","rules":[]}`, "must be deny"},
		{`{"kind":"private","default_action":"allow","rules":[]}`, "must be deny"},
		{`{"kind":"web","default_action":"maybe","rules":[]}`, "unknown default_action"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"","priority":1,"action":"deny"}]}`, "empty id"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"deny"},{"id":"a","priority":2,"action":"deny"}]}`, "duplicate id"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"deny"},{"id":"b","priority":1,"action":"deny"}]}`, "duplicate priority"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"permit"}]}`, "unknown action"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"allow"}]}`, "matches everything"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":1,"action":"warn","match":{"groups":["g"]}}]}`, "warn is only valid"},
		{rule(`,"network":{"src_cidrs":["10.0.0.0/33"]}`), "bad CIDR"},
		{rule(`,"network":{"src_cidrs":["not-a-cidr"]}`), "bad CIDR"},
		{rule(`,"network":{"src_cidrs":["10.0.0.1"]}`), "bad CIDR"},
		{rule(`,"time":{"tz":"Mars/Base"}`), "bad time zone"},
		{rule(`,"time":{"from":"25:00","to":"26:00"}`), "bad time"},
		{rule(`,"time":{"from":"07:00"}`), "both from and to"},
		{rule(`,"time":{"from":"7am","to":"8pm"}`), "bad time"},
		{rule(`,"time":{"days":["funday"]}`), "bad day"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["https://x.com"]}}]}`, "bad domain"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["x.com/path"]}}]}`, "bad domain"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["x.com:443"]}}]}`, "bad domain"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":[""]}}]}`, "bad domain"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"deny","match":{"domains":["a b.com"]}}]}`, "bad domain"},
		{`{"kind":"web","rules":[{"id":"a","priority":1,"action":"allow"}]}`, "matches everything"},
		{`not json`, "policy json"},
		{`{"kind":"private","default_action":"deny","rules":"nope"}`, "policy json"},
		{`{"kind":"private","default_action":"deny","rules":[{"id":"a","priority":"one","action":"deny"}]}`, "policy json"},
		{`[]`, "policy json"},
		{``, "policy json"},
	}
	if len(invalid) != 30 {
		t.Fatalf("corpus has %d invalid cases, the plan calls for 30", len(invalid))
	}
	for i, c := range invalid {
		_, err := Parse([]byte(c.json))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("invalid[%d]: want %q, got %v\n%s", i, c.want, err, c.json)
		}
	}
}

// FUZ-005: the suffix matcher agrees with a naive reference on random host names.
func TestHostMatchesAgainstReference(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	labels := []string{"a", "b", "example", "com", "net", "evil"}
	name := func() string {
		var parts []string
		for i := 0; i < 1+rnd.Intn(4); i++ {
			parts = append(parts, labels[rnd.Intn(len(labels))])
		}
		return strings.Join(parts, ".")
	}
	for i := 0; i < 5000; i++ {
		d, h := name(), name()
		want := h == d || strings.HasSuffix("."+h, "."+d)
		if got := hostMatches([]string{d}, h); got != want {
			t.Fatalf("domain %q host %q: got %v want %v", d, h, got, want)
		}
	}
}
