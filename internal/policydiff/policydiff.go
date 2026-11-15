// Package policydiff describes what changed between two versions of a policy, in plain terms an
// admin can read before deciding to roll back (ADM-004).
package policydiff

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/larytet/zscaler/internal/policy"
)

// Change is one difference.
type Change struct {
	Kind string `json:"kind"` // "default_action", "rule_added", "rule_removed", "rule_changed"
	Rule string `json:"rule,omitempty"`
	Text string `json:"text"`
}

// Result is the whole comparison.
type Result struct {
	Changes []Change `json:"changes"`
	Same    bool     `json:"same"`
}

func canon(r policy.Rule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// Diff compares two policies. Rules are matched by their ID.
func Diff(from, to *policy.Policy) Result {
	var res Result
	if from == nil || to == nil {
		res.Changes = []Change{{Kind: "rule_changed", Text: "one of the versions is missing"}}
		return res
	}
	if from.DefaultAction != to.DefaultAction {
		res.Changes = append(res.Changes, Change{Kind: "default_action",
			Text: fmt.Sprintf("default action changed from %q to %q", from.DefaultAction, to.DefaultAction)})
	}
	old := map[string]policy.Rule{}
	for _, r := range from.Rules {
		old[r.ID] = r
	}
	cur := map[string]policy.Rule{}
	for _, r := range to.Rules {
		cur[r.ID] = r
	}
	ids := map[string]bool{}
	for id := range old {
		ids[id] = true
	}
	for id := range cur {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		o, hadOld := old[id]
		c, hasNew := cur[id]
		switch {
		case !hadOld:
			res.Changes = append(res.Changes, Change{Kind: "rule_added", Rule: id, Text: fmt.Sprintf("rule %q added: %s", id, describe(c))})
		case !hasNew:
			res.Changes = append(res.Changes, Change{Kind: "rule_removed", Rule: id, Text: fmt.Sprintf("rule %q removed (it was: %s)", id, describe(o))})
		case canon(o) != canon(c):
			res.Changes = append(res.Changes, Change{Kind: "rule_changed", Rule: id, Text: fmt.Sprintf("rule %q changed: was %s; now %s", id, describe(o), describe(c))})
		}
	}
	res.Same = len(res.Changes) == 0
	if res.Changes == nil {
		res.Changes = []Change{}
	}
	return res
}

func describe(r policy.Rule) string {
	m := r.Match
	s := fmt.Sprintf("%s, priority %d", r.Action, r.Priority)
	add := func(label string, v []string) {
		if len(v) > 0 {
			s += fmt.Sprintf(", %s %v", label, v)
		}
	}
	add("users", m.Users)
	add("groups", m.Groups)
	add("apps", m.Apps)
	add("domains", m.Domains)
	add("categories", m.Categories)
	add("paths", m.Paths)
	add("methods", m.Methods)
	add("dlp", m.DLP)
	add("dlp_response", m.DLPResponse)
	if m.Posture != nil {
		s += ", with a posture condition"
	}
	if m.Time != nil {
		s += ", with a time condition"
	}
	if r.Capture {
		s += ", captures"
	}
	if r.Inject != "" {
		s += ", injects " + r.Inject
	}
	return s
}
