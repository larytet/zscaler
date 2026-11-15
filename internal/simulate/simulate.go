// Package simulate replays recorded access decisions against a draft policy
// and reports what would change (ZPA-028, ADM-020), so an admin can see the
// effect of a rule change before applying it.
package simulate

import (
	"sort"

	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/policy"
)

type Change struct {
	User string   `json:"user"`
	App  string   `json:"app"`
	From string   `json:"from"`
	To   string   `json:"to"`
	Rule string   `json:"draft_rule,omitempty"`
	N    int      `json:"count"`
	Why  string   `json:"why"`
	Grp  []string `json:"groups,omitempty"`
}

type Result struct {
	Replayed     int      `json:"replayed"`
	Unchanged    int      `json:"unchanged"`
	NewlyDenied  int      `json:"newly_denied"`
	NewlyAllowed int      `json:"newly_allowed"`
	Skipped      int      `json:"skipped_not_policy_decisions"`
	Changes      []Change `json:"changes"` // most frequent first, at most 20
	Caveats      []string `json:"caveats"`
}

// nonPolicy reasons come from the machinery, not from rule evaluation, so a
// different policy would not have changed them.
var nonPolicy = map[string]bool{"unknown-app": true, "target-not-in-segment": true, "no-connector": true,
	"state-stale": true, "log-sink-unavailable": true, "no-policy": true, "unknown-user": true, "evaluation-error": true}

func Run(draft *policy.Policy, entries []decisions.Entry) Result {
	res := Result{Changes: []Change{}, Caveats: []string{
		"Only private-access sessions are replayed. Web decisions are not, because records do not keep the category list.",
		"Source IP is not recorded, so rules that match on network address are replayed as if the address were unknown.",
		"A user's groups and device posture are those recorded at the time of each decision.",
		"Risk scores are not recorded, so rules that use max_risk or min_risk are replayed as if every user had risk 0.",
	}}
	type key struct{ user, app, from, to, rule string }
	agg := map[key]*Change{}
	for _, e := range entries {
		if e.Kind != "private" || e.Event != "open" || e.App == "" {
			continue
		}
		if nonPolicy[e.Reason] {
			res.Skipped++
			continue
		}
		var pos *policy.Posture
		if e.Posture != nil {
			pos = &policy.Posture{OS: e.Posture.OS, OSVersion: e.Posture.OSVersion, DiskEncrypted: e.Posture.DiskEncrypted,
				FirewallOn: e.Posture.FirewallOn, ScreenLock: e.Posture.ScreenLock, RemovableMedia: e.Posture.RemovableMedia, ReportedAt: e.Posture.ReportedAt}
		}
		d := draft.Evaluate(policy.Request{Kind: policy.Private, App: e.App, Now: e.TS,
			User:   policy.User{Subject: e.User, Email: e.User, Groups: e.Groups},
			Device: policy.Device{Posture: pos}})
		res.Replayed++
		was := e.Action
		now := string(d.Action)
		if was == now {
			res.Unchanged++
			continue
		}
		if now == "allow" {
			res.NewlyAllowed++
		} else {
			res.NewlyDenied++
		}
		k := key{e.User, e.App, was, now, d.RuleID}
		if c := agg[k]; c != nil {
			c.N++
			continue
		}
		why := "no rule in the draft allows it (default deny)"
		if d.RuleID != "" {
			why = "draft rule " + d.RuleID + " decides it"
		}
		if d.Reason == "user-disabled" || d.Reason == "device-revoked" {
			why = d.Reason
		}
		agg[k] = &Change{User: e.User, App: e.App, From: was, To: now, Rule: d.RuleID, N: 1, Why: why, Grp: e.Groups}
	}
	for _, c := range agg {
		res.Changes = append(res.Changes, *c)
	}
	sort.Slice(res.Changes, func(i, j int) bool {
		if res.Changes[i].N != res.Changes[j].N {
			return res.Changes[i].N > res.Changes[j].N
		}
		return res.Changes[i].User+res.Changes[i].App < res.Changes[j].User+res.Changes[j].App
	})
	if len(res.Changes) > 20 {
		res.Changes = res.Changes[:20]
	}
	if res.Replayed == 0 {
		res.Caveats = append(res.Caveats, "There were no recorded private-access decisions to replay in this period, so this says nothing about the draft.")
	}
	return res
}
