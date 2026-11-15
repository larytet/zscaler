// Package advice turns recorded decisions into things an admin can act on:
// suggested rules for repeated denials (OPS-005) and a plain-language
// timeline for one user (OPS-004). Suggestions are drafts to dry-run and
// simulate, never applied automatically.
package advice

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/policy"
)

const MinAttempts = 3

type Suggestion struct {
	Summary  string      `json:"summary"`
	Attempts int         `json:"attempts"`
	Users    []string    `json:"users"`
	Draft    policy.Rule `json:"draft_rule"`
	Caution  string      `json:"caution"`
}

func postureBad(p *broker.PostureSnap) bool {
	return p == nil || p.DiskEncrypted == nil || !*p.DiskEncrypted || p.FirewallOn == nil || !*p.FirewallOn
}

// Suggest looks at private-access denials that came from the default deny
// (no rule matched). Where most attempts came from devices that fail the
// baseline, it recommends fixing the devices instead of widening a rule.
func Suggest(entries []decisions.Entry) (out []Suggestion, deviceProblems []string) {
	type agg struct {
		attempts, badPosture int
		users                map[string]bool
		groups               map[string]map[string]bool // group -> users
	}
	byApp := map[string]*agg{}
	for _, e := range entries {
		if e.Kind != "private" || e.Event != "open" || e.Action != "deny" || e.Reason != "default" || e.App == "" {
			continue
		}
		a := byApp[e.App]
		if a == nil {
			a = &agg{users: map[string]bool{}, groups: map[string]map[string]bool{}}
			byApp[e.App] = a
		}
		a.attempts++
		if postureBad(e.Posture) {
			a.badPosture++
		}
		a.users[e.User] = true
		for _, g := range e.Groups {
			if a.groups[g] == nil {
				a.groups[g] = map[string]bool{}
			}
			a.groups[g][e.User] = true
		}
	}
	apps := make([]string, 0, len(byApp))
	for k := range byApp {
		apps = append(apps, k)
	}
	sort.Strings(apps)
	for _, app := range apps {
		a := byApp[app]
		if a.attempts < MinAttempts {
			continue
		}
		users := keys(a.users)
		if a.badPosture*2 >= a.attempts { // half or more from unhealthy devices
			deviceProblems = append(deviceProblems, fmt.Sprintf(
				"%d of %d blocked attempts at %s came from devices that do not meet the security baseline (disk encryption or firewall off or unknown). Fixing those devices is likely a better answer than a new rule: %s.",
				a.badPosture, a.attempts, app, strings.Join(users, ", ")))
			continue
		}
		// the group that covers the most blocked users, ties alphabetical
		best, bestN := "", 0
		for g, us := range a.groups {
			if len(us) > bestN || (len(us) == bestN && g < best) {
				best, bestN = g, len(us)
			}
		}
		r := policy.Rule{ID: "suggested-" + app, Priority: 500, Action: policy.Allow,
			Reason: "Suggested from repeated blocked attempts; review before applying",
			Match:  policy.Match{Apps: []string{app}}}
		s := Suggestion{Attempts: a.attempts, Users: users, Draft: r,
			Caution: "This widens access. Run it through simulate first, and confirm with the people who own the app."}
		if best != "" && bestN >= 1 {
			s.Draft.Match.Groups = []string{best}
			covered := keys(a.groups[best])
			s.Users = covered
			s.Summary = fmt.Sprintf("%d people in group %q were blocked from %s %d times. If they should have access, allow that group.", len(covered), best, app, a.attempts)
		} else {
			s.Draft.Match.Users = users
			s.Summary = fmt.Sprintf("%s were blocked from %s %d times and belong to no group. If they should have access, allow them by name.", strings.Join(users, ", "), app, a.attempts)
		}
		out = append(out, s)
	}
	return out, deviceProblems
}

func keys(m map[string]bool) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

type Step struct {
	TS      time.Time `json:"ts"`
	What    string    `json:"what"`
	Why     string    `json:"why"`
	Fix     string    `json:"fix,omitempty"`
	Outcome string    `json:"outcome"`
}

type Investigation struct {
	User     string `json:"user"`
	Summary  string `json:"summary"`
	Timeline []Step `json:"timeline"` // newest first, at most 50
}

func baseline(p *broker.PostureSnap) string {
	if p == nil {
		return "no posture report from the device"
	}
	var bad []string
	if p.DiskEncrypted == nil {
		bad = append(bad, "disk encryption could not be checked")
	} else if !*p.DiskEncrypted {
		bad = append(bad, "disk encryption is off")
	}
	if p.FirewallOn == nil {
		bad = append(bad, "the firewall could not be checked")
	} else if !*p.FirewallOn {
		bad = append(bad, "the firewall is off")
	}
	return strings.Join(bad, " and ")
}

// Explain describes one decision in plain words.
func Explain(e decisions.Entry) Step {
	st := Step{TS: e.TS, Outcome: e.Action}
	target := e.App
	if e.Kind == "web" {
		target = e.Target
	}
	switch {
	case e.Action == "allow":
		st.What = "Reached " + target
		st.Why = "Allowed"
		if e.Rule != "" {
			st.Why += " by rule " + e.Rule
		}
		return st
	case e.Action == "warn":
		st.What = "Visited " + target
		st.Why = "A warning page was shown (rule " + e.Rule + ")"
		return st
	}
	st.What = "Tried to reach " + target
	switch e.Reason {
	case "user-disabled":
		st.Why, st.Fix = "The account is disabled.", "If this person should still have access, re-enable the account in your identity provider and ask them to sign in again."
	case "device-revoked":
		st.Why, st.Fix = "This device was revoked.", "If it was revoked by mistake, the person needs to enrol the device again."
	case "unknown-app":
		st.Why, st.Fix = "The application name does not exist.", "Check the app name in the agent configuration against the segments in the console."
	case "target-not-in-segment":
		st.Why, st.Fix = "The address or port asked for is not part of that application.", "Check the segment's targets and the port the person used."
	case "no-connector":
		st.Why, st.Fix = "The connector for that site was not reachable.", "Check that the site's connector host is on and online. Apps behind it are unavailable until then."
	case "state-stale":
		st.Why, st.Fix = "The enforcement node had lost contact with the control plane.", "Check the control plane and the node's network."
	case "log-sink-unavailable":
		st.Why, st.Fix = "The node could not write its decision log.", "Check free disk space on the enforcement node."
	case "no-policy":
		st.Why, st.Fix = "No access policy is set for this tenant.", "Apply the safe defaults or write a policy."
	default:
		if e.Kind == "web" {
			st.Why = "Blocked by rule " + e.Rule + "."
			st.Fix = "If the site is legitimate, adjust the web policy or its category."
			break
		}
		if e.Reason == "default" && postureBad(e.Posture) {
			st.Why = "No rule allowed it, and the device does not meet the security baseline: " + baseline(e.Posture) + "."
			st.Fix = "Fix the device first (turn on disk encryption and the firewall). Changing the rule is not the answer."
		} else if e.Reason == "default" {
			st.Why = fmt.Sprintf("No rule allows group(s) %s to reach %s.", groupsText(e.Groups), e.App)
			st.Fix = "If this person should have access, simulate and add a rule for their group."
		} else {
			st.Why = "Blocked by rule " + e.Rule + "."
			if e.Reason != "" {
				st.Why += " (" + e.Reason + ")"
			}
			st.Fix = "Check what rule " + e.Rule + " is meant to do, and whether its posture or time conditions apply."
		}
	}
	return st
}

func groupsText(g []string) string {
	if len(g) == 0 {
		return "(none)"
	}
	return `"` + strings.Join(g, `", "`) + `"`
}

// Investigate builds the timeline for a user from their decisions.
func Investigate(user string, entries []decisions.Entry) Investigation {
	inv := Investigation{User: user, Timeline: []Step{}}
	var mine []decisions.Entry
	for _, e := range entries {
		if e.User == user && e.Event == "open" {
			mine = append(mine, e)
		}
	}
	if len(mine) == 0 {
		inv.Summary = "No recorded activity for " + user + " in this period. Either they have not tried to use anything, or their requests are not reaching an enforcement node: check that the agent is running and signed in."
		return inv
	}
	why := map[string]int{}
	fix := map[string]string{}
	allowed := 0
	for i := len(mine) - 1; i >= 0; i-- {
		s := Explain(mine[i])
		if s.Outcome == "allow" {
			allowed++
		} else {
			why[s.Why]++
			fix[s.Why] = s.Fix
		}
		if len(inv.Timeline) < 50 {
			inv.Timeline = append(inv.Timeline, s)
		}
	}
	if len(why) == 0 {
		inv.Summary = fmt.Sprintf("%s was allowed every time (%d attempts). Nothing looks wrong on the access side.", user, allowed)
		return inv
	}
	top, n := "", 0
	for w, c := range why {
		if c > n || (c == n && w < top) {
			top, n = w, c
		}
	}
	inv.Summary = fmt.Sprintf("%s was blocked %d of %d times. Most common reason: %s %s", user, sumMap(why), len(mine), top, fix[top])
	return inv
}

func sumMap(m map[string]int) int {
	t := 0
	for _, v := range m {
		t += v
	}
	return t
}
