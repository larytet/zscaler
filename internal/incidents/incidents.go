// Package incidents correlates what the product already knows about a person into one
// story with a severity (ZIA-022c, basic): a failing device, repeated blocked access,
// blocked uploads or downloads of sensitive data, repeated web blocks. Fixed rules, no model.
package incidents

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/risk"
)

type Severity string

const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

type Incident struct {
	User     string    `json:"user"`
	Severity Severity  `json:"severity"`
	Score    int       `json:"risk_score"`
	Signals  []string  `json:"signals"`
	Summary  string    `json:"summary"`
	Actions  []string  `json:"recommended_actions"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
}

// Window is how far back events are correlated.
const Window = 24 * time.Hour

type acc struct {
	user                         string
	signals                      []string
	actions                      []string
	first, last                  time.Time
	denies, webBlocks, dlpBlocks int
	dlpTypes                     map[string]bool
	devices                      int
}

func (a *acc) touch(t time.Time) {
	if a.first.IsZero() || t.Before(a.first) {
		a.first = t
	}
	if t.After(a.last) {
		a.last = t
	}
}

// Build returns incidents for users with at least one signal, most severe first.
func Build(now time.Time, entries []decisions.Entry, open []alerts.Alert, scores []risk.Score) []Incident {
	by := map[string]*acc{}
	get := func(u string) *acc {
		if by[u] == nil {
			by[u] = &acc{user: u, dlpTypes: map[string]bool{}}
		}
		return by[u]
	}
	cut := now.Add(-Window)
	for _, e := range entries {
		if e.Event != "open" || e.Action != "deny" || e.User == "" || e.TS.Before(cut) {
			continue
		}
		a := get(e.User)
		switch {
		case len(e.DLP) > 0:
			a.dlpBlocks++
			for _, d := range e.DLP {
				a.dlpTypes[d] = true
			}
			a.touch(e.TS)
		case e.Kind == "web":
			a.webBlocks++
			a.touch(e.TS)
		case e.Kind == "private" && e.Reason != "approval-required" && (e.Reason == "default" || e.Reason == "workspace-required" || e.Rule != ""):
			a.denies++
			a.touch(e.TS)
		}
	}
	for _, al := range open {
		if al.Closed != nil || al.User == "" {
			continue
		}
		if al.Kind == "posture-failed" {
			a := get(al.User)
			a.devices++
			a.touch(al.Opened)
			a.actions = append(a.actions, al.Action)
		}
	}
	scoreOf := map[string]risk.Score{}
	for _, s := range scores {
		scoreOf[s.User] = s
	}
	var out []Incident
	for u, a := range by {
		var kinds int
		var parts []string
		if a.devices > 0 {
			kinds++
			parts = append(parts, "their device is below the security baseline")
			a.signals = append(a.signals, "device-below-baseline")
		}
		if a.denies >= 3 {
			kinds++
			parts = append(parts, fmt.Sprintf("they were blocked %d times from private apps", a.denies))
			a.signals = append(a.signals, "repeated-blocked-access")
			a.actions = append(a.actions, "Check whether they should have access to what they keep trying, or whether the account is being misused.")
		}
		if a.webBlocks >= 5 {
			kinds++
			parts = append(parts, fmt.Sprintf("%d of their web requests were blocked", a.webBlocks))
			a.signals = append(a.signals, "repeated-blocked-web")
			a.actions = append(a.actions, "Look at which sites they tried: repeated blocks can mean malware on the device.")
		}
		if a.dlpBlocks > 0 {
			kinds++
			types := make([]string, 0, len(a.dlpTypes))
			for t := range a.dlpTypes {
				types = append(types, t)
			}
			sort.Strings(types)
			parts = append(parts, fmt.Sprintf("%d transfer(s) containing sensitive data (%s) were blocked", a.dlpBlocks, strings.Join(types, ", ")))
			a.signals = append(a.signals, "sensitive-data-blocked")
			a.actions = append(a.actions, "Ask them what they were sending and why; if it was deliberate, restrict the account.")
		}
		if kinds == 0 {
			continue
		}
		sc := scoreOf[u]
		sev := Low
		switch {
		case a.dlpBlocks > 0 && kinds >= 2, kinds >= 3, sc.Score >= 70:
			sev = High
		case kinds >= 2, a.dlpBlocks > 0, sc.Score >= 40:
			sev = Medium
		}
		if sev == High {
			a.actions = append(a.actions, "Consider restricting the account now (POST /v1/users/"+u+"/restrict) while you look.")
		}
		out = append(out, Incident{User: u, Severity: sev, Score: sc.Score, Signals: a.signals,
			Summary: fmt.Sprintf("%s: %s.", u, join(parts)), Actions: dedupe(a.actions), First: a.first, Last: a.last})
	}
	rank := map[Severity]int{High: 0, Medium: 1, Low: 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].User < out[j].User
	})
	return out
}

func join(parts []string) string {
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
