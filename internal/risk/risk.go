// Package risk computes a simple, explainable 0 to 100 risk score per user
// from signals the product already has (ARCH-007). It is deliberately not a
// model: every point has a stated reason an admin can check.
package risk

import (
	"sort"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/decisions"
)

// Points per signal. Kept small and visible so admins can reason about thresholds.
const (
	PostureFailing = 40 // an open "device fell below the baseline" alert
	ManyDenies     = 30 // 10 or more blocked private-access attempts in the last hour
	SomeDenies     = 15 // 3 to 9 in the last hour
	WebBlocks      = 20 // 5 or more blocked web requests in the last 24 hours
)

type Score struct {
	User    string   `json:"user"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}

// Compute scores every user that has any signal. Users with no signal are omitted (score 0).
func Compute(now time.Time, entries []decisions.Entry, open []alerts.Alert) []Score {
	type acc struct {
		score   int
		reasons []string
		denies  int
		webBlk  int
	}
	by := map[string]*acc{}
	get := func(u string) *acc {
		if by[u] == nil {
			by[u] = &acc{}
		}
		return by[u]
	}
	hour, day := now.Add(-time.Hour), now.Add(-24*time.Hour)
	for _, e := range entries {
		if e.Event != "open" || e.Action != "deny" || e.User == "" {
			continue
		}
		switch {
		case e.Kind == "private" && !e.TS.Before(hour):
			get(e.User).denies++
		case e.Kind == "web" && !e.TS.Before(day):
			get(e.User).webBlk++
		}
	}
	for _, a := range open {
		if a.Kind == "posture-failed" && a.User != "" && a.Closed == nil {
			x := get(a.User)
			x.score += PostureFailing
			x.reasons = append(x.reasons, "a device is below the security baseline")
		}
	}
	var out []Score
	for u, x := range by {
		switch {
		case x.denies >= 10:
			x.score += ManyDenies
			x.reasons = append(x.reasons, "many blocked access attempts in the last hour")
		case x.denies >= 3:
			x.score += SomeDenies
			x.reasons = append(x.reasons, "several blocked access attempts in the last hour")
		}
		if x.webBlk >= 5 {
			x.score += WebBlocks
			x.reasons = append(x.reasons, "repeated blocked web requests in the last day")
		}
		if x.score == 0 {
			continue
		}
		if x.score > 100 {
			x.score = 100
		}
		out = append(out, Score{User: u, Score: x.score, Reasons: x.reasons})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].User < out[j].User
	})
	return out
}
