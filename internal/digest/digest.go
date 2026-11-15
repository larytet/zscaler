// Package digest builds the plain-language weekly summary for the person who
// is the security team (ADM-009): what happened, and the few things to fix.
package digest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/decisions"
)

type Pair struct {
	Who   string `json:"who"`
	What  string `json:"what"`
	Count int    `json:"count"`
}

type Digest struct {
	Tenant       string    `json:"tenant"`
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	PrivateAllow int       `json:"private_sessions_allowed"`
	PrivateDeny  int       `json:"private_sessions_denied"`
	WebBlocked   int       `json:"web_requests_blocked"`
	WebWarned    int       `json:"web_requests_warned"`
	TopDenied    []Pair    `json:"top_denied"`
	OpenAlerts   []string  `json:"open_alerts"`
	ThingsToFix  []string  `json:"things_to_fix"`
	// AdminChanges lists who was given, lost or had replaced administrator access in the period.
	AdminChanges  []string `json:"administrator_changes"`
	NoDataWarning string   `json:"no_data_warning,omitempty"`
}

// Build summarises [from, to). Only "open" events of access decisions count.
func Build(tenant string, from, to time.Time, entries []decisions.Entry, al []alerts.Alert) Digest {
	d := Digest{Tenant: tenant, From: from, To: to}
	pairs := map[[2]string]int{}
	counted := 0
	for _, e := range entries {
		if e.Event != "open" || e.TS.Before(from) || !e.TS.Before(to) {
			continue
		}
		counted++
		switch {
		case e.Kind == "private" && e.Action == "allow":
			d.PrivateAllow++
		case e.Kind == "private" && e.Action == "deny":
			d.PrivateDeny++
			pairs[[2]string{e.User, e.App}]++
		case e.Kind == "web" && e.Action == "deny":
			d.WebBlocked++
		case e.Kind == "web" && e.Action == "warn":
			d.WebWarned++
		}
	}
	for k, n := range pairs {
		d.TopDenied = append(d.TopDenied, Pair{k[0], k[1], n})
	}
	sort.Slice(d.TopDenied, func(i, j int) bool {
		if d.TopDenied[i].Count != d.TopDenied[j].Count {
			return d.TopDenied[i].Count > d.TopDenied[j].Count
		}
		return d.TopDenied[i].Who+d.TopDenied[i].What < d.TopDenied[j].Who+d.TopDenied[j].What
	})
	if len(d.TopDenied) > 3 {
		d.TopDenied = d.TopDenied[:3]
	}
	d.OpenAlerts = []string{}
	for _, a := range al {
		if a.Closed == nil {
			d.OpenAlerts = append(d.OpenAlerts, a.Message)
			d.ThingsToFix = append(d.ThingsToFix, a.Action)
		}
	}
	if len(d.TopDenied) > 0 && d.TopDenied[0].Count >= 5 {
		t := d.TopDenied[0]
		d.ThingsToFix = append(d.ThingsToFix, fmt.Sprintf("%s was blocked %s from %s. Decide whether they should have access.", t.Who, times(t.Count), t.What))
	}
	if len(d.ThingsToFix) > 3 {
		d.ThingsToFix = d.ThingsToFix[:3]
	}
	if d.ThingsToFix == nil {
		d.ThingsToFix = []string{}
	}
	if counted == 0 {
		d.NoDataWarning = "No access activity was recorded in this period. If people were working, check that the enforcement nodes are running and reaching the control plane."
	}
	return d
}

// adminActions are the audit events that change who can administer the tenant.
var adminActions = map[string]string{
	"admin.create": "gave administrator access to",
	"admin.remove": "removed administrator access of",
	"admin.rotate": "replaced the token of",
	"owner.reset":  "reset the owner token of",
}

// AddAdminChanges adds the changes of administrator access found in the audit events of the period. A reset
// of an owner from the server's command line is also put first among the things to fix: it is the one
// change that bypasses the console, so it is worth a look by whoever did not do it.
func (d *Digest) AddAdminChanges(ev []audit.Event) {
	d.AdminChanges = []string{}
	for _, e := range ev {
		verb, ok := adminActions[e.Action]
		if !ok || e.Tenant != d.Tenant || e.TS.Before(d.From) || !e.TS.Before(d.To) {
			continue
		}
		line := fmt.Sprintf("%s: %s %s %s", e.TS.UTC().Format("2 Jan 15:04"), e.Actor, verb, e.Object)
		if e.Action == "owner.reset" {
			line += " (from the server's command line, not the console)"
			d.ThingsToFix = append([]string{fmt.Sprintf("An owner account (%s) was reset from the server's command line on %s. If that was not you or your IT person, treat it as a break-in: replace every administrator token and check the audit log.", e.Object, e.TS.UTC().Format("2 Jan"))}, d.ThingsToFix...)
			if len(d.ThingsToFix) > 3 {
				d.ThingsToFix = d.ThingsToFix[:3]
			}
		}
		d.AdminChanges = append(d.AdminChanges, line)
	}
}

// Text renders the digest as a short plain-text email body.
func (d Digest) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security summary, %s to %s\r\n\r\n", d.From.Format("2 Jan"), d.To.Add(-time.Second).Format("2 Jan 2006"))
	if d.NoDataWarning != "" {
		fmt.Fprintf(&b, "%s\r\n\r\n", d.NoDataWarning)
	}
	fmt.Fprintf(&b, "Private apps: %d sessions allowed, %d blocked.\r\n", d.PrivateAllow, d.PrivateDeny)
	fmt.Fprintf(&b, "Web: %d requests blocked, %d warnings shown.\r\n", d.WebBlocked, d.WebWarned)
	if len(d.TopDenied) > 0 {
		b.WriteString("\r\nMost blocked:\r\n")
		for _, p := range d.TopDenied {
			fmt.Fprintf(&b, "  - %s from %s: %s\r\n", p.Who, p.What, times(p.Count))
		}
	}
	if len(d.OpenAlerts) > 0 {
		b.WriteString("\r\nOpen alerts:\r\n")
		for _, a := range d.OpenAlerts {
			fmt.Fprintf(&b, "  - %s\r\n", a)
		}
	}
	if len(d.AdminChanges) > 0 {
		b.WriteString("\r\nAdministrator access changes:\r\n")
		for _, c := range d.AdminChanges {
			fmt.Fprintf(&b, "  - %s\r\n", c)
		}
	}
	if len(d.ThingsToFix) > 0 {
		b.WriteString("\r\nWhat to do this week:\r\n")
		for i, t := range d.ThingsToFix {
			fmt.Fprintf(&b, "  %d. %s\r\n", i+1, t)
		}
	} else {
		b.WriteString("\r\nNothing needs your attention this week.\r\n")
	}
	return b.String()
}

func times(n int) string {
	if n == 1 {
		return "1 time"
	}
	return fmt.Sprintf("%d times", n)
}
