// Package digest builds the plain-language weekly summary for the person who
// is the security team (ADM-009): what happened, and the few things to fix.
package digest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/decisions"
)

type Pair struct {
	Who   string `json:"who"`
	What  string `json:"what"`
	Count int    `json:"count"`
}

type Digest struct {
	Tenant        string    `json:"tenant"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	PrivateAllow  int       `json:"private_sessions_allowed"`
	PrivateDeny   int       `json:"private_sessions_denied"`
	WebBlocked    int       `json:"web_requests_blocked"`
	WebWarned     int       `json:"web_requests_warned"`
	TopDenied     []Pair    `json:"top_denied"`
	OpenAlerts    []string  `json:"open_alerts"`
	ThingsToFix   []string  `json:"things_to_fix"`
	NoDataWarning string    `json:"no_data_warning,omitempty"`
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
		d.ThingsToFix = append(d.ThingsToFix, fmt.Sprintf("%s was blocked %d times from %s. Decide whether they should have access.", t.Who, t.Count, t.What))
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
			fmt.Fprintf(&b, "  - %s from %s: %d times\r\n", p.Who, p.What, p.Count)
		}
	}
	if len(d.OpenAlerts) > 0 {
		b.WriteString("\r\nOpen alerts:\r\n")
		for _, a := range d.OpenAlerts {
			fmt.Fprintf(&b, "  - %s\r\n", a)
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
