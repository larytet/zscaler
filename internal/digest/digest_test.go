package digest

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
)

var t0 = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)

func ent(kind, action, user, app string, at time.Time, ev string) decisions.Entry {
	return decisions.Entry{Record: broker.Record{Kind: kind, Action: action, User: user, App: app, TS: at, Event: ev}}
}

func TestCountsWindowAndTop(t *testing.T) {
	to := t0.Add(7 * 24 * time.Hour)
	var es []decisions.Entry
	for i := 0; i < 6; i++ {
		es = append(es, ent("private", "deny", "alice", "erp", t0.Add(time.Hour), "open"))
	}
	es = append(es,
		ent("private", "deny", "bob", "wiki", t0.Add(time.Hour), "open"),
		ent("private", "allow", "alice", "erp", t0.Add(2*time.Hour), "open"),
		ent("private", "allow", "alice", "erp", t0.Add(2*time.Hour), "close"), // close records are not sessions
		ent("web", "deny", "alice", "", t0.Add(3*time.Hour), "open"),
		ent("web", "warn", "alice", "", t0.Add(3*time.Hour), "open"),
		ent("private", "deny", "old", "erp", t0.Add(-time.Hour), "open"), // before the window
		ent("private", "deny", "new", "erp", to, "open"),                 // at the end: excluded
	)
	d := Build("t1", t0, to, es, nil)
	if d.PrivateAllow != 1 || d.PrivateDeny != 7 || d.WebBlocked != 1 || d.WebWarned != 1 {
		t.Fatalf("%+v", d)
	}
	if len(d.TopDenied) != 2 || d.TopDenied[0].Who != "alice" || d.TopDenied[0].Count != 6 {
		t.Fatalf("%+v", d.TopDenied)
	}
	if len(d.ThingsToFix) != 1 || !strings.Contains(d.ThingsToFix[0], "alice was blocked 6 times from erp") {
		t.Fatalf("%v", d.ThingsToFix)
	}
}

func TestAlertsBecomeActions(t *testing.T) {
	closed := t0
	al := []alerts.Alert{
		{Message: "Office connector is offline", Action: "Check the host."},
		{Message: "old", Action: "ignore", Closed: &closed},
	}
	d := Build("t1", t0, t0.Add(time.Hour), []decisions.Entry{ent("private", "allow", "a", "x", t0, "open")}, al)
	if len(d.OpenAlerts) != 1 || d.ThingsToFix[0] != "Check the host." {
		t.Fatalf("%+v", d)
	}
}

func TestAtMostThreeThingsAndQuietWeek(t *testing.T) {
	var al []alerts.Alert
	for i := 0; i < 6; i++ {
		al = append(al, alerts.Alert{Message: "m", Action: "do something"})
	}
	d := Build("t1", t0, t0.Add(time.Hour), []decisions.Entry{ent("private", "allow", "a", "x", t0, "open")}, al)
	if len(d.ThingsToFix) != 3 {
		t.Fatalf("%d actions", len(d.ThingsToFix))
	}
	quiet := Build("t1", t0, t0.Add(time.Hour), []decisions.Entry{ent("private", "allow", "a", "x", t0, "open")}, nil)
	if !strings.Contains(quiet.Text(), "Nothing needs your attention") {
		t.Fatal(quiet.Text())
	}
}

func TestNoDataIsFlagged(t *testing.T) {
	d := Build("t1", t0, t0.Add(time.Hour), nil, nil)
	if d.NoDataWarning == "" || !strings.Contains(d.Text(), "No access activity") {
		t.Fatal("an empty week must say so rather than claim all is well")
	}
	if strings.Contains(d.Text(), "Nothing needs your attention") && d.NoDataWarning == "" {
		t.Fatal("silence must not read as safety")
	}
}

func TestTextIsPlain(t *testing.T) {
	d := Build("t1", t0, t0.Add(7*24*time.Hour), []decisions.Entry{ent("private", "deny", "alice", "erp", t0, "open")}, nil)
	txt := d.Text()
	for _, want := range []string{"Security summary, 9 Nov to 15 Nov 2026", "Private apps: 0 sessions allowed, 1 blocked.", "alice from erp: 1 time\r\n"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
}
