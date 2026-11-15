package incidents

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/risk"
)

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func deny(user, kind, reason string, ago time.Duration, dlp ...string) decisions.Entry {
	return decisions.Entry{Record: broker.Record{User: user, Kind: kind, Action: "deny", Event: "open", Reason: reason, DLP: dlp, TS: now.Add(-ago)}}
}

func many(n int, e decisions.Entry) []decisions.Entry {
	var o []decisions.Entry
	for i := 0; i < n; i++ {
		o = append(o, e)
	}
	return o
}

func TestOneSignalIsLowAndSomeSignalsAreNotIncidents(t *testing.T) {
	if got := Build(now, many(2, deny("a", "private", "default", time.Minute)), nil, nil); len(got) != 0 {
		t.Fatalf("two blocked attempts are not an incident: %+v", got)
	}
	got := Build(now, many(4, deny("a", "private", "default", time.Minute)), nil, nil)
	if len(got) != 1 || got[0].Severity != Low || !strings.Contains(got[0].Summary, "blocked 4 times") {
		t.Fatalf("%+v", got)
	}
}

func TestSignalsCorrelateAndRaiseSeverity(t *testing.T) { // ZIA-022c
	es := many(6, deny("alice", "private", "default", time.Minute))
	open := []alerts.Alert{{Kind: "posture-failed", User: "alice", Action: "Ask alice to fix the device.", Opened: now.Add(-time.Hour)}}
	got := Build(now, es, open, nil)
	if len(got) != 1 || got[0].Severity != Medium || len(got[0].Signals) != 2 {
		t.Fatalf("two kinds of signal: %+v", got)
	}
	if !strings.Contains(got[0].Summary, "device is below the security baseline and they were blocked 6 times") {
		t.Fatalf("one story, in one sentence: %s", got[0].Summary)
	}
	es = append(es, deny("alice", "web", "", time.Minute, "credit-card"))
	got = Build(now, es, open, nil)
	if got[0].Severity != High || !strings.Contains(got[0].Summary, "credit-card") {
		t.Fatalf("sensitive data plus other signals is high: %+v", got[0])
	}
	var restrict bool
	for _, a := range got[0].Actions {
		restrict = restrict || strings.Contains(a, "/v1/users/alice/restrict")
	}
	if !restrict {
		t.Fatalf("a high incident should point at the restrict action: %v", got[0].Actions)
	}
}

func TestSensitiveDataBlockAloneIsMediumAndRiskScoreCanRaiseIt(t *testing.T) {
	got := Build(now, []decisions.Entry{deny("bob", "web", "dlp-response", time.Minute, "us-ssn")}, nil, nil)
	if len(got) != 1 || got[0].Severity != Medium {
		t.Fatalf("%+v", got)
	}
	got = Build(now, many(5, deny("carol", "private", "default", time.Minute)), nil, []risk.Score{{User: "carol", Score: 75}})
	if got[0].Severity != High || got[0].Score != 75 {
		t.Fatalf("a high risk score raises severity: %+v", got[0])
	}
}

func TestWindowAndIsolationBetweenUsers(t *testing.T) {
	old := many(10, deny("dave", "private", "default", 25*time.Hour))
	if got := Build(now, old, nil, nil); len(got) != 0 {
		t.Fatalf("events older than the window were correlated: %+v", got)
	}
	es := append(many(4, deny("erin", "private", "default", time.Minute)), many(1, deny("frank", "private", "default", time.Minute))...)
	got := Build(now, es, nil, nil)
	if len(got) != 1 || got[0].User != "erin" {
		t.Fatalf("one person's activity must not be pooled with another's: %+v", got)
	}
}

func TestIgnoresApprovalRequestsClosedAlertsAndNonDenials(t *testing.T) {
	es := many(10, deny("g", "private", "approval-required", time.Minute))
	ok := decisions.Entry{Record: broker.Record{User: "g", Kind: "private", Action: "allow", Event: "open", TS: now}}
	closed := now
	open := []alerts.Alert{{Kind: "posture-failed", User: "g", Closed: &closed}}
	if got := Build(now, append(es, ok), open, nil); len(got) != 0 {
		t.Fatalf("normal workflow must not look like an incident: %+v", got)
	}
}

func TestOrderedMostSevereFirst(t *testing.T) {
	es := append(many(4, deny("low", "private", "default", time.Hour)), deny("hi", "web", "", time.Minute, "credit-card"), deny("hi", "private", "default", time.Minute), deny("hi", "private", "default", time.Minute), deny("hi", "private", "default", time.Minute))
	got := Build(now, es, nil, nil)
	if len(got) != 2 || got[0].User != "hi" || got[0].Severity != High || got[1].User != "low" {
		t.Fatalf("%+v", got)
	}
}
