package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newEngine() (*Engine, *clock) {
	c := &clock{time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	e := New()
	e.Now = c.now
	e.Name = func(t, s string) string {
		if s == "u1" {
			return "Alice"
		}
		return s
	}
	return e, c
}

func deny(user, app string) broker.Record {
	return broker.Record{Tenant: "t1", Kind: "private", Action: "deny", Event: "open", User: user, App: app, Rule: "r-fin"}
}

func TestRepeatedDeniesOneAlert(t *testing.T) { // ALR-001
	e, c := newEngine()
	for i := 0; i < 9; i++ {
		e.Ingest(deny("u1", "erp"))
		c.t = c.t.Add(10 * time.Second)
	}
	if len(e.List("t1", true)) != 0 {
		t.Fatal("alert before the threshold")
	}
	for i := 0; i < 5; i++ { // 10th deny and more
		e.Ingest(deny("u1", "erp"))
	}
	al := e.List("t1", true)
	if len(al) != 1 {
		t.Fatalf("want exactly one alert, got %d", len(al))
	}
	a := al[0]
	if !strings.Contains(a.Message, "Alice was blocked") || !strings.Contains(a.Message, "erp") || a.Action == "" || !strings.Contains(a.Action, "r-fin") {
		t.Fatalf("%+v", a)
	}
}

func TestDeniesOutsideWindowDoNotCount(t *testing.T) {
	e, c := newEngine()
	for i := 0; i < 9; i++ {
		e.Ingest(deny("u1", "erp"))
	}
	c.t = c.t.Add(11 * time.Minute)
	e.Ingest(deny("u1", "erp"))
	if len(e.List("t1", true)) != 0 {
		t.Fatal("old denies were counted")
	}
}

func TestDeniesAreSeparatePerUserAndApp(t *testing.T) {
	e, _ := newEngine()
	for i := 0; i < 9; i++ {
		e.Ingest(deny("u1", "erp"))
		e.Ingest(deny("u2", "erp"))
		e.Ingest(deny("u1", "wiki"))
	}
	if len(e.List("t1", false)) != 0 {
		t.Fatal("different users or apps were merged")
	}
}

func TestTenantsAreSeparate(t *testing.T) {
	e, _ := newEngine()
	r := deny("u1", "erp")
	for i := 0; i < 12; i++ {
		e.Ingest(r)
	}
	if len(e.List("t2", false)) != 0 || len(e.List("t1", false)) != 1 {
		t.Fatal("alerts leaked between tenants")
	}
}

func TestOnlyOpenDeniesCount(t *testing.T) {
	e, _ := newEngine()
	r := deny("u1", "erp")
	r.Event = "close"
	for i := 0; i < 20; i++ {
		e.Ingest(r)
	}
	allow := deny("u1", "erp")
	allow.Action = "allow"
	for i := 0; i < 20; i++ {
		e.Ingest(allow)
	}
	if len(e.List("t1", false)) != 0 {
		t.Fatal("non-deny or close records counted")
	}
}

func conn(ev string) broker.Record {
	return broker.Record{Tenant: "t1", Kind: "connector", Event: ev, App: "site1", Device: "c1"}
}

func TestConnectorOfflineOpensAndCloses(t *testing.T) { // ALR-002
	e, c := newEngine()
	e.Ingest(conn("connected"))
	e.Ingest(conn("disconnected"))
	c.t = c.t.Add(90 * time.Second)
	e.Tick()
	if len(e.List("t1", true)) != 0 {
		t.Fatal("alerted before 2 minutes")
	}
	c.t = c.t.Add(40 * time.Second)
	e.Tick()
	e.Tick() // repeated ticks must not duplicate
	al := e.List("t1", true)
	if len(al) != 1 || !strings.Contains(al[0].Message, `"c1"`) || !strings.Contains(al[0].Message, "offline") {
		t.Fatalf("%+v", al)
	}
	e.Ingest(conn("connected"))
	if len(e.List("t1", true)) != 0 {
		t.Fatal("alert did not close when the connector returned")
	}
	if all := e.List("t1", false); len(all) != 1 || all[0].Closed == nil {
		t.Fatal("closed alert should stay in history")
	}
}

func TestBriefDisconnectIsQuiet(t *testing.T) {
	e, c := newEngine()
	e.Ingest(conn("connected"))
	e.Ingest(conn("disconnected"))
	c.t = c.t.Add(30 * time.Second)
	e.Ingest(conn("connected"))
	c.t = c.t.Add(10 * time.Minute)
	e.Tick()
	if len(e.List("t1", false)) != 0 {
		t.Fatal("a quick reconnect caused an alert")
	}
}

func posture(action, reason string) broker.Record {
	return broker.Record{Tenant: "t1", Kind: "posture", Action: action, Reason: reason, User: "u1", Device: "d1"}
}

func TestPostureTransition(t *testing.T) { // ALR-003
	e, _ := newEngine()
	e.Ingest(posture("fail", "disk encryption is off")) // never passed: not a transition
	if len(e.List("t1", false)) != 0 {
		t.Fatal("alert for a device that never passed")
	}
	e.Ingest(posture("pass", ""))
	e.Ingest(posture("fail", "disk encryption is off"))
	al := e.List("t1", true)
	if len(al) != 1 || !strings.Contains(al[0].Message, "disk encryption is off") || !strings.Contains(al[0].Message, "Alice") {
		t.Fatalf("%+v", al)
	}
	e.Ingest(posture("fail", "disk encryption is off")) // still failing: no second alert
	if len(e.List("t1", false)) != 1 {
		t.Fatal("duplicate posture alert")
	}
	e.Ingest(posture("pass", ""))
	if len(e.List("t1", true)) != 0 {
		t.Fatal("alert did not close when the device recovered")
	}
}
