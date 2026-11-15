package cp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/store"
)

func TestDecisionHistoryEndpoint(t *testing.T) { // AGT-026 (ADM-006, FW-010, ADM-007)
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	// without an archive the endpoint says so
	if c, _, _ := e.call("GET", "/v1/decisions/history", e.adminA, nil); c != 503 {
		t.Fatalf("no archive: %d", c)
	}
	arch, err := decisions.OpenArchive(t.TempDir()+"/d", decisions.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	defer arch.Close()
	e.api.Decisions.SetArchive(arch)

	base := time.Now().UTC().Add(-5 * 24 * time.Hour)
	var recs []broker.Record
	for d := 0; d < 5; d++ {
		for i := 0; i < 4; i++ {
			act, user := "allow", "u1"
			if i == 3 {
				act, user = "deny", "u2"
			}
			recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Action: act, Event: "open", User: user, App: "erp",
				Rule: fmt.Sprintf("r%d", i), TS: base.Add(time.Duration(d)*24*time.Hour + time.Duration(i)*time.Minute)})
		}
	}
	recs = append(recs,
		broker.Record{Tenant: "a", Kind: "capture", Action: "info", Event: "open", User: "u1", TS: base, Capture: &broker.Capture{ReqBody: "c2VjcmV0"}},
		broker.Record{Tenant: "a", Kind: "health", Action: "info", User: "u1", TS: base},
		broker.Record{Tenant: "b", Kind: "private", Action: "deny", Event: "open", User: "other-tenant", TS: base})
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatalf("ingest %d", c)
	}
	type page struct {
		Records    []broker.Record
		NextCursor string `json:"next_cursor"`
		Oldest     time.Time
		Retention  int `json:"retention_days"`
	}
	get := func(q string) (int, page) {
		c, b, _ := e.call("GET", "/v1/decisions/history"+q, e.adminA, nil)
		var p page
		json.Unmarshal(b, &p)
		return c, p
	}
	c, p := get("?limit=1000")
	if c != 200 || len(p.Records) != 20 || p.Retention != 183 || p.Oldest.IsZero() {
		t.Fatalf("%d %d records, retention %d", c, len(p.Records), p.Retention)
	}
	for _, r := range p.Records {
		if r.Tenant != "a" || r.Kind == "capture" || r.Kind == "health" || r.Capture != nil {
			t.Fatalf("a record that does not belong: %+v", r)
		}
	}
	// filters, dates, paging
	if _, p = get("?action=deny&limit=1000"); len(p.Records) != 5 {
		t.Fatalf("denials: %d", len(p.Records))
	}
	if _, p = get("?user=u2"); len(p.Records) != 5 {
		t.Fatalf("u2: %d", len(p.Records))
	}
	from := base.Add(24 * time.Hour).Format("2006-01-02")
	to := base.Add(2 * 24 * time.Hour).Format("2006-01-02")
	if _, p = get("?from=" + from + "&to=" + to + "&limit=1000"); len(p.Records) != 8 {
		t.Fatalf("two whole days (dates are inclusive): %d", len(p.Records))
	}
	total, cursor := 0, ""
	for i := 0; i < 20; i++ {
		_, p = get("?limit=3&cursor=" + cursor)
		total += len(p.Records)
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if total != 20 {
		t.Fatalf("paging returned %d", total)
	}
	// bad input
	for _, q := range []string{"?from=yesterday", "?to=2026-13-45", "?limit=0", "?limit=5000", "?limit=abc", "?cursor=../../x:1", "?from=2026-06-10&to=2026-06-01"} {
		if c, _ := get(q); c != 400 {
			t.Errorf("%s: %d", q, c)
		}
	}
	// roles: logs permission (helpdesk, auditor, admin, owner); not a read-only viewer
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("GET", "/v1/decisions/history", viewer, nil); c != 403 {
		t.Fatalf("a viewer read the history: %d", c)
	}
	for _, role := range []store.Role{store.Helpdesk, store.Auditor} {
		tok, _ := e.api.Store.AddAdmin("a", "r-"+string(role), role)
		if c, _, _ := e.call("GET", "/v1/decisions/history", tok, nil); c != 200 {
			t.Errorf("%s: %d", role, c)
		}
	}
	// tenant isolation
	c2, b, _ := e.call("GET", "/v1/decisions/history?limit=1000", e.adminB, nil)
	if c2 != 200 || strings.Contains(string(b), `"u1"`) || !strings.Contains(string(b), "other-tenant") {
		t.Fatalf("tenant isolation: %d %s", c2, b)
	}
}

func TestDecisionsCanBeFoundByTheReferenceOnABlockPage(t *testing.T) { // AGT-028 (ZIA-014)
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	arch, _ := decisions.OpenArchive(t.TempDir()+"/d", decisions.DefaultRetention)
	defer arch.Close()
	e.api.Decisions.SetArchive(arch)
	now := time.Now().UTC()
	recs := []broker.Record{
		{Tenant: "a", Kind: "web", Action: "deny", Event: "open", User: "u1", Target: "x.example:443", Rule: "block-x", Ref: "0123456789ab", TS: now},
		{Tenant: "a", Kind: "web", Action: "deny", Event: "open", User: "u2", Target: "y.example:443", Ref: "ba9876543210", TS: now},
		{Tenant: "b", Kind: "web", Action: "deny", Event: "open", User: "x", Target: "z.example:443", Ref: "0123456789ab", TS: now}, // the same reference in another tenant
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatalf("ingest %d", c)
	}
	for _, path := range []string{"/v1/decisions?ref=0123456789ab", "/v1/decisions/history?ref=0123456789ab"} {
		c, b, _ := e.call("GET", path, e.adminA, nil)
		if c != 200 || !strings.Contains(string(b), `"block-x"`) || strings.Contains(string(b), "ba9876543210") || strings.Contains(string(b), `"z.example`) {
			t.Fatalf("%s: %d %s", path, c, b)
		}
	}
	if _, b, _ := e.call("GET", "/v1/decisions/history?ref=nonesuch", e.adminA, nil); strings.Contains(string(b), "block-x") {
		t.Fatalf("an unknown reference found a record: %s", b)
	}
}
