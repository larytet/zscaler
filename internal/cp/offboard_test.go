package cp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

// One action ends a person's access everywhere the store holds it, and says what it cannot reach (GAP-REQ-07).
func TestPersonLeftEndsAccessInOneAction(t *testing.T) { // AGT-039
	e := newEnrolEnv(t)
	e.api.Approvals = approvals.New()
	var disabled, revoked []string
	e.api.OnDisableUser = func(tn, s string) { disabled = append(disabled, tn+"/"+s) }
	e.api.OnRevokeDevice = func(tn string, d store.Device) { revoked = append(revoked, tn+"/"+d.ID) }
	st := e.api.Store
	st.UpsertUser("a", policy.User{Subject: "sub-leo", Email: "leo@example.com", Groups: []string{"sales"}})
	st.UpsertUser("a", policy.User{Subject: "sub-mia", Email: "mia@example.com"})
	st.UpsertUser("b", policy.User{Subject: "sub-leo", Email: "leo@example.com"}) // same name, other tenant
	st.PutDevice("a", store.Device{ID: "d-leo-1", User: "sub-leo", Serial: "1"})
	st.PutDevice("a", store.Device{ID: "d-leo-2", User: "sub-leo", Serial: "2"})
	st.PutDevice("a", store.Device{ID: "d-mia", User: "sub-mia", Serial: "3"})
	st.PutDevice("b", store.Device{ID: "d-b", User: "sub-leo", Serial: "4"})
	st.RevokeDevice("a", "d-leo-2") // already revoked: not counted again
	st.PutGrant("a", store.Grant{User: "sub-leo", App: "erp", Expires: time.Now().Add(time.Hour), By: "x"})
	st.PutGrant("a", store.Grant{User: "sub-mia", App: "erp", Expires: time.Now().Add(time.Hour), By: "x"})
	st.SetSCIM("a", true, false)
	su, _, _ := st.SCIMPutUser("a", "", store.SCIMUserIn{UserName: "leo@example.com", Email: "leo@example.com", Active: true})
	e.api.Approvals.Add("a", "sub-leo", "wiki", "jit", time.Now())
	e.api.Approvals.Add("a", "sub-mia", "wiki", "jit", time.Now())

	// the permission is "write": helpdesk and viewers are refused, an unknown person is not found
	for _, role := range []store.Role{store.Helpdesk, store.Viewer, store.Auditor} {
		tok, _ := st.AddAdmin("a", "x-"+string(role), role)
		if c, _, _ := e.call("POST", "/v1/users/sub-leo/offboard", tok, nil); c != 403 {
			t.Errorf("%s: %d", role, c)
		}
	}
	if c, _, _ := e.call("POST", "/v1/users/nobody/offboard", e.adminA, nil); c != 404 {
		t.Errorf("unknown person: %d", c)
	}
	if u, _ := st.User("a", "sub-leo"); u.Disabled {
		t.Fatal("a refused call changed something")
	}

	code, body, _ := e.call("POST", "/v1/users/sub-leo/offboard", e.adminA, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var out struct {
		Steps []struct {
			Step   string `json:"step"`
			Done   bool   `json:"done"`
			Count  int    `json:"count"`
			Detail string `json:"detail"`
		} `json:"steps"`
		TakesEffect string `json:"takes_effect"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	done := map[string]bool{}
	for _, s := range out.Steps {
		got[s.Step], done[s.Step] = s.Count, s.Done
	}
	if got["devices"] != 1 || got["access grants"] != 1 || got["access requests"] != 1 {
		t.Errorf("counts: %+v", out.Steps)
	}
	// what it ended is done; what it cannot reach is said so and not marked done
	for _, s := range []string{"account", "devices", "access grants", "access requests", "identity provider record"} {
		if !done[s] {
			t.Errorf("%s not done", s)
		}
	}
	for _, s := range []string{"AI agents", "other services"} {
		if done[s] {
			t.Errorf("%s must not claim to be done", s)
		}
	}
	if !strings.Contains(out.TakesEffect, "poll") {
		t.Errorf("no timing said: %q", out.TakesEffect)
	}
	// the state
	if u, _ := st.User("a", "sub-leo"); !u.Disabled {
		t.Error("account still enabled")
	}
	devs, _ := st.Devices("a")
	for _, d := range devs {
		if (d.User == "sub-leo") != d.Revoked {
			t.Errorf("device %s revoked=%v", d.ID, d.Revoked)
		}
	}
	if st.Granted("a", "sub-leo", "erp", time.Now()) || !st.Granted("a", "sub-mia", "erp", time.Now()) {
		t.Error("grants: Leo's must end and Mia's must stay")
	}
	if blocked, _ := st.SCIMBlocks("a", "sub-leo", "leo@example.com"); !blocked {
		t.Error("the provisioned user is still active")
	}
	if got, _, _ := st.SCIMUserGet("a", su.ID); got.Active {
		t.Error("SCIM user still active")
	}
	if p := e.api.Approvals.List("a", approvals.Pending); len(p) != 1 || p[0].User != "sub-mia" {
		t.Errorf("pending requests: %+v", p)
	}
	// another tenant's same-named person and other people are untouched
	if u, _ := st.User("b", "sub-leo"); u.Disabled {
		t.Error("another tenant's person was disabled")
	}
	if u, _ := st.User("a", "sub-mia"); u.Disabled {
		t.Error("another person was disabled")
	}
	// sessions were closed and the revoked device was announced to the nodes
	if len(disabled) == 0 || len(revoked) != 1 || revoked[0] != "a/d-leo-1" {
		t.Errorf("callbacks: %v %v", disabled, revoked)
	}
	// it is in the audit log, with the counts
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "user.offboard") {
		t.Error("not audited")
	}
	// asking twice is safe and finds nothing left to end
	code, body, _ = e.call("POST", "/v1/users/sub-leo/offboard", e.adminA, nil)
	if code != 200 {
		t.Fatalf("second call %d", code)
	}
	out.Steps = nil
	json.Unmarshal(body, &out)
	for _, s := range out.Steps {
		if (s.Step == "devices" || s.Step == "access grants" || s.Step == "access requests") && s.Count != 0 {
			t.Errorf("second call: %+v", s)
		}
		if s.Step == "account" && !strings.Contains(s.Detail, "already") {
			t.Errorf("second call account: %q", s.Detail)
		}
	}
}
