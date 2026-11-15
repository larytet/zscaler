package cp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/store"
)

func TestTemporaryAdministratorsAndVendorSupportAccess(t *testing.T) { // AGT-033 (NFR-023)
	e := newEnrolEnv(t)
	now := time.Now()
	e.api.Store.Now = func() time.Time { return now }
	create := func(tok string, body map[string]any) (int, map[string]any) {
		c, b, _ := e.call("POST", "/v1/admins", tok, body)
		var out map[string]any
		json.Unmarshal(b, &out)
		return c, out
	}

	// a temporary administrator
	c, out := create(e.adminA, map[string]any{"name": "temp-help", "role": "helpdesk", "expires_in_hours": 2, "note": "covering for Sam"})
	if c != 200 || out["expires"] == nil || out["token"] == "" || out["note"] != "covering for Sam" {
		t.Fatalf("%d %v", c, out)
	}
	temp := out["token"].(string)
	if c, _, _ := e.call("GET", "/v1/devices", temp, nil); c != 200 {
		t.Fatalf("a temporary account works until it ends: %d", c)
	}
	now = now.Add(3 * time.Hour)
	if c, _, _ := e.call("GET", "/v1/devices", temp, nil); c != 401 {
		t.Fatalf("after its end the token must not work: %d", c)
	}
	_, lb, _ := e.call("GET", "/v1/admins", e.adminA, nil)
	if !strings.Contains(string(lb), `"expired":true`) || !strings.Contains(string(lb), "covering for Sam") || strings.Contains(string(lb), temp) {
		t.Fatalf("an expired account is listed as expired, and no token is shown: %s", lb)
	}
	// bad input
	for name, body := range map[string]map[string]any{
		"an owner with an expiry": {"name": "o2", "role": "owner", "expires_in_hours": 1},
		"too long":                {"name": "x1", "role": "viewer", "expires_in_hours": 721},
		"negative":                {"name": "x2", "role": "viewer", "expires_in_hours": -1},
		"note too long":           {"name": "x3", "role": "viewer", "note": strings.Repeat("n", 201)},
		"note with a newline":     {"name": "x4", "role": "viewer", "note": "a\nb"},
	} {
		if c, _ := create(e.adminA, body); c != 400 {
			t.Errorf("%s: %d", name, c)
		}
	}

	// vendor support access: owners only, a reason, a role and hours that are limited
	adm, _ := e.api.Store.AddAdmin("a", "adam", store.Admin)
	if c, _, _ := e.call("POST", "/v1/support-access", adm, map[string]any{"reason": "ticket 1"}); c != 403 {
		t.Fatalf("a non-owner granted support access: %d", c)
	}
	for name, body := range map[string]map[string]any{
		"no reason":     {"hours": 2},
		"blank reason":  {"reason": "   "},
		"no owner role": {"reason": "t", "role": "owner"},
		"unknown role":  {"reason": "t", "role": "root"},
		"too long":      {"reason": "t", "hours": 73},
		"negative":      {"reason": "t", "hours": -2},
		"newline":       {"reason": "a\nb"},
	} {
		if c, _, _ := e.call("POST", "/v1/support-access", e.adminA, body); c != 400 {
			t.Errorf("%s: %d", name, c)
		}
	}
	c, b, _ := e.call("POST", "/v1/support-access", e.adminA, map[string]any{"reason": "ticket 4711: sync problem"})
	var sa map[string]any
	json.Unmarshal(b, &sa)
	if c != 200 || !strings.HasPrefix(sa["name"].(string), "support-") || sa["role"] != "auditor" || sa["support"] != true || sa["expires"] == nil || sa["token"] == "" {
		t.Fatalf("the defaults: an auditor for four hours: %d %s", c, b)
	}
	supTok := sa["token"].(string)
	if exp, _ := time.Parse(time.RFC3339Nano, sa["expires"].(string)); exp.Sub(now) < 3*time.Hour || exp.Sub(now) > 5*time.Hour {
		t.Fatalf("four hours by default: %v", sa["expires"])
	}
	// what the support account can and cannot do
	if c, _, _ := e.call("GET", "/v1/audit", supTok, nil); c != 200 {
		t.Fatalf("an auditor reads the audit log: %d", c)
	}
	if c, _, _ := e.call("PUT", "/v1/idp", supTok, map[string]any{}); c != 403 {
		t.Fatalf("a support auditor changed configuration: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/support-access", supTok, map[string]any{"reason": "x"}); c != 403 {
		t.Fatalf("a support account granted more access: %d", c)
	}
	// the customer sees it: listed as support, with the reason, when it ends, and that it was used
	_, lb, _ = e.call("GET", "/v1/admins", e.adminA, nil)
	var list []store.AdminInfo
	json.Unmarshal(lb, &list)
	var mine store.AdminInfo
	for _, a := range list {
		if a.Support {
			mine = a
		}
	}
	if mine.Name != sa["name"] || mine.Note != "ticket 4711: sync problem" || mine.Expires.IsZero() || mine.LastUsed.IsZero() || mine.Expired {
		t.Fatalf("%+v", mine)
	}
	// its actions are in the audit log under its own name; the creation names the reason and the end, never the token
	adminSup, _ := create(e.adminA, map[string]any{"name": "support-adm1", "role": "admin", "expires_in_hours": 1})
	_ = adminSup
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), `"admin.create"`) || !strings.Contains(string(ab), "ticket 4711") || strings.Contains(string(ab), supTok) || strings.Contains(string(ab), temp) {
		t.Fatalf("%s", ab)
	}
	// ended early by the customer
	if c, _, _ := e.call("DELETE", "/v1/admins/"+sa["name"].(string), e.adminA, nil); c != 200 {
		t.Fatalf("%d", c)
	}
	if c, _, _ := e.call("GET", "/v1/audit", supTok, nil); c != 401 {
		t.Fatalf("an ended support account still works: %d", c)
	}
	// it would have ended by itself
	_, sa2 := func() (int, map[string]any) {
		c, b, _ := e.call("POST", "/v1/support-access", e.adminA, map[string]any{"reason": "ticket 2", "hours": 1, "role": "helpdesk"})
		var m map[string]any
		json.Unmarshal(b, &m)
		return c, m
	}()
	now = now.Add(90 * time.Minute)
	if c, _, _ := e.call("GET", "/v1/devices", sa2["token"].(string), nil); c != 401 {
		t.Fatalf("an hour of support access ended after ninety minutes: %d", c)
	}
	// another tenant sees none of it
	if _, b, _ := e.call("GET", "/v1/admins", e.adminB, nil); strings.Contains(string(b), "support-") {
		t.Fatalf("tenant isolation: %s", b)
	}
}
