package cp

import (
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/store"
)

func TestTenancyEndpoints(t *testing.T) { // AGT-024 (DATA-002a)
	e := newEnrolEnv(t)
	good := map[string]any{
		"microsoft": map[string]any{"allowed": []string{"contoso.com", "Fabrikam.com"}, "context": "72f988bf-86f1-41af-91ab-2d7cd011db47"},
		"slack":     map[string]any{"allowed": []string{"t01abcdef"}},
	}
	c, b, _ := e.call("PUT", "/v1/tenancy", e.adminA, good)
	if c != 200 || !strings.Contains(string(b), `"configured":true`) || !strings.Contains(string(b), "fabrikam.com") {
		t.Fatalf("%d %s", c, b)
	}
	// with inspection off the answer says nothing is restricted yet
	if !strings.Contains(string(b), "TLS inspection is off") || !strings.Contains(string(b), "have not been checked against the live services") {
		t.Fatalf("the limits must be stated: %s", b)
	}
	// with inspection on, and a sign-in host exempt, it says that host is not restricted
	e.call("PUT", "/v1/inspection", e.adminA, map[string]any{"enabled": true, "exempt": []string{"login.microsoftonline.com"}})
	_, b, _ = e.call("GET", "/v1/tenancy", e.adminA, nil)
	if strings.Contains(string(b), "TLS inspection is off") || !strings.Contains(string(b), "login.microsoftonline.com is on the inspection exempt list") {
		t.Fatalf("%s", b)
	}
	e.call("PUT", "/v1/inspection", e.adminA, map[string]any{"enabled": true})
	if _, b, _ = e.call("GET", "/v1/tenancy", e.adminA, nil); strings.Contains(string(b), "exempt list") {
		t.Fatalf("no host is exempt now: %s", b)
	}

	// bad input is refused and changes nothing
	for name, body := range map[string]map[string]any{
		"no context":     {"microsoft": map[string]any{"allowed": []string{"contoso.com"}}},
		"bad slack id":   {"slack": map[string]any{"allowed": []string{"my-workspace"}}},
		"header split":   {"google": map[string]any{"allowed": []string{"a.com\r\nX-Evil: 1"}}},
		"unknown vendor": {"zoom": map[string]any{"allowed": []string{"a.com"}}},
	} {
		if c, _, _ := e.call("PUT", "/v1/tenancy", e.adminA, body); c != 400 {
			t.Errorf("%s accepted: %d", name, c)
		}
	}
	if got := e.api.Store.Tenancy("a"); got == nil || got.Microsoft == nil || got.Microsoft.Allowed[1] != "fabrikam.com" {
		t.Fatalf("a refused change altered the stored restriction: %+v", got)
	}

	// it reaches the node's snapshot, and only for this tenant
	if snap := e.api.Store.Snapshot().Tenants["a"]; snap == nil || snap.Tenancy == nil || snap.Tenancy.Slack == nil {
		t.Fatal("the restriction is not in the snapshot the nodes sync")
	}
	if snap := e.api.Store.Snapshot().Tenants["b"]; snap != nil && snap.Tenancy != nil {
		t.Fatal("tenant isolation: tenant b has tenant a's restriction")
	}
	if _, b, _ := e.call("GET", "/v1/tenancy", e.adminB, nil); !strings.Contains(string(b), `"configured":false`) {
		t.Fatalf("tenant b sees it: %s", b)
	}

	// roles: reading is for everyone who reads, changing is for write
	for _, role := range []store.Role{store.Viewer, store.Helpdesk, store.Auditor} {
		tok, _ := e.api.Store.AddAdmin("a", "r-"+string(role), role)
		if c, _, _ := e.call("GET", "/v1/tenancy", tok, nil); c != 200 {
			t.Errorf("%s could not read: %d", role, c)
		}
		if c, _, _ := e.call("PUT", "/v1/tenancy", tok, good); c != 403 {
			t.Errorf("%s changed it: %d", role, c)
		}
		if c, _, _ := e.call("DELETE", "/v1/tenancy", tok, nil); c != 403 {
			t.Errorf("%s removed it: %d", role, c)
		}
	}
	// audited with before and after, and removable; an empty config also means none
	if _, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil); !strings.Contains(string(ab), "tenancy.put") {
		t.Fatalf("%s", ab)
	}
	if c, _, _ := e.call("DELETE", "/v1/tenancy", e.adminA, nil); c != 200 {
		t.Fatal(c)
	}
	if e.api.Store.Tenancy("a") != nil {
		t.Fatal("not removed")
	}
	e.call("PUT", "/v1/tenancy", e.adminA, good)
	e.call("PUT", "/v1/tenancy", e.adminA, map[string]any{})
	if e.api.Store.Tenancy("a") != nil {
		t.Fatal("an empty config must mean none")
	}
}
