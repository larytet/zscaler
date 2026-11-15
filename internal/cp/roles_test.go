package cp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/store"
)

// A request that only checks the role: whatever the handler then says (200, 400, 404) is not 403.
type probe struct {
	method, path string
	perm         store.Perm
}

var probes = []probe{
	{"GET", "/v1/segments", store.PermRead},
	{"GET", "/v1/policies/web", store.PermRead},
	{"GET", "/v1/devices", store.PermRead},
	{"GET", "/v1/users", store.PermRead},
	{"GET", "/v1/alerts", store.PermRead},
	{"GET", "/v1/decisions", store.PermLogs},
	{"GET", "/v1/incidents", store.PermLogs},
	{"GET", "/v1/audit", store.PermAudit},
	{"GET", "/v1/evidence", store.PermAudit},
	{"POST", "/v1/devices/d-none/revoke", store.PermSupport},
	{"POST", "/v1/users/none/restrict", store.PermSupport},
	{"POST", "/v1/approvals/1/approve", store.PermSupport},
	{"PUT", "/v1/idp", store.PermWrite},
	{"POST", "/v1/segments", store.PermWrite},
	{"POST", "/v1/users/none/disable", store.PermWrite},
	{"POST", "/v1/policies/safe-defaults", store.PermWrite},
	{"PUT", "/v1/inspection", store.PermWrite},
	{"GET", "/v1/secrets", store.PermSensitive},
	{"GET", "/v1/edm", store.PermSensitive},
	{"GET", "/v1/captures", store.PermSensitive},
	{"GET", "/v1/admins", store.PermAdmins},
}

func TestRolePermissionMatrix(t *testing.T) { // AGT-022 (ADM-002)
	e := newEnrolEnv(t)
	roles := []store.Role{store.Owner, store.Admin, store.Helpdesk, store.Auditor, store.Viewer}
	for _, role := range roles {
		tok := e.adminA
		if role != store.Owner {
			var err error
			tok, err = e.api.Store.AddAdmin("a", "u-"+string(role), role)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range probes {
			code, _, _ := e.call(p.method, p.path, tok, map[string]any{})
			if want := role.Can(p.perm); want == (code == 403) {
				t.Errorf("%s %s as %s: got %d, but the role %s have the %q permission", p.method, p.path, role, code, map[bool]string{true: "should", false: "should not"}[want], p.perm)
			}
		}
	}
	// the matrix itself says what the spec says (ADM-002)
	for role, want := range map[store.Role]map[store.Perm]bool{
		store.Viewer:   {store.PermRead: true, store.PermLogs: false, store.PermAudit: false, store.PermSupport: false, store.PermWrite: false},
		store.Helpdesk: {store.PermRead: true, store.PermLogs: true, store.PermSupport: true, store.PermAudit: false, store.PermWrite: false, store.PermSensitive: false},
		store.Auditor:  {store.PermRead: true, store.PermLogs: true, store.PermAudit: true, store.PermSupport: false, store.PermWrite: false, store.PermSensitive: false},
		store.Admin:    {store.PermWrite: true, store.PermSensitive: true, store.PermAdmins: false},
		store.Owner:    {store.PermWrite: true, store.PermAdmins: true},
	} {
		for perm, w := range want {
			if role.Can(perm) != w {
				t.Errorf("%s.Can(%s) = %v, want %v", role, perm, !w, w)
			}
		}
	}
	if store.Role("root").Can(store.PermRead) || store.Role("").Can(store.PermRead) {
		t.Error("an unknown role must have no permission")
	}
}

func TestAdminAccountsAreManagedByOwnersOnly(t *testing.T) { // AGT-022 (ADM-002, ADM-003)
	e := newEnrolEnv(t)
	create := func(tok, name, role string) (int, map[string]string) {
		c, b, _ := e.call("POST", "/v1/admins", tok, map[string]string{"name": name, "role": role})
		var out map[string]string
		json.Unmarshal(b, &out)
		return c, out
	}
	c, out := create(e.adminA, "carol", "helpdesk")
	if c != 200 || out["token"] == "" || out["role"] != "helpdesk" {
		t.Fatalf("%d %v", c, out)
	}
	carol := out["token"]
	// the new token works, with the new role
	if c, _, _ := e.call("GET", "/v1/devices", carol, nil); c != 200 {
		t.Fatalf("helpdesk could not read: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/segments", carol, map[string]any{}); c != 403 {
		t.Fatalf("helpdesk could write: %d", c)
	}
	// only an owner manages administrators: not an admin, not the helpdesk
	adm, _ := e.api.Store.AddAdmin("a", "adam", store.Admin)
	for _, tok := range []string{adm, carol} {
		if c, _ := create(tok, "mallory", "owner"); c != 403 {
			t.Fatalf("a non-owner created an administrator: %d", c)
		}
		if c, _, _ := e.call("GET", "/v1/admins", tok, nil); c != 403 {
			t.Fatalf("a non-owner listed administrators: %d", c)
		}
		if c, _, _ := e.call("DELETE", "/v1/admins/carol", tok, nil); c != 403 {
			t.Fatalf("a non-owner removed an administrator: %d", c)
		}
	}
	// bad input and duplicates
	for name, body := range map[string]map[string]string{"bad role": {"name": "x1", "role": "root"}, "no role": {"name": "x2"}, "bad name": {"name": "Bad Name", "role": "viewer"}, "empty name": {"role": "viewer"}} {
		if c, _, _ := e.call("POST", "/v1/admins", e.adminA, body); c != 400 {
			t.Errorf("%s accepted: %d", name, c)
		}
	}
	if c, _ := create(e.adminA, "carol", "viewer"); c != 409 {
		t.Fatalf("a duplicate name was accepted: %d", c)
	}
	// listing shows names and roles, never tokens, and is audited without them
	c2, b, _ := e.call("GET", "/v1/admins", e.adminA, nil)
	if c2 != 200 || !strings.Contains(string(b), `"carol"`) || strings.Contains(string(b), carol) || strings.Contains(string(b), "token") {
		t.Fatalf("%d %s", c2, b)
	}
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "admin.create") || strings.Contains(string(ab), carol) {
		t.Fatalf("admin creation must be audited without the token: %s", ab)
	}
	// another tenant's owner cannot see or remove them
	if c, b, _ := e.call("GET", "/v1/admins", e.adminB, nil); c != 200 || strings.Contains(string(b), "carol") {
		t.Fatalf("tenant isolation: %d %s", c, b)
	}
	if c, _, _ := e.call("DELETE", "/v1/admins/carol", e.adminB, nil); c != 404 {
		t.Fatalf("another tenant removed an administrator: %d", c)
	}
	// removal ends the token at once; the last owner and oneself cannot be removed
	if c, _, _ := e.call("DELETE", "/v1/admins/carol", e.adminA, nil); c != 200 {
		t.Fatalf("remove: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/devices", carol, nil); c != 401 {
		t.Fatalf("a removed administrator's token still works: %d", c)
	}
	if c, _, _ := e.call("DELETE", "/v1/admins/owner", e.adminA, nil); c != 409 {
		t.Fatalf("an owner removed themselves: %d", c)
	}
	_, o2 := create(e.adminA, "olga", "owner")
	if c, _, _ := e.call("DELETE", "/v1/admins/owner", o2["token"], nil); c != 200 {
		t.Fatalf("a second owner could not remove the first: %d", c)
	}
	if c, _, _ := e.call("DELETE", "/v1/admins/olga", o2["token"], nil); c != 409 {
		t.Fatalf("the last owner removed themselves: %d", c)
	}
}
