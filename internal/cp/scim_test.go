package cp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

func (e *enrolEnv) scim(method, path, tok string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/scim/v2"+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 204 && !strings.HasPrefix(ct, "application/scim+json") {
		e.t.Errorf("%s %s: content type %q", method, path, ct)
	}
	return resp.StatusCode, out
}

func scimStart(t *testing.T) (*enrolEnv, string) {
	e := newEnrolEnv(t)
	if c, _, _ := e.call("PUT", "/v1/scim", e.adminA, map[string]any{"enabled": true}); c != 200 {
		t.Fatal(c)
	}
	c, b, _ := e.call("POST", "/v1/scim/token", e.adminA, nil)
	var tk struct{ Token string }
	json.Unmarshal(b, &tk)
	if c != 200 || !strings.HasPrefix(tk.Token, "scim-") {
		t.Fatalf("%d %s", c, b)
	}
	return e, tk.Token
}

func newUser(e *enrolEnv, tok, name string) string {
	c, u := e.scim("POST", "/Users", tok, map[string]any{"schemas": []string{scimUserSchema}, "userName": name, "displayName": strings.Split(name, "@")[0],
		"emails": []map[string]any{{"value": name, "primary": true}}, "active": true})
	if c != 201 {
		e.t.Fatalf("create %s: %d %v", name, c, u)
	}
	return u["id"].(string)
}

func TestSCIMTokensAndDiscovery(t *testing.T) { // AGT-029 (INT-002)
	e, tok := scimStart(t)
	// only an owner manages provisioning
	adm, _ := e.api.Store.AddAdmin("a", "adam", store.Admin)
	for _, call := range [][]string{{"GET", "/v1/scim"}, {"PUT", "/v1/scim"}, {"POST", "/v1/scim/token"}} {
		if c, _, _ := e.call(call[0], call[1], adm, map[string]any{"enabled": true}); c != 403 {
			t.Errorf("an admin used %s %s: %d", call[0], call[1], c)
		}
	}
	// the token is the only way in: not no token, not a wrong one, not an administrator's token
	for name, bearer := range map[string]string{"none": "", "wrong": "scim-nope", "an admin token": e.adminA} {
		if c, _ := e.scim("GET", "/Users", bearer, nil); c != 401 {
			t.Errorf("%s: %d", name, c)
		}
	}
	// the SCIM token is not an administrator's
	if c, _, _ := e.call("GET", "/v1/segments", tok, nil); c != 401 {
		t.Fatalf("a SCIM token worked on the admin API: %d", c)
	}
	for _, p := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		if c, _ := e.scim("GET", p, tok, nil); c != 200 {
			t.Errorf("%s: %d", p, c)
		}
	}
	// a new token ends the old one
	_, b, _ := e.call("POST", "/v1/scim/token", e.adminA, nil)
	var tk2 struct{ Token string }
	json.Unmarshal(b, &tk2)
	if c, _ := e.scim("GET", "/Users", tok, nil); c != 401 {
		t.Fatalf("the old token still works: %d", c)
	}
	if c, _ := e.scim("GET", "/Users", tk2.Token, nil); c != 200 {
		t.Fatal(c)
	}
	// turning provisioning off ends access, with the token kept
	e.call("PUT", "/v1/scim", e.adminA, map[string]any{"enabled": false})
	if c, _ := e.scim("GET", "/Users", tk2.Token, nil); c != 401 {
		t.Fatalf("provisioning is off: %d", c)
	}
	// the token is not shown again, or audited
	if _, b, _ := e.call("GET", "/v1/scim", e.adminA, nil); strings.Contains(string(b), tk2.Token) || !strings.Contains(string(b), `"has_token":true`) {
		t.Fatalf("%s", b)
	}
	if _, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil); strings.Contains(string(ab), tk2.Token) || !strings.Contains(string(ab), "scim.token") {
		t.Fatalf("%s", ab)
	}
}

func TestSCIMUsersAndGroups(t *testing.T) { // AGT-029 (INT-002)
	e, tok := scimStart(t)
	alice := newUser(e, tok, "alice@example.com")
	bob := newUser(e, tok, "bob@example.com")
	if c, _ := e.scim("POST", "/Users", tok, map[string]any{"userName": "ALICE@example.com"}); c != 409 {
		t.Fatalf("a duplicate user name (any case): %d", c)
	}
	for name, body := range map[string]map[string]any{"no name": {"emails": []map[string]any{{"value": "x@y.z"}}}, "no e-mail": {"userName": "nomail"}, "spaces": {"userName": "a b@c.d"}} {
		if c, _ := e.scim("POST", "/Users", tok, body); c != 400 {
			t.Errorf("%s: %d", name, c)
		}
	}
	if c, _ := e.scim("POST", "/Users", tok, nil); c != 400 {
		t.Errorf("an empty body: %d", c)
	}
	c, u := e.scim("GET", "/Users/"+alice, tok, nil)
	if c != 200 || u["userName"] != "alice@example.com" || u["active"] != true || u["id"] != alice {
		t.Fatalf("%d %v", c, u)
	}
	if c, _ := e.scim("GET", "/Users/no-such-id", tok, nil); c != 404 {
		t.Fatalf("%d", c)
	}
	// listing, filtering (case-insensitive), paging
	c, l := e.scim("GET", `/Users?filter=userName%20eq%20%22ALICE@example.com%22`, tok, nil)
	if c != 200 || l["totalResults"] != float64(1) {
		t.Fatalf("%d %v", c, l)
	}
	if c, l = e.scim("GET", "/Users?count=1&startIndex=2", tok, nil); c != 200 || l["totalResults"] != float64(2) || l["itemsPerPage"] != float64(1) {
		t.Fatalf("%d %v", c, l)
	}
	if c, l = e.scim("GET", "/Users?count=0", tok, nil); c != 200 || l["itemsPerPage"] != float64(0) {
		t.Fatalf("%d %v", c, l)
	}
	for _, q := range []string{"?filter=bogus", `?filter=title%20eq%20%22x%22`, "?startIndex=0", "?count=-1", "?startIndex=x"} {
		if c, _ := e.scim("GET", "/Users"+q, tok, nil); c != 400 {
			t.Errorf("%s: %d", q, c)
		}
	}
	// groups
	if c, _ := e.scim("POST", "/Groups", tok, map[string]any{"displayName": "ghosts", "members": []map[string]string{{"value": "no-such-user"}}}); c != 400 {
		t.Fatalf("a member that is not provisioned: %d", c)
	}
	if c, _ := e.scim("POST", "/Groups", tok, map[string]any{"displayName": ""}); c != 400 {
		t.Fatalf("%d", c)
	}
	c, g := e.scim("POST", "/Groups", tok, map[string]any{"displayName": "finance", "members": []map[string]string{{"value": alice}}})
	if c != 201 {
		t.Fatalf("%d %v", c, g)
	}
	fin := g["id"].(string)
	if c, _ := e.scim("POST", "/Groups", tok, map[string]any{"displayName": "FINANCE"}); c != 409 {
		t.Fatalf("a duplicate group name: %d", c)
	}
	patch := func(ops ...map[string]any) (int, map[string]any) {
		return e.scim("PATCH", "/Groups/"+fin, tok, map[string]any{"schemas": []string{scimPatchSchema}, "Operations": ops})
	}
	if c, g = patch(map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"value": bob}}}); c != 200 || len(g["members"].([]any)) != 2 {
		t.Fatalf("%d %v", c, g)
	}
	if c, g = patch(map[string]any{"op": "remove", "path": `members[value eq "` + alice + `"]`}); c != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("%d %v", c, g)
	}
	if c, g = patch(map[string]any{"op": "Replace", "path": "displayName", "value": "finance-team"}); c != 200 || g["displayName"] != "finance-team" {
		t.Fatalf("%d %v", c, g)
	}
	if c, g = patch(map[string]any{"op": "replace", "path": "members", "value": []map[string]string{{"value": alice}, {"value": bob}}}); c != 200 || len(g["members"].([]any)) != 2 {
		t.Fatalf("%d %v", c, g)
	}
	if c, g = patch(map[string]any{"op": "remove", "path": "members", "value": []map[string]string{{"value": bob}}}); c != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("%d %v", c, g)
	}
	if c, _ = patch(map[string]any{"op": "frobnicate", "path": "members"}); c != 400 {
		t.Fatalf("an unknown operation: %d", c)
	}
	if c, l = e.scim("GET", `/Groups?filter=displayName%20eq%20%22FINANCE-team%22`, tok, nil); c != 200 || l["totalResults"] != float64(1) {
		t.Fatalf("%d %v", c, l)
	}
	// a user shows the groups they belong to
	if _, u = e.scim("GET", "/Users/"+alice, tok, nil); len(u["groups"].([]any)) != 1 {
		t.Fatalf("%v", u["groups"])
	}
	if c, _ := e.scim("DELETE", "/Groups/"+fin, tok, nil); c != 204 {
		t.Fatalf("%d", c)
	}
	if c, _ := e.scim("GET", "/Groups/"+fin, tok, nil); c != 404 {
		t.Fatalf("%d", c)
	}
}

func TestSCIMDecidesGroupsAndAccess(t *testing.T) { // AGT-029 (INT-002)
	e, tok := scimStart(t)
	var closed []string
	e.api.OnDisableUser = func(tenant, subject string) { closed = append(closed, tenant+"/"+subject) }
	// people as they appear after signing in: the groups come from the sign-in token
	e.api.Store.UpsertUser("a", policy.User{Subject: "sub-alice", Email: "Alice@Example.com", Groups: []string{"from-token"}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "sub-bob", Email: "bob@example.com", Groups: []string{"from-token"}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "agent:helper", Groups: []string{"ai-agent"}})
	alice := newUser(e, tok, "alice@example.com")
	_, g := e.scim("POST", "/Groups", tok, map[string]any{"displayName": "finance", "members": []map[string]string{{"value": alice}}})
	groups := func(sub string) string {
		u, _ := e.api.Store.User("a", sub)
		return strings.Join(u.Groups, ",")
	}
	if groups("sub-alice") != "finance" {
		t.Fatalf("a provisioned user's groups are the SCIM groups, not the token's: %q", groups("sub-alice"))
	}
	if groups("sub-bob") != "from-token" {
		t.Fatalf("a user who is not provisioned keeps the token's groups while provisioning is optional: %q", groups("sub-bob"))
	}
	// the nodes see it too: it is in the snapshot
	for _, u := range e.api.Store.Snapshot().Tenants["a"].Users {
		if u.Subject == "sub-alice" && strings.Join(u.Groups, ",") != "finance" {
			t.Fatalf("the snapshot has %v", u.Groups)
		}
	}
	// deactivate the way Entra ID sends it: a string, capital letter
	if c, _ := e.scim("PATCH", "/Users/"+alice, tok, map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}}}); c != 200 {
		t.Fatalf("%d", c)
	}
	if u, _ := e.api.Store.User("a", "sub-alice"); !u.Disabled {
		t.Fatal("a deactivated user must be disabled")
	}
	if len(closed) != 1 || closed[0] != "a/sub-alice" {
		t.Fatalf("their sessions must be closed at once: %v", closed)
	}
	if blocked, _ := e.api.Store.SCIMBlocks("a", "sub-alice", "alice@example.com"); !blocked {
		t.Fatal("sign-in of a deactivated user must be refused")
	}
	// reactivate
	e.scim("PATCH", "/Users/"+alice, tok, map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": true}}}})
	if u, _ := e.api.Store.User("a", "sub-alice"); u.Disabled {
		t.Fatal("a reactivated user must work again")
	}
	// a person the owner disabled stays disabled whatever the identity provider says
	e.api.Store.SetUserDisabled("a", "sub-alice", true)
	e.scim("PATCH", "/Users/"+alice, tok, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}}})
	if u, _ := e.api.Store.User("a", "sub-alice"); !u.Disabled {
		t.Fatal("SCIM must not re-enable a user an administrator disabled")
	}
	e.api.Store.SetUserDisabled("a", "sub-alice", false)

	// require provisioning: bob is not provisioned; an AI agent is not a person and is unaffected
	e.call("PUT", "/v1/scim", e.adminA, map[string]any{"require_provisioned": true})
	if u, _ := e.api.Store.User("a", "sub-bob"); !u.Disabled {
		t.Fatal("an unprovisioned person must be refused when provisioning is required")
	}
	if blocked, why := e.api.Store.SCIMBlocks("a", "sub-bob", "bob@example.com"); !blocked || !strings.Contains(why, "not been provisioned") {
		t.Fatalf("%v %q", blocked, why)
	}
	if u, _ := e.api.Store.User("a", "agent:helper"); u.Disabled {
		t.Fatal("an AI agent is not provisioned through SCIM")
	}
	bob := newUser(e, tok, "bob@example.com")
	if u, _ := e.api.Store.User("a", "sub-bob"); u.Disabled {
		t.Fatal("provisioning bob must let him in")
	}

	// removing a user ends access; provisioning them again restores it
	closed = nil
	if c, _ := e.scim("DELETE", "/Users/"+bob, tok, nil); c != 204 {
		t.Fatal(c)
	}
	if u, _ := e.api.Store.User("a", "sub-bob"); !u.Disabled || len(closed) != 1 {
		t.Fatalf("removal must end access and close sessions: %v %v", u.Disabled, closed)
	}
	e.call("PUT", "/v1/scim", e.adminA, map[string]any{"require_provisioned": false})
	if u, _ := e.api.Store.User("a", "sub-bob"); !u.Disabled {
		t.Fatal("a removed user stays out even when provisioning is optional, until provisioned again")
	}
	newUser(e, tok, "bob@example.com")
	if u, _ := e.api.Store.User("a", "sub-bob"); u.Disabled {
		t.Fatal("provisioning again must restore access")
	}
	_ = g
	// the audit log names the actions, as the identity provider, and never a token
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), `"scim.user.create"`) || !strings.Contains(string(ab), `"actor":"scim"`) || strings.Contains(string(ab), tok) {
		t.Fatalf("%s", ab)
	}
}

func TestSCIMIsolatesTenants(t *testing.T) { // AGT-029
	e, tokA := scimStart(t)
	e.call("PUT", "/v1/scim", e.adminB, map[string]any{"enabled": true})
	_, b, _ := e.call("POST", "/v1/scim/token", e.adminB, nil)
	var tb struct{ Token string }
	json.Unmarshal(b, &tb)
	alice := newUser(e, tokA, "alice@example.com")
	if c, _ := e.scim("GET", "/Users/"+alice, tb.Token, nil); c != 404 {
		t.Fatalf("tenant b read tenant a's user: %d", c)
	}
	if c, l := e.scim("GET", "/Users", tb.Token, nil); c != 200 || l["totalResults"] != float64(0) {
		t.Fatalf("%d %v", c, l)
	}
	if c, _ := e.scim("DELETE", "/Users/"+alice, tb.Token, nil); c != 404 {
		t.Fatalf("tenant b deleted tenant a's user: %d", c)
	}
	if c, _ := e.scim("GET", "/Users/"+alice, tokA, nil); c != 200 {
		t.Fatal("the user must still be there")
	}
	// the same name in two tenants is fine
	newUser(e, tb.Token, "alice@example.com")
}
