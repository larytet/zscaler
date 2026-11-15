package cp

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/store"
)

type spec struct {
	OpenAPI string `json:"openapi"`
	Paths   map[string]map[string]struct {
		OperationID string   `json:"operationId"`
		Summary     string   `json:"summary"`
		Permission  string   `json:"x-required-permission"`
		Roles       []string `json:"x-roles"`
		Parameters  []struct {
			Name string `json:"name"`
			In   string `json:"in"`
		} `json:"parameters"`
		Responses map[string]any `json:"responses"`
	} `json:"paths"`
	Components struct {
		SecuritySchemes map[string]any `json:"securitySchemes"`
	} `json:"components"`
}

func TestOpenAPIDescribesEveryRouteAndIsConsistent(t *testing.T) { // AGT-036 (INT-006)
	api := &API{}
	api.Handler()
	var sp spec
	if err := json.Unmarshal(api.OpenAPI(), &sp); err != nil {
		t.Fatal(err)
	}
	if sp.OpenAPI != "3.0.3" || len(sp.Paths) < 60 {
		t.Fatalf("%s with %d paths", sp.OpenAPI, len(sp.Paths))
	}
	for _, s := range []string{"bearerAuth", "scimToken", "bootstrapToken"} {
		if sp.Components.SecuritySchemes[s] == nil {
			t.Errorf("security scheme %s is not described", s)
		}
	}
	// every registered route is in the description, once, with its permission and the roles that have it
	ids := map[string]bool{}
	n := 0
	for _, r := range api.routes {
		op, ok := sp.Paths[r.Path][strings.ToLower(r.Method)]
		if !ok {
			t.Errorf("%s %s is registered but not described", r.Method, r.Path)
			continue
		}
		n++
		if op.OperationID == "" || op.Summary == "" || len(op.Responses) < 2 {
			t.Errorf("%s %s: incomplete: %+v", r.Method, r.Path, op)
		}
		if r.Scheme == "admin" {
			want := store.RolesWith(r.Perm)
			if op.Permission != string(r.Perm) || len(op.Roles) != len(want) || len(want) == 0 {
				t.Errorf("%s %s: permission %q roles %v, expected %v", r.Method, r.Path, op.Permission, op.Roles, want)
			}
		}
		// every {parameter} of the address is declared
		for _, m := range pathParam.FindAllStringSubmatch(r.Path, -1) {
			found := false
			for _, p := range op.Parameters {
				found = found || (p.Name == m[1] && p.In == "path")
			}
			if !found {
				t.Errorf("%s %s: parameter %s is not declared", r.Method, r.Path, m[1])
			}
		}
	}
	total := 0
	for _, ms := range sp.Paths {
		total += len(ms)
	}
	if total != len(api.routes) || n != len(api.routes) {
		t.Errorf("the description has %d operations for %d routes", total, len(api.routes))
	}
	// the same operation id is not used twice for different routes of the same handler name
	seen := map[string]string{}
	for _, r := range api.routes {
		key := r.Method + " " + r.Path
		if prev, dup := seen[r.Handler]; dup && prev != key && r.Handler != "" {
			// two routes may share a handler (the SCIM Users and Groups differ in name); report a real clash
			if strings.Split(prev, " ")[0] == r.Method && prev == key {
				t.Errorf("duplicate route %s", key)
			}
		}
		seen[r.Handler] = key
		ids[r.Handler] = true
	}
	// a policy save says it needs If-Match
	put := sp.Paths["/v1/policies/{kind}"]["put"]
	hasIfMatch := false
	for _, p := range put.Parameters {
		hasIfMatch = hasIfMatch || (p.Name == "If-Match" && p.In == "header")
	}
	if !hasIfMatch || put.Responses["428"] == nil {
		t.Errorf("saving a policy needs If-Match: %+v", put)
	}
}

// the description says what each route needs; here the code is made to do it: no token is refused, a role
// without the permission is refused, and a role with it is not refused. (That the permission is the right one
// is a decision; TestTheCommittedDescriptionIsCurrent makes any change of it a deliberate act.)
func TestEveryDescribedRouteEnforcesItsPermission(t *testing.T) { // AGT-036 (INT-006)
	e := newEnrolEnv(t)
	roles := []store.Role{store.Owner, store.Admin, store.Helpdesk, store.Auditor, store.Viewer}
	tok := map[store.Role]string{store.Owner: e.adminA}
	for _, r := range roles[1:] {
		tok[r], _ = e.api.Store.AddAdmin("a", "u-"+string(r), r)
	}
	subst := pathParam.ReplaceAllString
	checked := 0
	for _, r := range e.api.routes {
		if r.Scheme != "admin" {
			continue
		}
		path := subst(r.Path, "x")
		if c, _, _ := e.call(r.Method, path, "", nil); c != 401 {
			t.Errorf("%s %s with no token: %d", r.Method, r.Path, c)
		}
		for _, role := range roles {
			code, _, _ := e.call(r.Method, path, tok[role], map[string]any{})
			switch {
			case !role.Can(r.Perm) && code != 403:
				t.Errorf("%s %s as %s: %d, but the description says %s needs %q", r.Method, r.Path, role, code, role, r.Perm)
			case role.Can(r.Perm) && r.Method == "GET" && (code == 403 || code == 401):
				t.Errorf("%s %s as %s: %d, but the description says the role may", r.Method, r.Path, role, code)
			}
		}
		checked++
	}
	if checked < 70 {
		t.Fatalf("only %d administrator routes were checked", checked)
	}
}

func TestTheConsoleOnlyUsesDescribedRoutes(t *testing.T) { // AGT-036 (INT-006: the API covers every console action)
	js, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	api := &API{}
	api.Handler()
	call := regexp.MustCompile(`api\('(GET|POST|PUT|DELETE|PATCH)', '(/v1/[^'?]*)'`)
	fetch := regexp.MustCompile(`fetch\('(/v1/[^'?]*)'`)
	type use struct{ method, lit string }
	var uses []use
	for _, m := range call.FindAllStringSubmatch(string(js), -1) {
		uses = append(uses, use{m[1], m[2]})
	}
	for _, m := range fetch.FindAllStringSubmatch(string(js), -1) {
		uses = append(uses, use{"GET", m[1]})
	}
	if len(uses) < 20 {
		t.Fatalf("found only %d API calls in the console: the check is not looking at the right thing", len(uses))
	}
	for _, u := range uses {
		ok := false
		for _, r := range api.routes {
			if r.Method != u.method {
				continue
			}
			full := regexp.MustCompile("^" + regexp.MustCompile(`\\\{[a-zA-Z]+\\\}`).ReplaceAllString(regexp.QuoteMeta(r.Path), "[^/]+") + "$")
			filled := pathParam.ReplaceAllString(r.Path, "x") // a literal that ends in "/" is the start of an address built from parts
			if full.MatchString(u.lit) || (strings.HasSuffix(u.lit, "/") && strings.HasPrefix(filled, u.lit)) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("the console calls %s %s, which no described route matches", u.method, u.lit)
		}
	}
}

func TestTheCommittedDescriptionIsCurrent(t *testing.T) { // AGT-036
	api := &API{}
	api.Handler()
	got, err := os.ReadFile("../../API.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(api.OpenAPI()) {
		t.Fatal("API.openapi.json is out of date: run  go run ./cmd/ztx-cp -print-openapi > API.openapi.json  and commit it")
	}
}

func TestOpenAPIEndpoint(t *testing.T) { // AGT-036
	e := newEnrolEnv(t)
	c, b, _ := e.call("GET", "/v1/openapi.json", e.adminA, nil)
	var sp spec
	if c != 200 || json.Unmarshal(b, &sp) != nil || sp.OpenAPI != "3.0.3" || sp.Paths["/v1/openapi.json"]["get"].OperationID != "openAPI" {
		t.Fatalf("%d %.200s", c, b)
	}
	if c, _, _ := e.call("GET", "/v1/openapi.json", "", nil); c != 401 {
		t.Fatalf("the description needs a token: %d", c)
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("GET", "/v1/openapi.json", viewer, nil); c != 200 {
		t.Fatalf("anyone who can read may read it: %d", c)
	}
}
