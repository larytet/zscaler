package cp

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/larytet/zscaler/internal/store"
)

// routeInfo is one route of the admin API as registered.
type routeInfo struct {
	Method, Path string
	Scheme       string     // "admin" (an administrator's token), "scim", "bootstrapToken" or "" (none)
	Perm         store.Perm // for "admin" routes: the permission a role needs
	Handler      string     // the Go handler, which gives the operation its id
}

func handlerName(h any) string {
	n := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	n = n[strings.LastIndex(n, ".")+1:]
	return strings.TrimSuffix(n, "-fm")
}

func (a *API) record(pattern, scheme string, perm store.Perm, h any) {
	f := strings.SplitN(pattern, " ", 2)
	a.routes = append(a.routes, routeInfo{Method: f[0], Path: f[1], Scheme: scheme, Perm: perm, Handler: handlerName(h)})
}

// route registers an administrator route and records it for the API description (INT-006).
func (a *API) route(m *http.ServeMux, pattern string, perm store.Perm, h handler) {
	m.HandleFunc(pattern, a.wrap(perm, h))
	a.record(pattern, "admin", perm, h)
}

func (a *API) scimRoute(m *http.ServeMux, pattern string, h scimHandler) {
	m.HandleFunc(pattern, a.scimAuth(h))
	a.record(pattern, "scim", "", h)
}

func (a *API) plain(m *http.ServeMux, pattern, scheme string, h http.HandlerFunc) {
	m.HandleFunc(pattern, h)
	a.record(pattern, scheme, "", h)
}

var pathParam = regexp.MustCompile(`\{([a-zA-Z]+)\}`)

// words turns putPolicy into "Put policy".
func words(name string) string {
	var sb strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) && i > 0 {
			sb.WriteByte(' ')
		}
		if i == 0 {
			sb.WriteRune(unicode.ToUpper(r))
		} else {
			sb.WriteRune(unicode.ToLower(r))
		}
	}
	return sb.String()
}

// OpenAPI describes every route of the admin API (OpenAPI 3.0.3), built from the routes as they were
// registered, so it cannot drift from the code. It gives each operation its address, method, the
// permission and roles it needs and its path parameters. It does not describe request or response
// fields: bodies are shown as JSON objects (see the README and the field names in the handlers).
func (a *API) OpenAPI() []byte {
	paths := map[string]map[string]any{}
	rs := append([]routeInfo(nil), a.routes...)
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Path != rs[j].Path {
			return rs[i].Path < rs[j].Path
		}
		return rs[i].Method < rs[j].Method
	})
	for _, r := range rs {
		op := map[string]any{"operationId": r.Handler, "summary": words(r.Handler)}
		var params []map[string]any
		for _, m := range pathParam.FindAllStringSubmatch(r.Path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]string{"type": "string"}})
		}
		responses := map[string]any{"200": map[string]string{"description": "Success"}}
		switch r.Scheme {
		case "admin":
			op["security"] = []map[string][]string{{"bearerAuth": {}}}
			op["x-required-permission"] = string(r.Perm)
			roles := store.RolesWith(r.Perm)
			names := make([]string, len(roles))
			for i, ro := range roles {
				names[i] = string(ro)
			}
			op["x-roles"] = names
			responses["401"] = map[string]string{"description": "No token, or an invalid or expired one"}
			responses["403"] = map[string]string{"description": "The role of the token does not have the permission " + string(r.Perm)}
		case "scim":
			op["security"] = []map[string][]string{{"scimToken": {}}}
			responses["401"] = map[string]string{"description": "No token, an invalid one, or provisioning is not enabled"}
		case "bootstrapToken":
			op["security"] = []map[string][]string{{"bootstrapToken": {}}}
			responses["401"] = map[string]string{"description": "The bootstrap token is required"}
		default:
			op["security"] = []map[string][]string{}
		}
		if strings.HasPrefix(r.Path, "/v1/policies/") && (r.Method == "PUT" || strings.HasSuffix(r.Path, "/rollback")) {
			params = append(params, map[string]any{"name": "If-Match", "in": "header", "required": true, "description": "The current version of the policy (0 for a new one)", "schema": map[string]string{"type": "integer"}})
			responses["412"] = map[string]string{"description": "The policy changed: read it again and retry"}
			responses["428"] = map[string]string{"description": "If-Match is required"}
		}
		responses["400"] = map[string]string{"description": "The request is not valid; the message says why"}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			op["requestBody"] = map[string]any{"required": false, "content": map[string]any{"application/json": map[string]any{"schema": map[string]string{"type": "object"}}}}
		}
		op["responses"] = responses
		if paths[r.Path] == nil {
			paths[r.Path] = map[string]any{}
		}
		paths[r.Path][strings.ToLower(r.Method)] = op
	}
	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{"title": "SMB-ZTX admin API", "version": "0.8",
			"description": "Every route of the control plane's admin API, generated from the routes as registered. Request and response bodies are JSON; their fields are not described here. The enrolment and synchronisation routes used by the agent, connector and enforcement nodes (a different listener) are not part of it."},
		"paths": paths,
		"components": map[string]any{"securitySchemes": map[string]any{
			"bearerAuth":     map[string]string{"type": "http", "scheme": "bearer", "description": "An administrator's token (POST /v1/admins makes more, GET /v1/admins lists them)"},
			"scimToken":      map[string]string{"type": "http", "scheme": "bearer", "description": "The tenant's SCIM token (POST /v1/scim/token)"},
			"bootstrapToken": map[string]string{"type": "http", "scheme": "bearer", "description": "The platform's bootstrap token, for creating tenants and enforcement node tokens"},
		}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n')
}

func (a *API) openAPI(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return json.RawMessage(a.OpenAPI()), nil
}
