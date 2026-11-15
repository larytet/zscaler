package cp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/larytet/zscaler/internal/store"
)

// SCIM 2.0 (RFC 7643, 7644) provisioning of users and groups (INT-002). An identity provider such as
// Entra ID, Okta or Google Workspace calls these endpoints with the tenant's SCIM token. The supported
// part is the one those products use: users and groups with create, read, replace, patch, delete,
// listing with paging and an equality filter, and the discovery endpoints.

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type scimErr struct {
	status  int
	scimTyp string
	detail  string
}

func (e *scimErr) Error() string { return e.detail }

func scimFail(status int, typ, detail string) *scimErr { return &scimErr{status, typ, detail} }

func scimWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func scimWriteErr(w http.ResponseWriter, err error) {
	var se *scimErr
	if !errors.As(err, &se) {
		switch {
		case errors.Is(err, store.ErrNotFound):
			se = scimFail(404, "", "resource not found")
		case errors.Is(err, store.ErrSCIMConflict):
			se = scimFail(409, "uniqueness", "a resource with that name exists")
		case errors.Is(err, store.ErrSCIMLimit):
			se = scimFail(409, "tooMany", "too many resources for this tenant")
		default:
			se = scimFail(400, "invalidValue", err.Error())
		}
	}
	scimWrite(w, se.status, map[string]any{"schemas": []string{scimErrSchema}, "status": strconv.Itoa(se.status), "scimType": se.scimTyp, "detail": se.detail})
}

type scimHandler func(w http.ResponseWriter, r *http.Request, tenant string) error

// scimAuth checks the SCIM token. It is not an administrator token: it can provision, nothing else.
func (a *API) scimAuth(h scimHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			scimWriteErr(w, scimFail(401, "", "bearer token required"))
			return
		}
		tenant, ok := a.Store.SCIMTenant(tok)
		if !ok {
			scimWriteErr(w, scimFail(401, "", "invalid token, or provisioning is not enabled"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := h(w, r, tenant); err != nil {
			scimWriteErr(w, err)
		}
	}
}

func (a *API) scimLog(tenant, action, object string, after any) {
	a.log(ctxInfo{tenant: tenant, actor: "scim"}, action, object, nil, after)
}

func (a *API) mountSCIM(m *http.ServeMux) {
	m.HandleFunc("GET /scim/v2/ServiceProviderConfig", a.scimAuth(a.scimConfig))
	m.HandleFunc("GET /scim/v2/ResourceTypes", a.scimAuth(a.scimResourceTypes))
	m.HandleFunc("GET /scim/v2/Schemas", a.scimAuth(a.scimSchemas))
	m.HandleFunc("GET /scim/v2/Users", a.scimAuth(a.scimListUsers))
	m.HandleFunc("POST /scim/v2/Users", a.scimAuth(a.scimCreateUser))
	m.HandleFunc("GET /scim/v2/Users/{id}", a.scimAuth(a.scimGetUser))
	m.HandleFunc("PUT /scim/v2/Users/{id}", a.scimAuth(a.scimReplaceUser))
	m.HandleFunc("PATCH /scim/v2/Users/{id}", a.scimAuth(a.scimPatchUser))
	m.HandleFunc("DELETE /scim/v2/Users/{id}", a.scimAuth(a.scimDeleteUser))
	m.HandleFunc("GET /scim/v2/Groups", a.scimAuth(a.scimListGroups))
	m.HandleFunc("POST /scim/v2/Groups", a.scimAuth(a.scimCreateGroup))
	m.HandleFunc("GET /scim/v2/Groups/{id}", a.scimAuth(a.scimGetGroup))
	m.HandleFunc("PUT /scim/v2/Groups/{id}", a.scimAuth(a.scimReplaceGroup))
	m.HandleFunc("PATCH /scim/v2/Groups/{id}", a.scimAuth(a.scimPatchGroup))
	m.HandleFunc("DELETE /scim/v2/Groups/{id}", a.scimAuth(a.scimDeleteGroup))
}

func (a *API) scimConfig(w http.ResponseWriter, r *http.Request, tenant string) error {
	scimWrite(w, 200, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer token", "description": "The tenant's SCIM token"}},
	})
	return nil
}

func (a *API) scimResourceTypes(w http.ResponseWriter, r *http.Request, tenant string) error {
	scimWrite(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "Resources": []map[string]string{
		{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema},
		{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema}}})
	return nil
}

func (a *API) scimSchemas(w http.ResponseWriter, r *http.Request, tenant string) error {
	scimWrite(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "Resources": []map[string]string{
		{"id": scimUserSchema, "name": "User"}, {"id": scimGroupSchema, "name": "Group"}}})
	return nil
}

// ---- users ----

type scimUserBody struct {
	ExternalID  string `json:"externalId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Name        struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Active *bool `json:"active"`
}

func (b scimUserBody) in() (store.SCIMUserIn, error) {
	in := store.SCIMUserIn{ExternalID: b.ExternalID, UserName: strings.TrimSpace(b.UserName), DisplayName: b.DisplayName, Active: true}
	if b.Active != nil {
		in.Active = *b.Active
	}
	if in.DisplayName == "" {
		in.DisplayName = b.Name.Formatted
	}
	for _, e := range b.Emails {
		if in.Email == "" || e.Primary {
			in.Email = strings.TrimSpace(e.Value)
		}
	}
	if in.Email == "" && strings.Contains(in.UserName, "@") {
		in.Email = in.UserName
	}
	if in.UserName == "" || len(in.UserName) > 256 || in.Email == "" || len(in.Email) > 256 || !strings.Contains(in.Email, "@") ||
		strings.ContainsAny(in.UserName+in.Email, "\r\n\x00 ") {
		return in, scimFail(400, "invalidValue", "userName and an e-mail address are required (one line, no spaces)")
	}
	return in, nil
}

func scimUserJSON(su store.SCIMUser, groups []store.SCIMGroup) map[string]any {
	gs := make([]map[string]string, 0, len(groups))
	for _, g := range groups {
		gs = append(gs, map[string]string{"value": g.ID, "display": g.DisplayName, "$ref": "/scim/v2/Groups/" + g.ID})
	}
	out := map[string]any{"schemas": []string{scimUserSchema}, "id": su.ID, "userName": su.UserName, "displayName": su.DisplayName,
		"emails": []map[string]any{{"value": su.Email, "primary": true}}, "active": su.Active, "groups": gs,
		"meta": map[string]any{"resourceType": "User", "created": su.Created, "lastModified": su.Updated, "location": "/scim/v2/Users/" + su.ID}}
	if su.ExternalID != "" {
		out["externalId"] = su.ExternalID
	}
	return out
}

var scimFilter = regexp.MustCompile(`(?i)^\s*([A-Za-z.]+)\s+eq\s+"([^"]*)"\s*$`)

func scimPage(r *http.Request) (start, count int, err error) {
	start, count = 1, 100
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if start, err = strconv.Atoi(v); err != nil || start < 1 {
			return 0, 0, scimFail(400, "invalidValue", "startIndex must be 1 or more")
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if count, err = strconv.Atoi(v); err != nil || count < 0 {
			return 0, 0, scimFail(400, "invalidValue", "count must be 0 or more")
		}
	}
	if count > 200 {
		count = 200
	}
	return start, count, nil
}

func scimFilterOf(r *http.Request) (attr, val string, err error) {
	f := r.URL.Query().Get("filter")
	if f == "" {
		return "", "", nil
	}
	m := scimFilter.FindStringSubmatch(f)
	if m == nil {
		return "", "", scimFail(400, "invalidFilter", `only filters of the form attribute eq "value" are supported`)
	}
	return strings.ToLower(m[1]), strings.ToLower(m[2]), nil
}

func (a *API) scimListUsers(w http.ResponseWriter, r *http.Request, tenant string) error {
	attr, val, err := scimFilterOf(r)
	if err != nil {
		return err
	}
	start, count, err := scimPage(r)
	if err != nil {
		return err
	}
	var matched []map[string]any
	for _, su := range a.Store.SCIMUserList(tenant) {
		ok := true
		switch attr {
		case "":
		case "username":
			ok = strings.ToLower(su.UserName) == val
		case "externalid":
			ok = strings.ToLower(su.ExternalID) == val
		case "emails.value", "emails":
			ok = strings.ToLower(su.Email) == val
		case "displayname":
			ok = strings.ToLower(su.DisplayName) == val
		default:
			return scimFail(400, "invalidFilter", "cannot filter users on "+attr)
		}
		if ok {
			_, gs, _ := a.Store.SCIMUserGet(tenant, su.ID)
			matched = append(matched, scimUserJSON(su, gs))
		}
	}
	scimWrite(w, 200, scimListOf(matched, start, count))
	return nil
}

func scimListOf(all []map[string]any, start, count int) map[string]any {
	res := []map[string]any{}
	if start-1 < len(all) {
		end := start - 1 + count
		if end > len(all) {
			end = len(all)
		}
		res = all[start-1 : end]
	}
	return map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(all), "startIndex": start, "itemsPerPage": len(res), "Resources": res}
}

func decodeBody(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return scimFail(400, "invalidSyntax", "the body could not be read")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return scimFail(400, "invalidSyntax", "the body is not valid JSON")
	}
	return nil
}

func (a *API) endAccess(tenant string, subjects []string) {
	if a.OnDisableUser != nil {
		for _, s := range subjects {
			a.OnDisableUser(tenant, s) // close their sessions now, as for an admin's disable
		}
	}
}

func (a *API) scimCreateUser(w http.ResponseWriter, r *http.Request, tenant string) error {
	var b scimUserBody
	if err := decodeBody(r, &b); err != nil {
		return err
	}
	in, err := b.in()
	if err != nil {
		return err
	}
	su, _, err := a.Store.SCIMPutUser(tenant, "", in)
	if err != nil {
		return err
	}
	a.scimLog(tenant, "scim.user.create", su.ID, map[string]bool{"active": su.Active})
	w.Header().Set("Location", "/scim/v2/Users/"+su.ID)
	scimWrite(w, 201, scimUserJSON(su, nil))
	return nil
}

func (a *API) scimGetUser(w http.ResponseWriter, r *http.Request, tenant string) error {
	su, gs, ok := a.Store.SCIMUserGet(tenant, r.PathValue("id"))
	if !ok {
		return scimFail(404, "", "user not found")
	}
	scimWrite(w, 200, scimUserJSON(su, gs))
	return nil
}

func (a *API) scimReplaceUser(w http.ResponseWriter, r *http.Request, tenant string) error {
	var b scimUserBody
	if err := decodeBody(r, &b); err != nil {
		return err
	}
	in, err := b.in()
	if err != nil {
		return err
	}
	su, ended, err := a.Store.SCIMPutUser(tenant, r.PathValue("id"), in)
	if err != nil {
		return err
	}
	a.endAccess(tenant, ended)
	a.scimLog(tenant, "scim.user.replace", su.ID, map[string]bool{"active": su.Active})
	_, gs, _ := a.Store.SCIMUserGet(tenant, su.ID)
	scimWrite(w, 200, scimUserJSON(su, gs))
	return nil
}

type scimOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type scimPatchBody struct {
	Schemas    []string `json:"schemas"`
	Operations []scimOp `json:"Operations"`
}

// truthy reads a boolean the way identity providers send it: true, "true", "True".
func truthy(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(s) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func asString(raw json.RawMessage) string {
	var s string
	json.Unmarshal(raw, &s)
	return s
}

func (a *API) scimPatchUser(w http.ResponseWriter, r *http.Request, tenant string) error {
	id := r.PathValue("id")
	su, _, ok := a.Store.SCIMUserGet(tenant, id)
	if !ok {
		return scimFail(404, "", "user not found")
	}
	var body scimPatchBody
	if err := decodeBody(r, &body); err != nil {
		return err
	}
	in := store.SCIMUserIn{ExternalID: su.ExternalID, UserName: su.UserName, Email: su.Email, DisplayName: su.DisplayName, Active: su.Active}
	set := func(attr string, raw json.RawMessage) error {
		switch strings.ToLower(attr) {
		case "active":
			v, ok := truthy(raw)
			if !ok {
				return scimFail(400, "invalidValue", "active must be true or false")
			}
			in.Active = v
		case "username":
			in.UserName = asString(raw)
		case "displayname":
			in.DisplayName = asString(raw)
		case "externalid":
			in.ExternalID = asString(raw)
		case "emails", "emails.value":
			var list []struct {
				Value   string `json:"value"`
				Primary bool   `json:"primary"`
			}
			if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
				in.Email = list[0].Value
				for _, e := range list {
					if e.Primary {
						in.Email = e.Value
					}
				}
			} else if s := asString(raw); s != "" {
				in.Email = s
			}
		} // anything else (name parts, title, ...) is accepted and ignored: providers send many attributes
		return nil
	}
	for _, op := range body.Operations {
		switch strings.ToLower(op.Op) {
		case "add", "replace":
			path := op.Path
			if strings.HasPrefix(strings.ToLower(path), "emails[") {
				path = "emails"
			}
			if path != "" {
				if err := set(path, op.Value); err != nil {
					return err
				}
				continue
			}
			var obj map[string]json.RawMessage
			if json.Unmarshal(op.Value, &obj) != nil {
				return scimFail(400, "invalidValue", "an operation without a path needs an object value")
			}
			for k, v := range obj {
				if err := set(k, v); err != nil {
					return err
				}
			}
		case "remove":
			if strings.EqualFold(op.Path, "displayName") {
				in.DisplayName = ""
			}
		default:
			return scimFail(400, "invalidValue", "unknown operation "+op.Op)
		}
	}
	nu, ended, err := a.Store.SCIMPutUser(tenant, id, in)
	if err != nil {
		return err
	}
	a.endAccess(tenant, ended)
	a.scimLog(tenant, "scim.user.patch", id, map[string]bool{"active": nu.Active})
	_, gs, _ := a.Store.SCIMUserGet(tenant, id)
	scimWrite(w, 200, scimUserJSON(nu, gs))
	return nil
}

func (a *API) scimDeleteUser(w http.ResponseWriter, r *http.Request, tenant string) error {
	ended, err := a.Store.SCIMDeleteUser(tenant, r.PathValue("id"))
	if err != nil {
		return err
	}
	a.endAccess(tenant, ended)
	a.scimLog(tenant, "scim.user.delete", r.PathValue("id"), nil)
	scimWrite(w, 204, nil)
	return nil
}

// ---- groups ----

func scimGroupJSON(g store.SCIMGroup, a *API, tenant string) map[string]any {
	ms := make([]map[string]string, 0, len(g.Members))
	for _, m := range g.Members {
		if su, _, ok := a.Store.SCIMUserGet(tenant, m); ok {
			ms = append(ms, map[string]string{"value": m, "display": su.DisplayName, "$ref": "/scim/v2/Users/" + m})
		}
	}
	out := map[string]any{"schemas": []string{scimGroupSchema}, "id": g.ID, "displayName": g.DisplayName, "members": ms,
		"meta": map[string]any{"resourceType": "Group", "created": g.Created, "lastModified": g.Updated, "location": "/scim/v2/Groups/" + g.ID}}
	if g.ExternalID != "" {
		out["externalId"] = g.ExternalID
	}
	return out
}

type scimGroupBody struct {
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (b scimGroupBody) ids() []string {
	out := make([]string, 0, len(b.Members))
	for _, m := range b.Members {
		out = append(out, m.Value)
	}
	return out
}

func (a *API) scimListGroups(w http.ResponseWriter, r *http.Request, tenant string) error {
	attr, val, err := scimFilterOf(r)
	if err != nil {
		return err
	}
	start, count, err := scimPage(r)
	if err != nil {
		return err
	}
	var matched []map[string]any
	for _, g := range a.Store.SCIMGroupList(tenant) {
		ok := true
		switch attr {
		case "":
		case "displayname":
			ok = strings.ToLower(g.DisplayName) == val
		case "externalid":
			ok = strings.ToLower(g.ExternalID) == val
		default:
			return scimFail(400, "invalidFilter", "cannot filter groups on "+attr)
		}
		if ok {
			matched = append(matched, scimGroupJSON(g, a, tenant))
		}
	}
	scimWrite(w, 200, scimListOf(matched, start, count))
	return nil
}

func (a *API) scimCreateGroup(w http.ResponseWriter, r *http.Request, tenant string) error {
	var b scimGroupBody
	if err := decodeBody(r, &b); err != nil {
		return err
	}
	g, err := a.Store.SCIMPutGroup(tenant, "", b.ExternalID, b.DisplayName, b.ids())
	if err != nil {
		return err
	}
	a.scimLog(tenant, "scim.group.create", g.ID, map[string]int{"members": len(g.Members)})
	w.Header().Set("Location", "/scim/v2/Groups/"+g.ID)
	scimWrite(w, 201, scimGroupJSON(g, a, tenant))
	return nil
}

func (a *API) scimGetGroup(w http.ResponseWriter, r *http.Request, tenant string) error {
	g, ok := a.Store.SCIMGroupGet(tenant, r.PathValue("id"))
	if !ok {
		return scimFail(404, "", "group not found")
	}
	scimWrite(w, 200, scimGroupJSON(g, a, tenant))
	return nil
}

func (a *API) scimReplaceGroup(w http.ResponseWriter, r *http.Request, tenant string) error {
	var b scimGroupBody
	if err := decodeBody(r, &b); err != nil {
		return err
	}
	g, err := a.Store.SCIMPutGroup(tenant, r.PathValue("id"), b.ExternalID, b.DisplayName, b.ids())
	if err != nil {
		return err
	}
	a.scimLog(tenant, "scim.group.replace", g.ID, map[string]int{"members": len(g.Members)})
	scimWrite(w, 200, scimGroupJSON(g, a, tenant))
	return nil
}

var memberPath = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"([^"]+)"\]$`)

func (a *API) scimPatchGroup(w http.ResponseWriter, r *http.Request, tenant string) error {
	id := r.PathValue("id")
	g, ok := a.Store.SCIMGroupGet(tenant, id)
	if !ok {
		return scimFail(404, "", "group not found")
	}
	var body scimPatchBody
	if err := decodeBody(r, &body); err != nil {
		return err
	}
	name, ext := g.DisplayName, g.ExternalID
	members := map[string]bool{}
	for _, m := range g.Members {
		members[m] = true
	}
	values := func(raw json.RawMessage) []string {
		var list []struct {
			Value string `json:"value"`
		}
		json.Unmarshal(raw, &list)
		out := make([]string, 0, len(list))
		for _, m := range list {
			out = append(out, m.Value)
		}
		return out
	}
	apply := func(op, path string, raw json.RawMessage) error {
		switch {
		case strings.EqualFold(path, "displayName") && op != "remove":
			name = asString(raw)
		case strings.EqualFold(path, "externalId") && op != "remove":
			ext = asString(raw)
		case strings.EqualFold(path, "members"):
			switch op {
			case "add":
				for _, v := range values(raw) {
					members[v] = true
				}
			case "replace":
				members = map[string]bool{}
				for _, v := range values(raw) {
					members[v] = true
				}
			case "remove":
				if len(raw) == 0 {
					members = map[string]bool{} // remove with no value empties the group
				}
				for _, v := range values(raw) {
					delete(members, v)
				}
			}
		case memberPath.MatchString(path):
			if op == "remove" {
				delete(members, memberPath.FindStringSubmatch(path)[1])
			}
		}
		return nil
	}
	for _, o := range body.Operations {
		op := strings.ToLower(o.Op)
		if op != "add" && op != "replace" && op != "remove" {
			return scimFail(400, "invalidValue", "unknown operation "+o.Op)
		}
		if o.Path != "" {
			apply(op, o.Path, o.Value)
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(o.Value, &obj) != nil {
			return scimFail(400, "invalidValue", "an operation without a path needs an object value")
		}
		for k, v := range obj {
			apply(op, k, v)
		}
	}
	ids := make([]string, 0, len(members))
	for m := range members {
		ids = append(ids, m)
	}
	sort.Strings(ids)
	ng, err := a.Store.SCIMPutGroup(tenant, id, ext, name, ids)
	if err != nil {
		return err
	}
	a.scimLog(tenant, "scim.group.patch", id, map[string]int{"members": len(ng.Members)})
	scimWrite(w, 200, scimGroupJSON(ng, a, tenant))
	return nil
}

func (a *API) scimDeleteGroup(w http.ResponseWriter, r *http.Request, tenant string) error {
	if err := a.Store.SCIMDeleteGroup(tenant, r.PathValue("id")); err != nil {
		return err
	}
	a.scimLog(tenant, "scim.group.delete", r.PathValue("id"), nil)
	scimWrite(w, 204, nil)
	return nil
}

// ---- administration of provisioning (owners) ----

func (a *API) scimStatus(tenant string) map[string]any {
	c, users, groups := a.Store.SCIMConfigOf(tenant)
	return map[string]any{"enabled": c.Enabled, "require_provisioned": c.RequireProvisioned, "has_token": c.HasToken,
		"users": users, "groups": groups, "base_path": "/scim/v2"}
}

func (a *API) getSCIM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.scimStatus(c.tenant), nil
}

// putSCIM turns provisioning on or off. Provisioning decides who is in which group, so it needs the
// owner role: whoever holds the SCIM token can grant any access a group grants.
func (a *API) putSCIM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Enabled            *bool `json:"enabled"`
		RequireProvisioned *bool `json:"require_provisioned"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	cur, _, _ := a.Store.SCIMConfigOf(c.tenant)
	if in.Enabled != nil {
		cur.Enabled = *in.Enabled
	}
	if in.RequireProvisioned != nil {
		cur.RequireProvisioned = *in.RequireProvisioned
	}
	if err := a.Store.SetSCIM(c.tenant, cur.Enabled, cur.RequireProvisioned); err != nil {
		return nil, err
	}
	a.log(c, "scim.put", "", nil, map[string]bool{"enabled": cur.Enabled, "require_provisioned": cur.RequireProvisioned})
	return a.scimStatus(c.tenant), nil
}

// scimToken makes a new SCIM token, ending the old one, and shows it once.
func (a *API) scimToken(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	tok, err := a.Store.NewSCIMToken(c.tenant)
	if err != nil {
		return nil, err
	}
	a.log(c, "scim.token", "", nil, nil) // never the token
	return map[string]string{"token": tok, "base_path": "/scim/v2", "note": "shown once; give it to your identity provider as the bearer token"}, nil
}
