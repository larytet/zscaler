// Package cp is the control-plane admin API (DESIGN.md D5.1).
package cp

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

type API struct {
	Store          *store.Store
	Audit          *audit.Log
	AuditPath      string
	Tokens         *pki.Tokens
	BootstrapToken string
	// Hooks let enforcement nodes react immediately to revocations.
	Alerts         *alerts.Engine
	OnRevokeDevice func(tenant string, d store.Device)
	OnDisableUser  func(tenant, subject string)
}

type apiErr struct {
	status int
	Code   string `json:"code"`
	Msg    string `json:"message"`
}

func (e *apiErr) Error() string { return e.Msg }

func fail(status int, code, msg string) *apiErr { return &apiErr{status, code, msg} }

type ctxInfo struct {
	tenant, actor string
	role          store.Role
}

type handler func(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error)

func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	m.HandleFunc("POST /v1/tenants", a.createTenant)
	m.HandleFunc("POST /v1/ens/tokens", a.enToken)
	read, write := store.Viewer, store.Admin
	m.HandleFunc("PUT /v1/idp", a.wrap(write, a.putIDP))
	m.HandleFunc("GET /v1/segments", a.wrap(read, a.listSegments))
	m.HandleFunc("POST /v1/segments", a.wrap(write, a.putSegment))
	m.HandleFunc("PUT /v1/segments/{id}", a.wrap(write, a.putSegment))
	m.HandleFunc("DELETE /v1/segments/{id}", a.wrap(write, a.deleteSegment))
	m.HandleFunc("GET /v1/policies/{kind}", a.wrap(read, a.getPolicy))
	m.HandleFunc("PUT /v1/policies/{kind}", a.wrap(write, a.putPolicy))
	m.HandleFunc("POST /v1/policies/{kind}/dry-run", a.wrap(read, a.dryRun))
	m.HandleFunc("POST /v1/policies/safe-defaults", a.wrap(write, a.safeDefaults))
	m.HandleFunc("POST /v1/connectors/tokens", a.wrap(write, a.connectorToken))
	m.HandleFunc("GET /v1/devices", a.wrap(read, a.listDevices))
	m.HandleFunc("POST /v1/devices/{id}/revoke", a.wrap(write, a.revokeDevice))
	m.HandleFunc("GET /v1/users", a.wrap(read, a.listUsers))
	m.HandleFunc("POST /v1/users/{id}/disable", a.wrap(write, a.disableUser))
	m.HandleFunc("GET /v1/audit", a.wrap(read, a.listAudit))
	m.HandleFunc("GET /v1/alerts", a.wrap(read, a.listAlerts))
	m.HandleFunc("PUT /v1/alert-settings", a.wrap(write, a.putAlertSettings))
	m.HandleFunc("GET /v1/alert-settings", a.wrap(read, a.getAlertSettings))
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiErr
	if !errors.As(err, &ae) {
		switch {
		case errors.Is(err, store.ErrNotFound):
			ae = fail(404, "not_found", "not found")
		case errors.Is(err, store.ErrConflict):
			ae = fail(412, "version_conflict", "the object changed; re-read and retry")
		case errors.Is(err, store.ErrExists):
			ae = fail(409, "exists", "already exists")
		default:
			ae = fail(400, "invalid", err.Error())
		}
	}
	writeJSON(w, ae.status, ae)
}

func (a *API) wrap(min store.Role, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeErr(w, fail(401, "unauthenticated", "bearer token required"))
			return
		}
		tenant, role, name, ok := a.Store.Auth(tok)
		if !ok {
			writeErr(w, fail(401, "unauthenticated", "invalid token"))
			return
		}
		if min == store.Admin && role != store.Admin {
			writeErr(w, fail(403, "forbidden", "admin role required"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		out, err := h(w, r, ctxInfo{tenant, name, role})
		if err != nil {
			writeErr(w, err)
			return
		}
		if out != nil {
			writeJSON(w, 200, out)
		}
	}
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fail(400, "bad_json", err.Error())
	}
	return nil
}

func (a *API) log(c ctxInfo, action, object string, before, after any) {
	if a.Audit != nil {
		a.Audit.Append(c.tenant, c.actor, action, object, before, after)
	}
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if a.BootstrapToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.BootstrapToken)) != 1 {
		writeErr(w, fail(401, "unauthenticated", "bootstrap token required"))
		return
	}
	var in struct{ ID, Name string }
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	if in.ID == "" || strings.ContainsAny(in.ID, "/ ") {
		writeErr(w, fail(400, "invalid", "tenant id must be non-empty with no slash or space"))
		return
	}
	admin, err := a.Store.CreateTenant(in.ID, in.Name)
	if err != nil {
		writeErr(w, err)
		return
	}
	a.log(ctxInfo{tenant: in.ID, actor: "bootstrap"}, "tenant.create", in.ID, nil, in)
	writeJSON(w, 201, map[string]string{"tenant": in.ID, "admin_token": admin})
}

func (a *API) putIDP(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in store.IDP
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Issuer == "" || in.ClientID == "" {
		return nil, fail(400, "invalid", "issuer and client_id are required")
	}
	if in.GroupClaim == "" {
		in.GroupClaim = "groups"
	}
	old, _ := a.Store.GetIDP(c.tenant)
	if err := a.Store.SetIDP(c.tenant, in); err != nil {
		return nil, err
	}
	a.log(c, "idp.update", "idp", old, in)
	return in, nil
}

func (a *API) listSegments(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.Store.Segments(c.tenant)
}

func (a *API) putSegment(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var g broker.Segment
	if err := decode(r, &g); err != nil {
		return nil, err
	}
	if id := r.PathValue("id"); id != "" {
		g.ID = id
	}
	if g.ID == "" || g.Group == "" || len(g.Targets) == 0 {
		return nil, fail(400, "invalid", "id, group and at least one target are required")
	}
	for _, t := range g.Targets {
		if t.Host == "" || len(t.Ports) == 0 {
			return nil, fail(400, "invalid", "each target needs a host and ports")
		}
		for _, p := range t.Ports {
			if p <= 0 || p > 65535 {
				return nil, fail(400, "invalid", "port out of range")
			}
		}
	}
	if g.Class != "" && g.Class != "standard" && g.Class != "admin" {
		return nil, fail(400, "invalid", "class must be standard or admin")
	}
	if err := a.Store.PutSegment(c.tenant, g); err != nil {
		return nil, err
	}
	a.log(c, "segment.put", g.ID, nil, g)
	return g, nil
}

func (a *API) deleteSegment(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	if err := a.Store.DeleteSegment(c.tenant, id); err != nil {
		return nil, err
	}
	a.log(c, "segment.delete", id, nil, nil)
	return map[string]string{"deleted": id}, nil
}

func kindOf(r *http.Request) (policy.Kind, error) {
	k := policy.Kind(r.PathValue("kind"))
	if k != policy.Private && k != policy.Web {
		return "", fail(404, "not_found", "unknown policy kind")
	}
	return k, nil
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	d, err := a.Store.GetPolicy(c.tenant, k)
	if err != nil {
		return nil, err
	}
	w.Header().Set("ETag", strconv.Itoa(d.Version))
	return d.Policy, nil
}

func ifMatch(r *http.Request) (int, error) {
	h := strings.Trim(r.Header.Get("If-Match"), `" `)
	if h == "" {
		return 0, fail(428, "precondition_required", "If-Match header with the current version is required (use 0 for a new policy)")
	}
	n, err := strconv.Atoi(h)
	if err != nil {
		return 0, fail(400, "invalid", "If-Match must be an integer version")
	}
	return n, nil
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	im, err := ifMatch(r)
	if err != nil {
		return nil, err
	}
	var p policy.Policy
	if err := decode(r, &p); err != nil {
		return nil, err
	}
	var before any
	if d, err := a.Store.GetPolicy(c.tenant, k); err == nil {
		before = d.Policy
	}
	v, err := a.Store.PutPolicy(c.tenant, k, &p, im)
	if err != nil {
		return nil, err
	}
	w.Header().Set("ETag", strconv.Itoa(v))
	a.log(c, "policy.put", string(k), before, &p)
	return map[string]int{"version": v}, nil
}

type dryRunIn struct {
	Policy     *policy.Policy  `json:"policy"` // draft; if nil the stored policy is used
	Email      string          `json:"email"`
	Groups     []string        `json:"groups"`
	App        string          `json:"app"`
	Host       string          `json:"host"`
	Categories []string        `json:"categories"`
	Posture    *policy.Posture `json:"posture"`
	Now        *time.Time      `json:"now"`
}

func (a *API) dryRun(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	var in dryRunIn
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	p := in.Policy
	if p != nil {
		p.Kind = k
		if err := p.Compile(a.Store.SegmentIDs(c.tenant)); err != nil {
			return nil, err
		}
	} else if p = a.Store.Policy(c.tenant, k); p == nil {
		return nil, fail(404, "not_found", "no stored policy and no draft supplied")
	}
	now := time.Now()
	if in.Now != nil {
		now = *in.Now
	}
	d := p.Evaluate(policy.Request{Kind: k, App: in.App, Host: in.Host, Categories: in.Categories, Now: now,
		User:   policy.User{Email: in.Email, Groups: in.Groups},
		Device: policy.Device{Posture: in.Posture}})
	return d, nil // nothing is stored
}

func (a *API) safeDefaults(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	segs, err := a.Store.Segments(c.tenant)
	if err != nil {
		return nil, err
	}
	priv, web := SafeDefaults(segs)
	out := map[string]int{}
	for _, p := range []*policy.Policy{priv, web} {
		cur := 0
		if d, err := a.Store.GetPolicy(c.tenant, p.Kind); err == nil {
			cur = d.Version
		}
		v, err := a.Store.PutPolicy(c.tenant, p.Kind, p, cur)
		if err != nil {
			return nil, err
		}
		out[string(p.Kind)] = v
	}
	a.log(c, "policy.safe-defaults", "all", nil, out)
	return out, nil
}

func (a *API) connectorToken(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct{ Group string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Group == "" {
		return nil, fail(400, "invalid", "group is required")
	}
	tok := a.Tokens.Issue(c.tenant, in.Group)
	a.log(c, "connector.token", in.Group, nil, nil) // the token itself is never logged
	return map[string]any{"token": tok, "expires_in_seconds": 3600}, nil
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.Store.Devices(c.tenant)
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	d, err := a.Store.RevokeDevice(c.tenant, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if a.OnRevokeDevice != nil {
		a.OnRevokeDevice(c.tenant, d)
	}
	a.log(c, "device.revoke", d.ID, nil, nil)
	return d, nil
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.Store.Users(c.tenant)
}

func (a *API) disableUser(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	if err := a.Store.SetUserDisabled(c.tenant, id, true); err != nil {
		return nil, err
	}
	if a.OnDisableUser != nil {
		a.OnDisableUser(c.tenant, id)
	}
	a.log(c, "user.disable", id, nil, nil)
	return map[string]string{"disabled": id}, nil
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.AuditPath == "" {
		return []audit.Event{}, nil
	}
	ev, err := audit.ReadAll(a.AuditPath, c.tenant) // tenant from the token only
	if ev == nil {
		ev = []audit.Event{}
	}
	after, limit := cursor(r)
	out := []audit.Event{}
	for _, e := range ev {
		if e.Seq > after {
			out = append(out, e)
			if len(out) == limit {
				w.Header().Set("X-Next-Cursor", strconv.Itoa(e.Seq))
				break
			}
		}
	}
	return out, err
}

// SafeDefaults builds the shipped policy pack (DESIGN.md D2.4).
func SafeDefaults(segs []broker.Segment) (private, web *policy.Policy) {
	tr := true
	posture := &policy.PostureMatch{DiskEncrypted: &tr, FirewallOn: &tr, MaxAgeSeconds: 3600}
	private = &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny}
	var std, adm []string
	for _, s := range segs {
		switch s.Class {
		case "admin":
			adm = append(adm, s.ID)
		default:
			std = append(std, s.ID)
		}
	}
	if len(std) > 0 {
		private.Rules = append(private.Rules, policy.Rule{ID: "sd-staff", Priority: 10, Action: policy.Allow,
			Reason: "All staff reach standard apps from healthy devices",
			Match:  policy.Match{Groups: []string{"all-staff"}, Apps: std, Posture: posture}})
	}
	if len(adm) > 0 {
		private.Rules = append(private.Rules, policy.Rule{ID: "sd-admins", Priority: 20, Action: policy.Allow,
			Reason: "Admins reach admin apps from healthy devices",
			Match:  policy.Match{Groups: []string{"admins"}, Apps: adm, Posture: posture}})
	}
	web = &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Rules: []policy.Rule{
		{ID: "sd-bad", Priority: 10, Action: policy.Deny, Reason: "Known-bad categories",
			Match: policy.Match{Categories: []string{"malware", "phishing", "command-and-control"}}},
		{ID: "sd-warn", Priority: 20, Action: policy.Warn, Reason: "Risky categories",
			Match: policy.Match{Categories: []string{"newly-registered", "file-sharing-unsanctioned"}}},
	}}
	return
}

// enToken issues a one-time enforcement-node enrolment token. Platform-level:
// guarded by the bootstrap token, not a tenant admin token.
func (a *API) enToken(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if a.BootstrapToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.BootstrapToken)) != 1 {
		writeErr(w, fail(401, "unauthenticated", "bootstrap token required"))
		return
	}
	var in struct {
		Names []string `json:"names"`
	}
	if err := decode(r, &in); err != nil || len(in.Names) == 0 {
		writeErr(w, fail(400, "invalid", "names (DNS names or IPs) are required"))
		return
	}
	t := a.Tokens.Issue("", ENTokenPrefix+strings.Join(in.Names, ","))
	writeJSON(w, 200, map[string]any{"token": t, "expires_in_seconds": 3600})
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Alerts == nil {
		return []alerts.Alert{}, nil
	}
	all := a.Alerts.List(c.tenant, r.URL.Query().Get("open") == "1") // newest first, ids descending
	after, limit := cursor(r)
	out := []alerts.Alert{}
	for _, al := range all {
		if after == 0 || al.ID < after {
			out = append(out, al)
			if len(out) == limit {
				w.Header().Set("X-Next-Cursor", strconv.Itoa(al.ID))
				break
			}
		}
	}
	return out, nil
}

func (a *API) putAlertSettings(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Emails []string `json:"emails"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	for _, e := range in.Emails {
		if !strings.Contains(e, "@") || strings.ContainsAny(e, " \r\n<>,") || len(e) > 254 {
			return nil, fail(400, "invalid", "bad email address")
		}
	}
	if len(in.Emails) > 20 {
		return nil, fail(400, "invalid", "at most 20 recipients")
	}
	old := a.Store.AlertEmails(c.tenant)
	if err := a.Store.SetAlertEmails(c.tenant, in.Emails); err != nil {
		return nil, err
	}
	a.log(c, "alert-settings.update", "alerts", old, in.Emails)
	return in, nil
}

func (a *API) getAlertSettings(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	e := a.Store.AlertEmails(c.tenant)
	if e == nil {
		e = []string{}
	}
	return map[string]any{"emails": e}, nil
}

// cursor reads ?after=<id>&limit=<n>. limit defaults to 100 and is capped at 500.
// The next page is requested with after=<value of the X-Next-Cursor header>.
func cursor(r *http.Request) (after, limit int) {
	after, _ = strconv.Atoi(r.URL.Query().Get("after"))
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	return
}
