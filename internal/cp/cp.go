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

	"github.com/larytet/zscaler/internal/advice"
	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/digest"
	"github.com/larytet/zscaler/internal/evidence"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/risk"
	"github.com/larytet/zscaler/internal/simulate"
	"github.com/larytet/zscaler/internal/store"
)

type API struct {
	Store          *store.Store
	Audit          *audit.Log
	AuditPath      string
	Tokens         *pki.Tokens
	BootstrapToken string
	// Hooks let enforcement nodes react immediately to revocations.
	Alerts    *alerts.Engine
	Decisions *decisions.Store
	Approvals *approvals.Store
	Health    *devhealth.Store
	// OnApprovalRequest is called when a new access request is created.
	OnApprovalRequest func(approvals.Request)
	OnRevokeDevice    func(tenant string, d store.Device)
	OnDisableUser     func(tenant, subject string)
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
	a.mountUI(m)
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
	m.HandleFunc("POST /v1/policies/{kind}/simulate", a.wrap(read, a.simulate))
	m.HandleFunc("POST /v1/policies/safe-defaults", a.wrap(write, a.safeDefaults))
	m.HandleFunc("POST /v1/connectors/tokens", a.wrap(write, a.connectorToken))
	m.HandleFunc("GET /v1/devices", a.wrap(read, a.listDevices))
	m.HandleFunc("POST /v1/devices/{id}/revoke", a.wrap(write, a.revokeDevice))
	m.HandleFunc("GET /v1/users", a.wrap(read, a.listUsers))
	m.HandleFunc("POST /v1/users/{id}/disable", a.wrap(write, a.disableUser))
	m.HandleFunc("POST /v1/users/{id}/restrict", a.wrap(write, a.restrictUser))
	m.HandleFunc("POST /v1/users/{id}/unrestrict", a.wrap(write, a.unrestrictUser))
	m.HandleFunc("GET /v1/audit", a.wrap(read, a.listAudit))
	m.HandleFunc("GET /v1/alerts", a.wrap(read, a.listAlerts))
	m.HandleFunc("GET /v1/decisions", a.wrap(read, a.listDecisions))
	m.HandleFunc("GET /v1/digest", a.wrap(read, a.getDigest))
	m.HandleFunc("GET /v1/risk", a.wrap(read, a.getRisk))
	m.HandleFunc("GET /v1/health", a.wrap(read, a.getHealth))
	m.HandleFunc("POST /v1/ai-agents", a.wrap(write, a.createAIAgent))
	m.HandleFunc("GET /v1/ai-agents", a.wrap(read, a.listAIAgents))
	m.HandleFunc("DELETE /v1/ai-agents/{name}", a.wrap(write, a.removeAIAgent))
	m.HandleFunc("PUT /v1/inspection", a.wrap(write, a.putInspection))
	m.HandleFunc("GET /v1/inspection", a.wrap(read, a.getInspection))
	m.HandleFunc("GET /v1/inspection/ca.pem", a.wrap(read, a.getInspectionCA))
	m.HandleFunc("GET /v1/approvals", a.wrap(read, a.listApprovals))
	m.HandleFunc("POST /v1/approvals/{id}/approve", a.wrap(write, a.approve))
	m.HandleFunc("POST /v1/approvals/{id}/deny", a.wrap(write, a.denyRequest))
	m.HandleFunc("POST /v1/approvals/{id}/end", a.wrap(write, a.endGrant))
	m.HandleFunc("GET /v1/suggestions", a.wrap(read, a.getSuggestions))
	m.HandleFunc("GET /v1/investigate", a.wrap(read, a.investigate))
	m.HandleFunc("GET /v1/evidence", a.wrap(read, a.getEvidence))
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
	if g.Class != "" && g.Class != "standard" && g.Class != "admin" && g.Class != "sensitive" {
		return nil, fail(400, "invalid", "class must be standard, admin or sensitive")
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
	private.Rules = append(private.Rules, policy.Rule{ID: "sd-restricted", Priority: 1, Action: policy.Deny,
		Reason: "Restricted users are blocked first", Match: policy.Match{Groups: []string{policy.RestrictedGroup}}})
	var std, adm, sens []string
	for _, s := range segs {
		switch s.Class {
		case "sensitive":
			sens = append(sens, s.ID)
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
	if len(sens) > 0 {
		// sensitive apps are reachable only from the workspace browser (WB-008)
		private.Rules = append(private.Rules, policy.Rule{ID: "sd-sensitive", Priority: 15, Action: policy.Isolate,
			Reason: "Sensitive apps are reachable only from the workspace browser",
			Match:  policy.Match{Groups: []string{"all-staff"}, Apps: sens}})
	}
	if len(adm) > 0 {
		private.Rules = append(private.Rules, policy.Rule{ID: "sd-admins", Priority: 20, Action: policy.Allow,
			Reason: "Admins reach admin apps from healthy devices",
			Match:  policy.Match{Groups: []string{"admins"}, Apps: adm, Posture: posture}})
	}
	web = &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Rules: []policy.Rule{
		{ID: "sd-restricted", Priority: 1, Action: policy.Deny, Reason: "Restricted users are blocked first",
			Match: policy.Match{Groups: []string{policy.RestrictedGroup}}},
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

func (a *API) listDecisions(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Decisions == nil {
		return []decisions.Entry{}, nil
	}
	q := r.URL.Query()
	f := decisions.Filter{User: q.Get("user"), App: q.Get("app"), Action: q.Get("action"), Kind: q.Get("kind")}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fail(400, "invalid", "since must be an RFC 3339 time")
		}
		f.Since = t
	}
	f.After, f.Limit = cursor(r)
	out, next := a.Decisions.Query(c.tenant, f) // tenant from the token only
	if next != 0 {
		w.Header().Set("X-Next-Cursor", strconv.Itoa(next))
	}
	if out == nil {
		out = []decisions.Entry{}
	}
	return out, nil
}

// BuildDigest summarises the last `days` days for a tenant.
func (a *API) BuildDigest(tenant string, days int) digest.Digest {
	to := time.Now()
	from := to.Add(-time.Duration(days) * 24 * time.Hour)
	var es []decisions.Entry
	if a.Decisions != nil {
		es = a.Decisions.Since(tenant, from)
	}
	var al []alerts.Alert
	if a.Alerts != nil {
		al = a.Alerts.List(tenant, true)
	}
	return digest.Build(tenant, from, to, es, al)
}

func (a *API) getDigest(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 90 {
		days = 7
	}
	d := a.BuildDigest(c.tenant, days)
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, d.Text())
		return nil, nil
	}
	return d, nil
}

func (a *API) getEvidence(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	in := evidence.Inputs{Now: time.Now()}
	segs, _ := a.Store.Segments(c.tenant)
	in.Segments = len(segs)
	in.Private, in.Web = a.Store.Policy(c.tenant, policy.Private), a.Store.Policy(c.tenant, policy.Web)
	devs, _ := a.Store.Devices(c.tenant)
	in.Devices = len(devs)
	for _, d := range devs {
		if d.Revoked {
			in.RevokedDevices++
		}
	}
	users, _ := a.Store.Users(c.tenant)
	in.Users = len(users)
	for _, u := range users {
		if u.Disabled {
			in.DisabledUsers++
		}
	}
	if idp, err := a.Store.GetIDP(c.tenant); err == nil {
		in.IDPConfigured = idp.Issuer != ""
	}
	in.Admins, in.Viewers = a.Store.AdminCounts(c.tenant)
	if a.Alerts != nil {
		for _, al := range a.Alerts.List(c.tenant, true) {
			if al.Kind == "posture-failed" {
				in.OpenPostureFail++
			}
		}
	}
	if a.Decisions != nil {
		in.Decisions30d = len(a.Decisions.Since(c.tenant, time.Now().Add(-30*24*time.Hour)))
	}
	if a.AuditPath != "" {
		if _, err := audit.Verify(a.AuditPath); err != nil {
			in.AuditErr = err // the whole chain is checked; a break is reported to every tenant
		} else {
			ev, _ := audit.ReadAll(a.AuditPath, c.tenant)
			in.AuditRecords = len(ev)
		}
	}
	rep := evidence.Build(in)
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, rep.Text())
		return nil, nil
	}
	return rep, nil
}

// simulate replays recent private-access decisions against a draft policy. Nothing is stored.
func (a *API) simulate(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	if k != policy.Private {
		return nil, fail(400, "unsupported", "simulation covers private-access policies only")
	}
	var in struct {
		Policy *policy.Policy `json:"policy"`
		Days   int            `json:"days"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Policy == nil {
		return nil, fail(400, "invalid", "a draft policy is required")
	}
	in.Policy.Kind = k
	if err := in.Policy.Compile(a.Store.SegmentIDs(c.tenant)); err != nil {
		return nil, err
	}
	if in.Days <= 0 || in.Days > 90 {
		in.Days = 7
	}
	if a.Decisions == nil {
		return simulate.Run(in.Policy, nil), nil
	}
	return simulate.Run(in.Policy, a.Decisions.Since(c.tenant, time.Now().Add(-time.Duration(in.Days)*24*time.Hour))), nil
}

func (a *API) recent(r *http.Request, tenant string) []decisions.Entry {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 90 {
		days = 7
	}
	if a.Decisions == nil {
		return nil
	}
	return a.Decisions.Since(tenant, time.Now().Add(-time.Duration(days)*24*time.Hour))
}

func (a *API) getSuggestions(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	out, dev := advice.Suggest(a.recent(r, c.tenant))
	if out == nil {
		out = []advice.Suggestion{}
	}
	if dev == nil {
		dev = []string{}
	}
	return map[string]any{"rule_suggestions": out, "device_problems": dev}, nil
}

func (a *API) investigate(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	user := r.URL.Query().Get("user")
	if user == "" {
		return nil, fail(400, "invalid", "user is required")
	}
	return advice.Investigate(user, a.recent(r, c.tenant)), nil
}

func (a *API) restrictUser(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	var in struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	if len(in.Reason) > 200 {
		return nil, fail(400, "invalid", "reason is limited to 200 characters")
	}
	if err := a.Store.SetRestricted(c.tenant, id, true, in.Reason); err != nil {
		return nil, err
	}
	a.log(c, "user.restrict", id, nil, in.Reason)
	return map[string]any{"restricted": id}, nil
}

func (a *API) unrestrictUser(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	if err := a.Store.SetRestricted(c.tenant, id, false, ""); err != nil {
		return nil, err
	}
	a.log(c, "user.unrestrict", id, nil, nil)
	return map[string]any{"unrestricted": id}, nil
}

func (a *API) scores(tenant string) []risk.Score {
	var es []decisions.Entry
	if a.Decisions != nil {
		es = a.Decisions.Since(tenant, time.Now().Add(-24*time.Hour))
	}
	var al []alerts.Alert
	if a.Alerts != nil {
		al = a.Alerts.List(tenant, true)
	}
	return risk.Compute(time.Now(), es, al)
}

// RefreshRisk recomputes every tenant's scores and hands them to the store, from
// where they travel to enforcement nodes with the next state snapshot.
func (a *API) RefreshRisk() {
	for _, t := range a.Store.Tenants() {
		m := map[string]int{}
		for _, s := range a.scores(t) {
			m[s.User] = s.Score
		}
		a.Store.SetRisk(t, m)
	}
}

func (a *API) getRisk(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	out := a.scores(c.tenant)
	if out == nil {
		out = []risk.Score{}
	}
	return out, nil
}

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Approvals == nil {
		return []approvals.Request{}, nil
	}
	return a.Approvals.List(c.tenant, approvals.State(r.URL.Query().Get("state"))), nil
}

func (a *API) approvalID(r *http.Request) (int, error) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || a.Approvals == nil {
		return 0, fail(404, "not_found", "not found")
	}
	return id, nil
}

// approve grants access for 1 to 480 minutes (default 60).
func (a *API) approve(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id, err := a.approvalID(r)
	if err != nil {
		return nil, err
	}
	var in struct {
		Minutes int `json:"minutes"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	if in.Minutes == 0 {
		in.Minutes = 60
	}
	if in.Minutes < 1 || in.Minutes > 480 {
		return nil, fail(400, "invalid", "minutes must be between 1 and 480")
	}
	now := time.Now()
	until := now.Add(time.Duration(in.Minutes) * time.Minute)
	req, err := a.Approvals.Decide(c.tenant, id, approvals.Approved, c.actor, until, now)
	if errors.Is(err, approvals.ErrNotFound) {
		return nil, fail(404, "not_found", "not found")
	}
	if errors.Is(err, approvals.ErrDecided) {
		return nil, fail(409, "already_decided", "this request was already decided")
	}
	if err != nil {
		return nil, err
	}
	if err := a.Store.PutGrant(c.tenant, store.Grant{User: req.User, App: req.App, Expires: until, By: c.actor}); err != nil {
		return nil, err
	}
	a.log(c, "access.approve", req.User+"@"+req.App, nil, map[string]any{"minutes": in.Minutes})
	return req, nil
}

func (a *API) denyRequest(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id, err := a.approvalID(r)
	if err != nil {
		return nil, err
	}
	req, err := a.Approvals.Decide(c.tenant, id, approvals.Denied, c.actor, time.Time{}, time.Now())
	if errors.Is(err, approvals.ErrNotFound) {
		return nil, fail(404, "not_found", "not found")
	}
	if errors.Is(err, approvals.ErrDecided) {
		return nil, fail(409, "already_decided", "this request was already decided")
	}
	if err != nil {
		return nil, err
	}
	a.log(c, "access.deny", req.User+"@"+req.App, nil, nil)
	return req, nil
}

// endGrant ends an approved grant early. Live sessions end at the next state sync.
func (a *API) endGrant(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id, err := a.approvalID(r)
	if err != nil {
		return nil, err
	}
	var found *approvals.Request
	for _, q := range a.Approvals.List(c.tenant, approvals.Approved) {
		if q.ID == id {
			q := q
			found = &q
		}
	}
	if found == nil {
		return nil, fail(404, "not_found", "no approved request with that id")
	}
	if err := a.Store.RevokeGrant(c.tenant, found.User, found.App); err != nil {
		return nil, err
	}
	a.log(c, "access.end", found.User+"@"+found.App, nil, nil)
	return map[string]any{"ended": id}, nil
}

func (a *API) putInspection(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Enabled bool     `json:"enabled"`
		Exempt  []string `json:"exempt"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.Exempt) > 500 {
		return nil, fail(400, "invalid", "at most 500 exempt domains")
	}
	for i, d := range in.Exempt {
		raw := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".") // validate what was typed, not a normalised guess
		if raw == "" || strings.ContainsAny(raw, "/:@ *\r\n") || strings.HasPrefix(raw, ".") {
			return nil, fail(400, "invalid", "exempt entries are plain domains such as example.com (subdomains are included)")
		}
		in.Exempt[i] = raw
	}
	if err := a.Store.SetInspection(c.tenant, in.Enabled, in.Exempt); err != nil {
		return nil, err
	}
	a.log(c, "inspection.update", "tls-inspection", nil, map[string]any{"enabled": in.Enabled, "exempt": len(in.Exempt)})
	cfg, _ := a.Store.Inspection(c.tenant)
	return cfg, nil
}

func (a *API) getInspection(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	cfg, err := a.Store.Inspection(c.tenant)
	if err != nil {
		return nil, err
	}
	cfg.CACert = "" // fetch it from /v1/inspection/ca.pem
	if cfg.Exempt == nil {
		cfg.Exempt = []string{}
	}
	return cfg, nil
}

// getInspectionCA serves the tenant's intercept CA certificate (never its key) so it
// can be installed on devices. Without it, browsers show certificate errors on inspected sites.
func (a *API) getInspectionCA(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	cfg, err := a.Store.Inspection(c.tenant)
	if err != nil {
		return nil, err
	}
	if cfg.CACert == "" {
		return nil, fail(404, "not_found", "inspection has never been enabled for this tenant")
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="inspection-ca.pem"`)
	io.WriteString(w, cfg.CACert)
	return nil, nil
}

func (a *API) getHealth(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Health == nil {
		return []devhealth.Device{}, nil
	}
	return a.Health.List(c.tenant, time.Now()), nil
}
