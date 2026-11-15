// Package cp is the control-plane admin API (DESIGN.md D5.1).
package cp

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/larytet/zscaler/internal/dlp"
	"github.com/larytet/zscaler/internal/exemptions"
	"github.com/larytet/zscaler/internal/policydiff"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/advice"
	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/captures"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/digest"
	"github.com/larytet/zscaler/internal/evidence"
	"github.com/larytet/zscaler/internal/incidents"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/risk"
	"github.com/larytet/zscaler/internal/siem"
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
	Captures  *captures.Store
	routes    []routeInfo    // every route registered, for the API description (openapi.go)
	SIEM      *siem.Streamer // streams decision records and audit events to each tenant's own log system
	// OnApprovalRequest is called when a new access request is created.
	OnApprovalRequest func(approvals.Request)
	OnRevokeDevice    func(tenant string, d store.Device)
	// What GET /v1/keys reports about the platform's own keys; the program that starts the control plane sets them.
	RootCACert    *x509.Certificate
	PolicyPub     *ecdsa.PublicKey
	AtRestSealed  bool // the CA key, signing key and store are encrypted with a master key
	OnDisableUser func(tenant, subject string)
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
	a.routes = nil
	m := http.NewServeMux()
	a.mountUI(m)
	a.plain(m, "GET /healthz", "", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	a.plain(m, "POST /v1/tenants", "bootstrapToken", a.createTenant)
	a.plain(m, "POST /v1/ens/tokens", "bootstrapToken", a.enToken)
	read, write := store.PermRead, store.PermWrite
	logs, audit, support, sensitive, admins := store.PermLogs, store.PermAudit, store.PermSupport, store.PermSensitive, store.PermAdmins
	a.route(m, "PUT /v1/idp", write, a.putIDP)
	a.route(m, "GET /v1/segments", read, a.listSegments)
	a.route(m, "POST /v1/segments", write, a.putSegment)
	a.route(m, "PUT /v1/segments/{id}", write, a.putSegment)
	a.route(m, "DELETE /v1/segments/{id}", write, a.deleteSegment)
	a.route(m, "GET /v1/policies/{kind}", read, a.getPolicy)
	a.route(m, "PUT /v1/policies/{kind}", write, a.putPolicy)
	a.route(m, "GET /v1/policies/{kind}/versions", read, a.policyVersions)
	a.route(m, "GET /v1/policies/{kind}/versions/{n}", read, a.policyVersion)
	a.route(m, "GET /v1/policies/{kind}/diff", read, a.policyDiff)
	a.route(m, "POST /v1/policies/{kind}/rollback", write, a.policyRollback)
	a.route(m, "POST /v1/policies/{kind}/dry-run", read, a.dryRun)
	a.route(m, "POST /v1/policies/{kind}/simulate", read, a.simulate)
	a.route(m, "POST /v1/policies/safe-defaults", write, a.safeDefaults)
	a.route(m, "POST /v1/connectors/tokens", write, a.connectorToken)
	a.route(m, "GET /v1/devices", read, a.listDevices)
	a.route(m, "POST /v1/devices/{id}/revoke", support, a.revokeDevice)
	a.route(m, "GET /v1/users", read, a.listUsers)
	a.route(m, "POST /v1/users/{id}/disable", write, a.disableUser)
	a.route(m, "POST /v1/users/{id}/offboard", write, a.offboard)
	a.route(m, "POST /v1/users/{id}/restrict", support, a.restrictUser)
	a.route(m, "POST /v1/users/{id}/unrestrict", support, a.unrestrictUser)
	a.route(m, "GET /v1/audit", audit, a.listAudit)
	a.route(m, "GET /v1/alerts", read, a.listAlerts)
	a.route(m, "GET /v1/decisions", logs, a.listDecisions)
	a.route(m, "GET /v1/decisions/history", logs, a.decisionHistory)
	a.route(m, "GET /v1/digest", read, a.getDigest)
	a.route(m, "GET /v1/risk", read, a.getRisk)
	a.route(m, "GET /v1/ai-agents/{name}/readonly-pack", read, a.readonlyPack)
	a.route(m, "GET /v1/ai-agents/{name}/lint", read, a.lintAIAgent)
	a.route(m, "GET /v1/shadow-ai", read, a.shadowAI)
	a.route(m, "PUT /v1/edm/{name}", sensitive, a.putEDM)
	a.route(m, "GET /v1/edm", sensitive, a.listEDM)
	a.route(m, "DELETE /v1/edm/{name}", sensitive, a.deleteEDM)
	a.route(m, "PUT /v1/secrets/{name}", sensitive, a.putSecret)
	a.route(m, "GET /v1/secrets", sensitive, a.listSecrets)
	a.route(m, "DELETE /v1/secrets/{name}", sensitive, a.deleteSecret)
	a.route(m, "GET /v1/captures", sensitive, a.listCaptures)
	a.route(m, "GET /v1/captures/{id}", sensitive, a.getCapture)
	a.route(m, "DELETE /v1/captures", sensitive, a.purgeCaptures)
	a.route(m, "GET /v1/incidents", logs, a.getIncidents)
	a.route(m, "GET /v1/health", read, a.getHealth)
	a.route(m, "POST /v1/ai-agents", write, a.createAIAgent)
	a.route(m, "GET /v1/ai-agents", read, a.listAIAgents)
	a.route(m, "DELETE /v1/ai-agents/{name}", write, a.removeAIAgent)
	a.route(m, "PUT /v1/inspection", write, a.putInspection)
	a.route(m, "GET /v1/inspection", read, a.getInspection)
	a.route(m, "GET /v1/inspection/ca.pem", read, a.getInspectionCA)
	a.route(m, "POST /v1/inspection/rotate", write, a.rotateInspection)
	a.route(m, "GET /v1/keys", audit, a.keyStatus)
	a.route(m, "POST /v1/me/rotate", read, a.rotateOwnToken)
	a.route(m, "GET /v1/approvals", read, a.listApprovals)
	a.route(m, "POST /v1/approvals/{id}/approve", support, a.approve)
	a.route(m, "POST /v1/approvals/{id}/deny", support, a.denyRequest)
	a.route(m, "POST /v1/approvals/{id}/end", support, a.endGrant)
	a.route(m, "GET /v1/suggestions", read, a.getSuggestions)
	a.route(m, "GET /v1/investigate", read, a.investigate)
	a.route(m, "GET /v1/evidence", audit, a.getEvidence)
	a.route(m, "PUT /v1/alert-settings", write, a.putAlertSettings)
	a.route(m, "GET /v1/alert-settings", read, a.getAlertSettings)
	a.route(m, "GET /v1/openapi.json", read, a.openAPI)
	a.mountSCIM(m)
	a.route(m, "GET /v1/scim", admins, a.getSCIM)
	a.route(m, "PUT /v1/scim", admins, a.putSCIM)
	a.route(m, "POST /v1/scim/token", admins, a.scimToken)
	a.route(m, "PUT /v1/privacy", sensitive, a.putPrivacy)
	a.route(m, "GET /v1/privacy", read, a.getPrivacy)
	a.route(m, "GET /v1/privacy/reveal", admins, a.revealUser)
	a.route(m, "GET /v1/privacy/subject", admins, a.exportSubject)
	a.route(m, "DELETE /v1/privacy/subject", admins, a.eraseSubject)
	a.route(m, "GET /v1/cloud-apps", read, a.listCloudApps)
	a.route(m, "PUT /v1/cloud-apps/{id}", write, a.putCloudApp)
	a.route(m, "DELETE /v1/cloud-apps/{id}", write, a.deleteCloudApp)
	a.route(m, "PUT /v1/failure-mode", write, a.putFailureMode)
	a.route(m, "GET /v1/failure-mode", read, a.getFailureMode)
	a.route(m, "PUT /v1/tenancy", write, a.putTenancy)
	a.route(m, "GET /v1/tenancy", read, a.getTenancy)
	a.route(m, "DELETE /v1/tenancy", write, a.deleteTenancy)
	a.route(m, "PUT /v1/siem", sensitive, a.putSIEM)
	a.route(m, "GET /v1/siem", sensitive, a.getSIEM)
	a.route(m, "DELETE /v1/siem", sensitive, a.deleteSIEM)
	a.route(m, "POST /v1/siem/test", sensitive, a.testSIEM)
	a.route(m, "POST /v1/support-access", admins, a.supportAccess)
	a.route(m, "POST /v1/admins", admins, a.createAdmin)
	a.route(m, "GET /v1/admins", admins, a.listAdmins)
	a.route(m, "POST /v1/admins/{name}/rotate", admins, a.rotateAdminToken)
	a.route(m, "GET /v1/me", read, a.me)
	a.route(m, "DELETE /v1/admins/{name}", admins, a.removeAdmin)
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

func (a *API) wrap(min store.Perm, h handler) http.HandlerFunc {
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
		if !role.Can(min) {
			writeErr(w, fail(403, "forbidden", fmt.Sprintf("the %s role cannot do this (it needs the %q permission)", role, min)))
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
		ev, err := a.Audit.Append(c.tenant, c.actor, action, object, before, after)
		if err == nil && a.SIEM != nil {
			if e, err := siem.NewEvent("audit", ev); err == nil {
				a.SIEM.Emit(c.tenant, e)
			}
		}
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
	v, err := a.Store.PutPolicyAs(c.tenant, k, &p, im, c.actor, "")
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
	var in struct {
		// Inspection turns TLS inspection on (with the managed exemptions) so the file and sharing rules can
		// see what is sent. It is off unless asked for: devices must trust the inspection CA first.
		Inspection bool `json:"inspection"`
		// BlockUploadsTo names more apps of the catalogue whose uploads and posts are refused.
		BlockUploadsTo []string `json:"block_uploads_to"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			return nil, err
		}
	}
	cat := a.Store.CloudCatalog(c.tenant)
	for _, id := range in.BlockUploadsTo {
		if !cat.Has(id) {
			return nil, fail(400, "invalid", "unknown app "+id+" (see GET /v1/cloud-apps)")
		}
	}
	priv, web := SafeDefaultsWith(segs, SafeDefaultsOpts{BlockUploadsTo: in.BlockUploadsTo})
	out := map[string]any{}
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
	warnings := []string{}
	if in.Inspection {
		ic, _ := a.Store.Inspection(c.tenant)
		if err := a.Store.SetInspection(c.tenant, true, ic.Exempt); err != nil {
			return nil, err
		}
		warnings = append(warnings, "TLS inspection is now on, with the managed exemptions (GET /v1/inspection). Devices must trust the inspection CA (GET /v1/inspection/ca.pem) or HTTPS sites will show certificate errors there.")
	} else if ic, _ := a.Store.Inspection(c.tenant); !ic.Enabled {
		warnings = append(warnings, "TLS inspection is off, so the rules about uploads, downloads and file kinds in the web policy match nothing yet. Turn it on with PUT /v1/inspection, or run this again with {\"inspection\": true}, once your devices trust the inspection CA.")
	}
	out["inspection"], out["warnings"] = in.Inspection, warnings
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

// SafeDefaultsOpts are the choices of the shipped policy pack.
type SafeDefaultsOpts struct {
	// BlockUploadsTo names more file-sharing apps whose uploads are refused, besides the anonymous
	// sharing services the pack always refuses (they must be in the app catalogue).
	BlockUploadsTo []string
}

// AnonymousSharing are the services the pack refuses uploads and posts to without being asked: places to
// drop a file or text for anyone, with no account of the organisation's.
var AnonymousSharing = []string{"wetransfer", "pastebin", "github-gist"}

// SafeDefaults builds the shipped policy pack (DESIGN.md D2.4) with its default choices.
func SafeDefaults(segs []broker.Segment) (private, web *policy.Policy) {
	return SafeDefaultsWith(segs, SafeDefaultsOpts{})
}

// SafeDefaultsWith builds the pack with the given choices. The file rules in the web policy need decrypted
// traffic to see what is being sent: without TLS inspection they match nothing and do no harm.
func SafeDefaultsWith(segs []broker.Segment, o SafeDefaultsOpts) (private, web *policy.Policy) {
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
		{ID: "sd-no-adhoc-sharing", Priority: 12, Action: policy.Deny, Reason: "Anonymous file and text sharing services are not allowed",
			Match: policy.Match{CloudApps: append(append([]string(nil), AnonymousSharing...), o.BlockUploadsTo...), CloudActions: []string{"upload", "post"}}},
		{ID: "sd-no-exe-upload", Priority: 13, Action: policy.Deny, Reason: "Programs may not be sent out",
			Match: policy.Match{UploadFileTypes: []string{"executable"}}},
		{ID: "sd-no-disguised-download", Priority: 14, Action: policy.Deny, Reason: "A program disguised as another kind of file",
			Match: policy.Match{DownloadFileTypes: []string{"disguised"}}},
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
	f := decisions.Filter{App: q.Get("app"), Action: q.Get("action"), Kind: q.Get("kind"), Ref: q.Get("ref")}
	var alt []string
	f.User, alt = a.userFilter(c.tenant, q.Get("user"))
	if len(alt) > 0 {
		f.User = alt[0] // the live view holds real names: look for the person the pseudonym belongs to
	}
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
	a.redactEntries(out, c.tenant)
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
		// Managed exemptions (ZIA-032): the built-in list of pinned applications is on unless turned off,
		// and the categories never decrypted default to banking and health.
		ManagedExemptions *bool     `json:"managed_exemptions"`
		ExemptCategories  *[]string `json:"exempt_categories"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.ExemptCategories != nil {
		if len(*in.ExemptCategories) > 20 {
			return nil, fail(400, "invalid", "at most 20 exempt categories")
		}
		for i, c := range *in.ExemptCategories {
			c = strings.ToLower(strings.TrimSpace(c))
			if c == "" || len(c) > 40 || strings.ContainsAny(c, " /:@*\r\n") {
				return nil, fail(400, "invalid", "a category is one lower-case word such as banking")
			}
			(*in.ExemptCategories)[i] = c
		}
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
	var off *bool
	if in.ManagedExemptions != nil {
		v := !*in.ManagedExemptions
		off = &v
	}
	if err := a.Store.SetInspectionManaged(c.tenant, off, in.ExemptCategories); err != nil {
		return nil, err
	}
	a.log(c, "inspection.update", "tls-inspection", nil, map[string]any{"enabled": in.Enabled, "exempt": len(in.Exempt)})
	cfg, _ := a.Store.Inspection(c.tenant)
	return inspectionView(cfg), nil
}

// inspectionView is what the admin sees of the inspection setting: the effective managed exemptions
// included, and what they cannot do.
func inspectionView(cfg store.InspectCfg) map[string]any {
	exempt := cfg.Exempt
	if exempt == nil {
		exempt = []string{}
	}
	v := map[string]any{"enabled": cfg.Enabled, "exempt": exempt,
		"managed_exemptions": !cfg.ManagedOff, "managed_domains": exemptions.Pinned,
		"exempt_categories": cfg.EffectiveExemptCategories(),
		"notes": []string{
			"Never decrypted: your own exempt list; when managed_exemptions is true, the built-in list of applications that break when intercepted (managed_domains, hand-made and not exhaustive); and sites in exempt_categories.",
			"A category exemption covers the sites that the enforcement node's category list puts in that category. This platform ships no banking or health list: without one, those categories exempt nothing.",
		}}
	if cfg.CACert != "" { // public facts only: which certificate devices must trust, and when it was replaced
		v["ca_fingerprint"] = store.Fingerprint(cfg.CACert)
		if !cfg.Rotated.IsZero() {
			v["rotated"] = cfg.Rotated.UTC().Format(time.RFC3339)
		}
	}
	return v
}

func (a *API) getInspection(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	cfg, err := a.Store.Inspection(c.tenant)
	if err != nil {
		return nil, err
	}
	return inspectionView(cfg), nil
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

func (a *API) getIncidents(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var es []decisions.Entry
	if a.Decisions != nil {
		es = a.Decisions.Since(c.tenant, time.Now().Add(-incidents.Window))
	}
	var al []alerts.Alert
	if a.Alerts != nil {
		al = a.Alerts.List(c.tenant, true)
	}
	out := incidents.Build(time.Now(), es, al, a.scores(c.tenant))
	if out == nil {
		out = []incidents.Incident{}
	}
	return out, nil
}

// Captures hold decrypted content, so even reading the list needs the admin role (not viewer),
// and reading one is written to the audit log.
func (a *API) listCaptures(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Captures == nil {
		return []captures.Summary{}, nil
	}
	return a.Captures.List(c.tenant), nil
}

func (a *API) getCapture(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || a.Captures == nil {
		return nil, fail(404, "not_found", "not found")
	}
	e, ok := a.Captures.Get(c.tenant, id) // tenant from the token only
	if !ok {
		return nil, fail(404, "not_found", "not found or expired")
	}
	a.log(c, "capture.read", strconv.Itoa(id), nil, map[string]string{"user": e.User, "host": e.Capture.Host})
	return e, nil
}

func (a *API) purgeCaptures(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.Captures == nil {
		return map[string]int{"purged": 0}, nil
	}
	n := a.Captures.Purge(c.tenant)
	a.log(c, "capture.purge", "all", nil, map[string]int{"count": n})
	return map[string]int{"purged": n}, nil
}

var secretName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
var headerToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

// headers a secret may not be placed in: they change how the request is framed or routed.
var forbiddenSecretHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true, "proxy-authorization": true, "proxy-connection": true, "keep-alive": true}

// putSecret stores a credential for the proxy to inject (AGS-001). The value is write-only: no
// endpoint returns it, and it is not written to the audit log.
func (a *API) putSecret(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name := r.PathValue("name")
	var in struct {
		Host   string `json:"host"`
		Header string `json:"header"`
		Value  string `json:"value"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Host), "."))
	switch {
	case !secretName.MatchString(name):
		return nil, fail(400, "invalid", "secret name: 1 to 40 characters, lower-case letters, digits, dash and underscore")
	case in.Host == "" || strings.ContainsAny(in.Host, "/:@ *\r\n") || strings.HasPrefix(in.Host, "."):
		return nil, fail(400, "invalid", "host must be a plain domain or address such as api.example.com (subdomains are covered)")
	case !headerToken.MatchString(in.Header) || forbiddenSecretHeaders[strings.ToLower(in.Header)]:
		return nil, fail(400, "invalid", "header must be a plain header name such as Authorization or X-Api-Key, not one that changes how the request is sent")
	case in.Value == "" || len(in.Value) > 4096 || strings.ContainsAny(in.Value, "\r\n\x00"):
		return nil, fail(400, "invalid", "value must be 1 to 4096 characters on one line")
	}
	if old, _ := a.Store.Secrets(c.tenant); len(old) >= 50 {
		for _, o := range old {
			if o.Name == name {
				old = nil
			}
		}
		if old != nil {
			return nil, fail(400, "invalid", "at most 50 secrets")
		}
	}
	if err := a.Store.PutSecret(c.tenant, store.Secret{Name: name, Host: in.Host, Header: in.Header, Value: in.Value}); err != nil {
		return nil, err
	}
	a.log(c, "secret.put", name, nil, map[string]string{"host": in.Host, "header": in.Header}) // never the value
	return map[string]string{"name": name, "host": in.Host, "header": in.Header}, nil
}

func (a *API) listSecrets(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	out, err := a.Store.Secrets(c.tenant)
	if err != nil {
		return nil, err
	}
	return out, nil // Value is blank in this list
}

func (a *API) deleteSecret(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name := r.PathValue("name")
	if err := a.Store.DeleteSecret(c.tenant, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fail(404, "not_found", "not found")
		}
		return nil, fail(409, "in_use", err.Error())
	}
	a.log(c, "secret.delete", name, nil, nil)
	return map[string]string{"deleted": name}, nil
}

// putEDM replaces an exact-data-match set (DATA-006). Values are hashed on arrival and not kept; they
// are not written to the audit log either (only the counts).
func (a *API) putEDM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name := r.PathValue("name")
	var in struct {
		Values    []string `json:"values"`
		Documents []string `json:"documents"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len(in.Documents) > 0 {
		if len(in.Values) > 0 {
			return nil, fail(400, "invalid", "send either values or documents, not both")
		}
		runs, skipped, err := a.Store.PutEDMDocuments(c.tenant, name, in.Documents)
		if err != nil {
			return nil, fail(400, "invalid", err.Error())
		}
		a.log(c, "edm.put", name, nil, map[string]any{"kind": "documents", "runs": runs, "skipped": skipped})
		return map[string]any{"name": name, "runs": runs, "skipped": skipped,
			"note": fmt.Sprintf("only hashes of runs of %d words are kept; a rule with dlp edm:%s blocks text that repeats about %d words in a row from any document", dlp.DocWords, name, dlp.DocWords+dlp.DocMinRuns-1)}, nil
	}
	if len(in.Values) > dlp.EDMMaxValues {
		return nil, fail(400, "invalid", fmt.Sprintf("at most %d values per data set", dlp.EDMMaxValues))
	}
	kept, skipped, err := a.Store.PutEDM(c.tenant, name, in.Values)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	a.log(c, "edm.put", name, nil, map[string]int{"kept": kept, "skipped": skipped})
	return map[string]any{"name": name, "kept": kept, "skipped": skipped,
		"note": "values are stored as salted hashes only; a guessable value (a phone number, a short ID) can be guessed by whoever holds the hashes"}, nil
}

func (a *API) listEDM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.Store.EDMSets(c.tenant)
}

func (a *API) deleteEDM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name := r.PathValue("name")
	if err := a.Store.DeleteEDM(c.tenant, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fail(404, "not_found", "not found")
		}
		return nil, fail(409, "in_use", err.Error())
	}
	a.log(c, "edm.delete", name, nil, nil)
	return map[string]string{"deleted": name}, nil
}

func (a *API) policyVersions(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	return a.Store.PolicyVersions(c.tenant, k)
}

func versionNumber(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fail(400, "invalid", "version must be a positive integer")
	}
	return n, nil
}

func (a *API) policyVersion(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	n, err := versionNumber(r.PathValue("n"))
	if err != nil {
		return nil, err
	}
	v, err := a.Store.PolicyVersion(c.tenant, k, n)
	if err != nil {
		return nil, fail(404, "not_found", "that version is not kept (the last 50 are)")
	}
	return v, nil
}

// policyDiff says what changed between two saved versions (to defaults to the current one).
func (a *API) policyDiff(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	from, err := versionNumber(r.URL.Query().Get("from"))
	if err != nil {
		return nil, err
	}
	var to int
	if v := r.URL.Query().Get("to"); v != "" {
		if to, err = versionNumber(v); err != nil {
			return nil, err
		}
	} else if d, err := a.Store.GetPolicy(c.tenant, k); err == nil {
		to = d.Version
	} else {
		return nil, fail(404, "not_found", "no such policy")
	}
	fv, err := a.Store.PolicyVersion(c.tenant, k, from)
	if err != nil {
		return nil, fail(404, "not_found", fmt.Sprintf("version %d is not kept", from))
	}
	tv, err := a.Store.PolicyVersion(c.tenant, k, to)
	if err != nil {
		return nil, fail(404, "not_found", fmt.Sprintf("version %d is not kept", to))
	}
	res := policydiff.Diff(fv.Policy, tv.Policy)
	return map[string]any{"from": from, "to": to, "same": res.Same, "changes": res.Changes}, nil
}

// policyRollback saves an earlier version again as a new version (the history is never rewritten).
// If-Match must name the current version, as for any save.
func (a *API) policyRollback(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	k, err := kindOf(r)
	if err != nil {
		return nil, err
	}
	im, err := ifMatch(r)
	if err != nil {
		return nil, err
	}
	var in struct {
		Version int `json:"version"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	old, err := a.Store.PolicyVersion(c.tenant, k, in.Version)
	if err != nil || old.Policy == nil {
		return nil, fail(404, "not_found", "that version is not kept (the last 50 are)")
	}
	var before any
	if d, err := a.Store.GetPolicy(c.tenant, k); err == nil {
		before = d.Policy
	}
	p := old.Policy
	v, err := a.Store.PutPolicyAs(c.tenant, k, p, im, c.actor, fmt.Sprintf("rollback to version %d", in.Version))
	if err != nil {
		return nil, err
	}
	w.Header().Set("ETag", strconv.Itoa(v))
	a.log(c, "policy.rollback", string(k), before, map[string]int{"restored": in.Version, "version": v})
	return map[string]int{"version": v, "restored": in.Version}, nil
}
