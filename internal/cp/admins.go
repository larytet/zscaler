package cp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/store"
)

var adminName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)

// createAdmin makes another administrator and returns their token, once (ADM-002). Only an owner may.
func (a *API) createAdmin(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Name string     `json:"name"`
		Role store.Role `json:"role"`
		// ExpiresInHours makes the account temporary (1 to 720 hours); 0 means it does not expire.
		ExpiresInHours int    `json:"expires_in_hours"`
		Note           string `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !adminName.MatchString(in.Name) {
		return nil, fail(400, "invalid", "name: 1 to 40 characters, lower-case letters, digits, dot, dash and underscore")
	}
	if !store.ValidRole(in.Role) {
		return nil, fail(400, "invalid", "role must be one of owner, admin, helpdesk, auditor, viewer")
	}
	if in.ExpiresInHours < 0 || in.ExpiresInHours > 720 {
		return nil, fail(400, "invalid", "expires_in_hours must be 0 (never) or 1 to 720")
	}
	if len(in.Note) > 200 || strings.ContainsAny(in.Note, "\r\n\x00") {
		return nil, fail(400, "invalid", "note: one line, at most 200 characters")
	}
	return a.makeAdmin(c, in.Name, in.Role, in.ExpiresInHours, in.Note, false)
}

// makeAdmin creates the account and answers with its token, once. It is used for administrators and for
// the vendor's time-boxed support access.
func (a *API) makeAdmin(c ctxInfo, name string, role store.Role, hours int, note string, support bool) (any, error) {
	var o store.AdminOpts
	if hours > 0 {
		o.Expires = a.Store.Time().Add(time.Duration(hours) * time.Hour)
	}
	o.Note, o.Support = note, support
	tok, err := a.Store.AddAdminOpts(c.tenant, name, role, o)
	if errors.Is(err, store.ErrExists) {
		return nil, fail(409, "exists", "an administrator with that name exists")
	}
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	after := map[string]any{"role": string(role), "support": support, "note": note}
	out := map[string]any{"name": name, "role": string(role), "token": tok, "support": support, "note": note}
	if hours > 0 {
		after["expires"], out["expires"] = o.Expires.UTC(), o.Expires.UTC()
	}
	a.log(c, "admin.create", name, nil, after) // never the token
	return out, nil
}

// supportAccess gives the vendor's support staff time-boxed access (NFR-023): a temporary account with a
// limited role, a reason on record, an end time, and a name that shows in the audit log and the list of
// administrators for as long as it exists and afterwards until it is purged.
func (a *API) supportAccess(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Hours  int        `json:"hours"`
		Role   store.Role `json:"role"`
		Reason string     `json:"reason"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Hours == 0 {
		in.Hours = 4
	}
	if in.Hours < 1 || in.Hours > 72 {
		return nil, fail(400, "invalid", "hours must be 1 to 72")
	}
	if in.Role == "" {
		in.Role = store.Auditor
	}
	switch in.Role {
	case store.Auditor, store.Helpdesk, store.Viewer, store.Admin:
	default:
		return nil, fail(400, "invalid", "role must be auditor, helpdesk, viewer or admin")
	}
	if strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 200 || strings.ContainsAny(in.Reason, "\r\n\x00") {
		return nil, fail(400, "invalid", "reason is required: one line, at most 200 characters (a ticket number, say)")
	}
	b := make([]byte, 4)
	rand.Read(b)
	return a.makeAdmin(c, "support-"+hex.EncodeToString(b), in.Role, in.Hours, in.Reason, true)
}

func (a *API) listAdmins(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.Store.Admins(c.tenant), nil
}

// removeAdmin ends an administrator's token. The last owner cannot be removed, and nobody removes themselves.
func (a *API) removeAdmin(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name := r.PathValue("name")
	if name == c.actor {
		return nil, fail(409, "invalid", "you cannot remove yourself; ask another owner")
	}
	if err := a.Store.RemoveAdmin(c.tenant, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fail(404, "not_found", "no such administrator")
		}
		return nil, fail(409, "invalid", err.Error())
	}
	a.log(c, "admin.remove", name, nil, nil)
	return map[string]string{"removed": name}, nil
}

// me tells the console who is signed in and what the role may do, so it shows only the screens and buttons
// the role can use. The server still checks every call; this only spares people a refusal (ADM-001, ADM-002).
func (a *API) me(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	perms := []store.Perm{}
	for _, p := range []store.Perm{store.PermRead, store.PermLogs, store.PermAudit, store.PermSupport, store.PermWrite, store.PermSensitive, store.PermAdmins} {
		if c.role.Can(p) {
			perms = append(perms, p)
		}
	}
	return map[string]any{"name": c.actor, "role": c.role, "permissions": perms}, nil
}

// offboard is the "person left" action (GAP-REQ-07): one call ends the account, the devices, the access
// grants and the open access requests, and answers with a checklist of what it ended and what it cannot
// reach. The pieces are the same ones the separate disable and revoke calls use.
func (a *API) offboard(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	rep, err := a.Store.Offboard(c.tenant, id)
	if err != nil {
		return nil, err
	}
	if a.OnDisableUser != nil {
		for _, s := range rep.Identifiers {
			a.OnDisableUser(c.tenant, s) // close their sessions now
		}
		a.OnDisableUser(c.tenant, id)
	}
	if a.OnRevokeDevice != nil {
		for _, d := range rep.Devices {
			a.OnRevokeDevice(c.tenant, d)
		}
	}
	denied := 0
	if a.Approvals != nil {
		ids := map[string]bool{}
		for _, s := range rep.Identifiers {
			ids[s] = true
		}
		now := a.Store.Time()
		for _, q := range a.Approvals.List(c.tenant, approvals.Pending) {
			if ids[strings.ToLower(q.User)] {
				if _, err := a.Approvals.Decide(c.tenant, q.ID, approvals.Denied, c.actor, time.Time{}, now); err == nil {
					denied++
				}
			}
		}
	}
	type step struct {
		Step   string `json:"step"`
		Done   bool   `json:"done"`
		Count  int    `json:"count,omitempty"`
		Detail string `json:"detail"`
	}
	acct := "disabled; their sessions are closed"
	if rep.WasDisabled {
		acct = "was already disabled; sessions closed again"
	}
	steps := []step{
		{"account", true, 0, acct},
		{"devices", true, len(rep.Devices), "revoked and kept, so their certificates stay refused (devices already revoked are not counted)"},
		{"access grants", true, rep.Grants, "temporary approved access ended"},
		{"access requests", true, denied, "waiting requests refused"},
		{"identity provider record", true, 0, map[bool]string{true: "the provisioned user was marked inactive here", false: "no provisioned user to change"}[rep.SCIMDeactived]},
		{"AI agents", false, 0, "not covered: agent identities have no owner recorded, so none can be found from the person. Check the agent list (GET /v1/ai-agents) and remove what they set up."},
		{"other services", false, 0, "not covered: this product cannot end their sign-in at the identity provider, other cloud services, shared passwords or keys. Disable them there too."},
	}
	a.log(c, "user.offboard", id, nil, map[string]any{"devices": len(rep.Devices), "grants": rep.Grants, "requests": denied})
	return map[string]any{
		"user":         id,
		"steps":        steps,
		"takes_effect": "New connections are refused at once. Enforcement nodes pick the change up at their next poll (every 2 seconds by default). A node that cannot reach the control plane keeps its last state until that state is stale.",
	}, nil
}
