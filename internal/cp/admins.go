package cp

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/larytet/zscaler/internal/store"
)

var adminName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)

// createAdmin makes another administrator and returns their token, once (ADM-002). Only an owner may.
func (a *API) createAdmin(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Name string     `json:"name"`
		Role store.Role `json:"role"`
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
	tok, err := a.Store.AddAdmin(c.tenant, in.Name, in.Role)
	if errors.Is(err, store.ErrExists) {
		return nil, fail(409, "exists", "an administrator with that name exists")
	}
	if err != nil {
		return nil, err
	}
	a.log(c, "admin.create", in.Name, nil, map[string]string{"role": string(in.Role)}) // never the token
	return map[string]string{"name": in.Name, "role": string(in.Role), "token": tok}, nil
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
