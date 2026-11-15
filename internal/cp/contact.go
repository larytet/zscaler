package cp

import (
	"net/http"
	"strings"
)

// The person the platform's operator tells first if this tenant's data is lost (GAP-REQ-11).

func validEmail(e string) bool {
	return strings.Contains(e, "@") && !strings.ContainsAny(e, " \r\n<>,") && len(e) <= 254 && !strings.HasPrefix(e, "@") && !strings.HasSuffix(e, "@")
}

func (a *API) putSecurityContact(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Email != "" && !validEmail(in.Email) {
		return nil, fail(400, "invalid", "bad email address")
	}
	if len(in.Name) > 100 || strings.ContainsAny(in.Name, "\r\n<>") {
		return nil, fail(400, "invalid", "bad name")
	}
	oldName, oldEmail, _ := a.Store.SecurityContact(c.tenant)
	if err := a.Store.SetSecurityContact(c.tenant, in.Name, in.Email); err != nil {
		return nil, err
	}
	a.log(c, "security-contact.update", "contact", map[string]string{"name": oldName, "email": oldEmail}, map[string]string{"name": in.Name, "email": in.Email})
	return in, nil
}

func (a *API) getSecurityContact(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	name, email, _ := a.Store.SecurityContact(c.tenant)
	note := ""
	if email == "" {
		note = "No security contact is set. If the platform lost your data, the operator would fall back to your alert recipients (GET /v1/alert-settings) if there are any."
	}
	return map[string]string{"name": name, "email": email, "note": note}, nil
}
