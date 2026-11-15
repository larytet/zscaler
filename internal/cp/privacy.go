package cp

import (
	"net/http"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/privacy"
)

// privacyOn returns the tenant's pseudonymisation key, or "" when the mode is off.
func (a *API) privacyKey(tenant string) string {
	if c := a.Store.Privacy(tenant); c != nil && c.PseudonymiseUsers {
		return c.Key
	}
	return ""
}

// redact returns the record as it may be stored, streamed or shown: with the user's pseudonym in place
// of the name when the tenant's privacy mode is on. The live view the platform computes risk and
// alerts from is not redacted, because it needs to know who is who.
func (a *API) redact(r broker.Record) broker.Record {
	if key := a.privacyKey(r.Tenant); key != "" {
		r.User = privacy.Pseudonym(key, r.User)
	}
	return r
}

// userFilter turns the user a caller asked about into what to look for. In privacy mode a caller may
// ask about a pseudonym only: a real name must not find anything, or names could be matched to
// pseudonyms by trying them. It returns the value to match and other stored values that also match.
func (a *API) userFilter(tenant, asked string) (string, []string) {
	key := a.privacyKey(tenant)
	if key == "" || asked == "" {
		return asked, nil
	}
	if !privacy.IsPseudonym(asked) {
		return "\x00no-such-user", nil
	}
	if real := a.lookup(tenant, asked); real != "" {
		return asked, []string{real} // records stored before the mode was turned on carry the real name
	}
	return asked, nil
}

// lookup finds the user a pseudonym belongs to among the tenant's users, or "".
func (a *API) lookup(tenant, pseudonym string) string {
	c := a.Store.Privacy(tenant)
	if c == nil || c.Key == "" {
		return ""
	}
	users, _ := a.Store.Users(tenant)
	for _, u := range users {
		for _, name := range []string{u.Subject, u.Email} {
			if name != "" && privacy.Pseudonym(c.Key, name) == pseudonym {
				return name
			}
		}
	}
	return ""
}

// putPrivacy turns the log privacy mode on or off.
func (a *API) putPrivacy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		PseudonymiseUsers *bool `json:"pseudonymise_users"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.PseudonymiseUsers == nil {
		return nil, fail(400, "invalid", "pseudonymise_users (true or false) is required")
	}
	before := a.privacyView(c.tenant)
	if err := a.Store.SetPrivacy(c.tenant, *in.PseudonymiseUsers); err != nil {
		return nil, err
	}
	a.log(c, "privacy.put", "", before, a.privacyView(c.tenant))
	return a.privacyView(c.tenant), nil
}

func (a *API) privacyView(tenant string) map[string]any {
	out := map[string]any{"pseudonymise_users": false, "notes": []string{
		"Turning the mode on hides user names in decision records that are stored, streamed to a log system, or shown; it does not change records already stored or streamed, and it does not cover the admin audit log, alert and e-mail text, or the lists of users and devices.",
		"The same person always gets the same pseudonym, so a log can still be followed; an owner can look a pseudonym up with GET /v1/privacy/reveal, and each look-up is audited.",
	}}
	if c := a.Store.Privacy(tenant); c != nil {
		out["pseudonymise_users"] = c.PseudonymiseUsers
		if !c.Since.IsZero() {
			out["since"] = c.Since
		}
	}
	return out
}

func (a *API) getPrivacy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.privacyView(c.tenant), nil
}

// revealUser gives the user behind a pseudonym, to an owner, and audits the look-up (not the name).
func (a *API) revealUser(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	p := r.URL.Query().Get("pseudonym")
	if !privacy.IsPseudonym(p) {
		return nil, fail(400, "invalid", "pseudonym must look like u-0123456789ab")
	}
	user := a.lookup(c.tenant, p)
	a.log(c, "privacy.reveal", p, nil, map[string]bool{"found": user != ""})
	if user == "" {
		return nil, fail(404, "not_found", "no user of this tenant has that pseudonym")
	}
	return map[string]string{"pseudonym": p, "user": user}, nil
}

func (a *API) redactEntries(es []decisions.Entry, tenant string) {
	if key := a.privacyKey(tenant); key != "" {
		for i := range es {
			es[i].User = privacy.Pseudonym(key, es[i].User)
		}
	}
}
