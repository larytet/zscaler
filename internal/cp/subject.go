package cp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/privacy"
)

// Data about one person (NFR-030): a copy of what the platform holds, and erasure. Both are for owners:
// they expose, or destroy, personal data. Both are audited, by a reference that is not the person's name.

// subjectIDs works out what a person is known by. In privacy mode a pseudonym may be given.
func (a *API) subjectIDs(tenant, asked string) []string {
	asked = strings.TrimSpace(asked)
	if asked == "" {
		return nil
	}
	ids := []string{asked}
	if privacy.IsPseudonym(asked) {
		if real := a.lookup(tenant, asked); real != "" {
			ids = append(ids, real)
		}
	}
	return ids
}

// ref is a short reference to a person for the audit log: it does not contain their name.
func ref(asked string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(asked))))
	return "subject-" + hex.EncodeToString(h[:6])
}

const exportLimit = 5000

// exportSubject gives a copy of everything held about one person.
func (a *API) exportSubject(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	asked := r.URL.Query().Get("user")
	ids := a.subjectIDs(c.tenant, asked)
	if len(ids) == 0 {
		return nil, fail(400, "invalid", "user (a subject, an e-mail address or, in privacy mode, a pseudonym) is required")
	}
	data, err := a.Store.Subject(c.tenant, ids)
	if err != nil {
		return nil, err
	}
	if len(data.Users) == 0 && len(data.SCIMUsers) == 0 && len(data.Devices) == 0 {
		return nil, fail(404, "not_found", "nothing is held about that person under that name")
	}
	all := append([]string(nil), data.Identifiers...)
	if key := a.privacyKey(c.tenant); key != "" { // records stored in privacy mode carry the pseudonym
		for _, id := range data.Identifiers {
			all = append(all, privacy.Pseudonym(key, id))
		}
	}
	out := map[string]any{"held_by_the_store": data}
	if a.Approvals != nil {
		var reqs []any
		for _, q := range a.Approvals.List(c.tenant, "") { // every state
			if containsFold(all, q.User) {
				reqs = append(reqs, q)
			}
		}
		out["access_requests"] = reqs
	}
	if a.Alerts != nil {
		var al []any
		for _, x := range a.Alerts.List(c.tenant, false) {
			if x.User != "" && containsFold(all, x.User) {
				al = append(al, x)
			}
		}
		out["alerts"] = al
	}
	if a.Health != nil {
		var hs []any
		for _, d := range a.Health.List(c.tenant, a.Store.Time()) {
			if containsFold(all, d.User) {
				hs = append(hs, d)
			}
		}
		out["device_health"] = hs
	}
	if a.Decisions != nil {
		if arch := a.Decisions.Archive(); arch != nil {
			recs := []any{}
			truncated := false
			for _, id := range all {
				res, err := arch.Query(c.tenant, decisions.Query{User: id, Limit: 1000})
				for {
					for _, rec := range res.Records {
						if len(recs) >= exportLimit {
							truncated = true
						} else {
							recs = append(recs, rec)
						}
					}
					if err != nil || res.Next == "" || truncated {
						break
					}
					res, err = arch.Query(c.tenant, decisions.Query{User: id, Limit: 1000, Cursor: res.Next})
				}
			}
			out["decision_records"], out["decision_records_truncated"] = recs, truncated
		}
	}
	if a.AuditPath != "" {
		var ev []audit.Event
		all2, _ := audit.ReadAll(a.AuditPath, c.tenant)
		for _, e := range all2 {
			if containsFold(all, e.Actor) || containsAnyFold(e.Object, all) {
				ev = append(ev, e)
			}
		}
		out["admin_audit_events"] = ev
	}
	out["not_included"] = []string{
		"copies the enforcement nodes keep in their own decision files, and records already streamed to a log system",
		"backups of the control plane's data directory",
	}
	a.log(c, "privacy.export", ref(asked), nil, nil)
	return out, nil
}

func containsFold(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) && s != "" {
			return true
		}
	}
	return false
}

func containsAnyFold(s string, l []string) bool {
	s = strings.ToLower(s)
	for _, x := range l {
		if x != "" && strings.Contains(s, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

// eraseSubject erases one person from the platform. confirm must repeat the name exactly, so a slip of
// the keyboard cannot destroy a record. The admin audit log is kept as it is (it is a hash chain whose
// purpose is to show who did what); the erasure itself is added to it under a reference, not the name.
func (a *API) eraseSubject(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	asked := r.URL.Query().Get("user")
	if asked == "" || r.URL.Query().Get("confirm") != asked {
		return nil, fail(400, "invalid", "user and confirm are required, and confirm must repeat the user exactly")
	}
	ids := a.subjectIDs(c.tenant, asked)
	data, err := a.Store.Subject(c.tenant, ids)
	if err != nil {
		return nil, err
	}
	if len(data.Users) == 0 && len(data.SCIMUsers) == 0 && len(data.Devices) == 0 {
		return nil, fail(404, "not_found", "nothing is held about that person under that name")
	}
	b := make([]byte, 4)
	rand.Read(b)
	repl := "erased-" + hex.EncodeToString(b) // one stand-in for the person in every record, so patterns remain and the name does not
	all := append([]string(nil), data.Identifiers...)
	if key := a.privacyKey(c.tenant); key != "" {
		for _, id := range data.Identifiers {
			all = append(all, privacy.Pseudonym(key, id))
		}
	}
	rep, err := a.Store.EraseSubject(c.tenant, ids)
	if err != nil {
		return nil, err
	}
	// end their access now: sessions of the user and of every device that was theirs
	if a.OnDisableUser != nil {
		for _, u := range data.Users {
			a.OnDisableUser(c.tenant, u.Subject)
		}
	}
	if a.OnRevokeDevice != nil {
		for _, d := range rep.Revoked {
			a.OnRevokeDevice(c.tenant, d)
		}
	}
	out := map[string]any{"erased_as": repl, "users": rep.Users, "scim_users": rep.SCIMUsers, "devices_revoked_and_disowned": rep.Devices, "access_grants": rep.Grants}
	if a.Decisions != nil {
		out["decision_records_live_view"] = a.Decisions.Erase(c.tenant, all, repl)
		if arch := a.Decisions.Archive(); arch != nil {
			recs, files, err := arch.Redact(c.tenant, all, repl)
			if err != nil {
				return nil, err
			}
			out["decision_records_on_disk"], out["decision_files_rewritten"] = recs, files
		}
	}
	if a.Approvals != nil {
		out["access_requests"] = a.Approvals.Erase(c.tenant, all, repl)
	}
	if a.Alerts != nil {
		out["alerts"] = a.Alerts.EraseUser(c.tenant, all)
	}
	if a.Health != nil {
		out["device_health_reports"] = a.Health.Erase(c.tenant, all)
	}
	out["kept"] = []string{
		"the admin audit log, which is an unalterable chain of what administrators did (it holds no name of this person that was not already there, and this erasure is recorded in it under a reference)",
		"copies the enforcement nodes keep in their own decision files, records already streamed to a log system, and backups: remove those yourself",
		"their devices' certificates are revoked, not deleted: a deleted revoked device would be valid again",
	}
	a.log(c, "privacy.erase", repl, nil, map[string]any{"ref": ref(asked), "users": rep.Users, "devices": rep.Devices})
	return out, nil
}
