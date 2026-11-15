package cp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/privacy"
	"github.com/larytet/zscaler/internal/store"
)

// readAll returns the text of every file under dir that holds records of the given tenant.
func readAll(t *testing.T, dir, tenant string) string {
	var sb strings.Builder
	filepath.Walk(dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), `"tenant":"`+tenant+`"`) {
				sb.Write(b)
			}
		}
		return nil
	})
	return sb.String()
}

func TestAPersonCanBeExportedAndErasedEverywhere(t *testing.T) { // AGT-037 (NFR-030)
	e := newEnrolEnv(t)
	dir := filepath.Join(t.TempDir(), "d")
	arch, _ := decisions.OpenArchive(dir, decisions.DefaultRetention)
	defer arch.Close()
	e.api.Decisions = decisions.New()
	e.api.Decisions.SetArchive(arch)
	e.api.Approvals, e.api.Alerts, e.api.Health = approvals.New(), alerts.New(), devhealth.New()
	var disabled []string
	var revoked []string
	e.api.OnDisableUser = func(tn, s string) { disabled = append(disabled, tn+"/"+s) }
	e.api.OnRevokeDevice = func(tn string, d store.Device) { revoked = append(revoked, tn+"/"+d.ID) }
	st := e.api.Store
	// the person, in every place the platform keeps one
	st.UpsertUser("a", policy.User{Subject: "sub-alice", Email: "alice@example.com", Groups: []string{"finance"}})
	st.UpsertUser("a", policy.User{Subject: "sub-bob", Email: "bob@example.com"})
	st.UpsertUser("b", policy.User{Subject: "sub-alice", Email: "alice@example.com"}) // the same name in another tenant
	st.PutDevice("a", store.Device{ID: "d-alice", User: "sub-alice", Serial: "111"})
	st.PutDevice("a", store.Device{ID: "d-bob", User: "sub-bob", Serial: "222"})
	st.PutGrant("a", store.Grant{User: "sub-alice", App: "erp", Expires: time.Now().Add(time.Hour), By: "admin"})
	st.SetRestricted("a", "sub-alice", true, "phishing report")
	st.SetSCIM("a", true, false)
	su, _, _ := st.SCIMPutUser("a", "", store.SCIMUserIn{UserName: "alice@example.com", Email: "alice@example.com", DisplayName: "Alice A", Active: true})
	st.SCIMPutGroup("a", "", "", "finance", []string{su.ID})
	e.api.Approvals.Add("a", "sub-alice", "erp", "jit", time.Now())
	e.api.Approvals.Add("a", "sub-bob", "erp", "jit", time.Now())
	e.api.Health.Put(devhealth.Entry{Tenant: "a", User: "sub-alice", Device: "d-alice", At: time.Now()})
	e.api.Health.Put(devhealth.Entry{Tenant: "a", User: "sub-bob", Device: "d-bob", At: time.Now()})
	now := time.Now().UTC()
	var recs []broker.Record
	for i := 0; i < 3; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Action: "allow", Event: "open", User: "sub-alice", App: "erp", TS: now})
	}
	recs = append(recs,
		broker.Record{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "sub-bob", App: "erp", TS: now},
		broker.Record{Tenant: "a", Kind: "posture", Action: "pass", User: "sub-alice", Device: "d-alice", TS: now},
		broker.Record{Tenant: "a", Kind: "posture", Action: "fail", User: "sub-alice", Device: "d-alice", TS: now, Reason: "disk"}, // a pass and then a fail opens an alert about her
		broker.Record{Tenant: "b", Kind: "private", Action: "allow", Event: "open", User: "sub-alice", App: "x", TS: now})
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatalf("ingest %d", c)
	}
	e.call("POST", "/v1/users/sub-alice/restrict", e.adminA, map[string]string{"reason": "r"}) // an audit event that names her

	// only owners may ask, and the request must name someone who is known
	adm, _ := st.AddAdmin("a", "adam", store.Admin)
	for _, m := range []string{"GET", "DELETE"} {
		if c, _, _ := e.call(m, "/v1/privacy/subject?user=sub-alice&confirm=sub-alice", adm, nil); c != 403 {
			t.Fatalf("an admin used %s: %d", m, c)
		}
	}
	if c, _, _ := e.call("GET", "/v1/privacy/subject", e.adminA, nil); c != 400 {
		t.Fatalf("no user: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/privacy/subject?user=nobody", e.adminA, nil); c != 404 {
		t.Fatalf("an unknown person: %d", c)
	}

	// the copy: everything about her, found by her e-mail address too, and nothing about anyone else
	c, b, _ := e.call("GET", "/v1/privacy/subject?user=Alice@Example.com", e.adminA, nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var exp struct {
		Held struct {
			Users     []policy.User
			SCIMUsers []store.SCIMUser `json:"scim_users"`
			Devices   []store.Device
			Grants    []store.Grant `json:"access_grants"`
		} `json:"held_by_the_store"`
		Requests  []any    `json:"access_requests"`
		Alerts    []any    `json:"alerts"`
		Health    []any    `json:"device_health"`
		Decisions []any    `json:"decision_records"`
		Audit     []any    `json:"admin_audit_events"`
		Not       []string `json:"not_included"`
	}
	json.Unmarshal(b, &exp)
	if len(exp.Held.Users) != 1 || len(exp.Held.SCIMUsers) != 1 || len(exp.Held.Devices) != 1 || len(exp.Held.Grants) != 1 || len(exp.Requests) != 1 ||
		len(exp.Alerts) != 1 || len(exp.Health) != 1 || len(exp.Decisions) != 5 || len(exp.Audit) < 1 || len(exp.Not) == 0 {
		t.Fatalf("the copy is incomplete: %s", b)
	}
	if strings.Contains(string(b), "sub-bob") || strings.Contains(string(b), "d-bob") || strings.Contains(string(b), "bob@example.com") {
		t.Fatalf("someone else's data is in the copy: %s", b)
	}

	// erasure needs the name repeated
	if c, _, _ := e.call("DELETE", "/v1/privacy/subject?user=sub-alice", e.adminA, nil); c != 400 {
		t.Fatalf("no confirmation: %d", c)
	}
	if c, _, _ := e.call("DELETE", "/v1/privacy/subject?user=sub-alice&confirm=sub-alic", e.adminA, nil); c != 400 {
		t.Fatalf("a wrong confirmation: %d", c)
	}
	if d, _ := st.Subject("a", []string{"sub-alice"}); len(d.Users) != 1 {
		t.Fatal("a refused erasure changed something")
	}
	c, b, _ = e.call("DELETE", "/v1/privacy/subject?user=Alice@Example.com&confirm=Alice@Example.com", e.adminA, nil)
	var er map[string]any
	json.Unmarshal(b, &er)
	repl, _ := er["erased_as"].(string)
	if c != 200 || !strings.HasPrefix(repl, "erased-") || er["users"] != float64(1) || er["devices_revoked_and_disowned"] != float64(1) ||
		er["decision_records_on_disk"] != float64(5) || er["scim_users"] != float64(1) || er["access_grants"] != float64(1) {
		t.Fatalf("%d %s", c, b)
	}
	if len(disabled) != 1 || disabled[0] != "a/sub-alice" || len(revoked) != 1 || revoked[0] != "a/d-alice" {
		t.Fatalf("sessions must be closed: %v %v", disabled, revoked)
	}

	// gone from every place
	if d, _ := st.Subject("a", []string{"sub-alice", "alice@example.com"}); len(d.Users)+len(d.SCIMUsers)+len(d.Devices)+len(d.Grants) != 0 || d.Restricted != nil {
		t.Fatalf("%+v", d)
	}
	if g, _ := st.SCIMGroupList("a"), 0; len(g) != 1 || len(g[0].Members) != 0 {
		t.Fatalf("the SCIM group must have lost her: %+v", g)
	}
	snap := st.Snapshot().Tenants["a"]
	revokedInSnap := false
	for _, d := range snap.RevokedDevices {
		revokedInSnap = revokedInSnap || d == "d-alice"
	}
	if !revokedInSnap {
		t.Fatal("her device must stay revoked: deleting it would make its certificate valid again")
	}
	if devs, _ := st.Devices("a"); len(devs) != 2 {
		t.Fatalf("%v", devs)
	}
	for _, d := range func() []store.Device { x, _ := st.Devices("a"); return x }() {
		if d.ID == "d-alice" && (d.User != "" || !d.Revoked) {
			t.Fatalf("her device must be revoked and have no owner: %+v", d)
		}
	}
	for _, r := range e.api.Approvals.List("a", "") {
		if r.User == "sub-alice" {
			t.Fatal("an access request still names her")
		}
	}
	if len(e.api.Alerts.List("a", false)) != 0 || len(e.api.Health.List("a", time.Now())) != 1 {
		t.Fatal("alerts about her must be gone and only Bob's health report left")
	}
	if es, _ := e.api.Decisions.Query("a", decisions.Filter{User: "sub-alice", Limit: 100}); len(es) != 0 {
		t.Fatal("the live view still names her")
	}
	raw := strings.ToLower(readAll(t, dir, "a"))
	if strings.Contains(raw, "sub-alice") || strings.Contains(raw, "alice@example.com") {
		t.Fatal("her name is still on disk in the decision records")
	}
	if strings.Count(raw, repl) != 5 || !strings.Contains(raw, "sub-bob") {
		t.Fatalf("the records stay, under the stand-in, and Bob's are untouched: %d", strings.Count(raw, repl))
	}
	// the other tenant's person of the same name is untouched, and Bob is untouched
	if d, _ := st.Subject("b", []string{"sub-alice"}); len(d.Users) != 1 {
		t.Fatal("another tenant's user was erased")
	}
	if d, _ := st.Subject("a", []string{"sub-bob"}); len(d.Users) != 1 || len(d.Devices) != 1 {
		t.Fatal("another person was erased")
	}
	if rb, _ := e.api.Decisions.Archive().Query("b", decisions.Query{Limit: 10}); len(rb.Records) != 1 || rb.Records[0].User != "sub-alice" {
		t.Fatal("another tenant's records were changed")
	}
	// the audit log is kept, and the erasure is in it under a stand-in, with no name
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	var evs []struct{ Action, Object string }
	json.Unmarshal(ab, &evs)
	var sawErase, sawExport bool
	for _, ev := range evs {
		if ev.Action == "privacy.erase" {
			sawErase = ev.Object == repl
		}
		if ev.Action == "privacy.export" {
			sawExport = strings.HasPrefix(ev.Object, "subject-") && !strings.Contains(ev.Object, "alice")
		}
	}
	if !sawErase || !sawExport || !strings.Contains(string(ab), `"user.restrict"`) {
		t.Fatalf("the audit log is kept, and the export and erasure are in it without the name: %s", ab)
	}
	if c, _, _ := e.call("DELETE", "/v1/privacy/subject?user=sub-alice&confirm=sub-alice", e.adminA, nil); c != 404 {
		t.Fatalf("erasing twice: %d", c)
	}
	// tenant b's owner sees only tenant b's person
	if c, b, _ := e.call("GET", "/v1/privacy/subject?user=sub-alice", e.adminB, nil); c != 200 || strings.Contains(string(b), "d-alice") || strings.Contains(string(b), "finance") {
		t.Fatalf("tenant isolation: %d %s", c, b)
	}
}

func TestAPersonCanBeFoundAndErasedByPseudonym(t *testing.T) { // AGT-037 (NFR-030, with the privacy mode)
	e := newEnrolEnv(t)
	dir := filepath.Join(t.TempDir(), "d")
	arch, _ := decisions.OpenArchive(dir, decisions.DefaultRetention)
	defer arch.Close()
	e.api.Decisions = decisions.New()
	e.api.Decisions.SetArchive(arch)
	e.api.Store.UpsertUser("a", policy.User{Subject: "sub-dora", Email: "dora@example.com"})
	e.call("PUT", "/v1/privacy", e.adminA, map[string]any{"pseudonymise_users": true})
	pseudo := privacyPseudonym(e, "sub-dora")
	recs := []broker.Record{{Tenant: "a", Kind: "private", Action: "allow", Event: "open", User: "sub-dora", App: "erp", TS: time.Now().UTC()}}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	if !strings.Contains(strings.ToLower(readAll(t, dir, "a")), pseudo) || strings.Contains(strings.ToLower(readAll(t, dir, "a")), "sub-dora") {
		t.Fatal("in privacy mode the archive holds the pseudonym, not the name")
	}
	c, b, _ := e.call("GET", "/v1/privacy/subject?user="+pseudo, e.adminA, nil)
	if c != 200 || !strings.Contains(string(b), "decision_records") || strings.Count(string(b), pseudo) < 1 {
		t.Fatalf("a pseudonym finds the person: %d %s", c, b)
	}
	if c, b, _ := e.call("DELETE", "/v1/privacy/subject?user="+pseudo+"&confirm="+pseudo, e.adminA, nil); c != 200 || !strings.Contains(string(b), `"decision_records_on_disk":1`) {
		t.Fatalf("%d %s", c, b)
	}
	if strings.Contains(strings.ToLower(readAll(t, dir, "a")), pseudo) {
		t.Fatal("the pseudonym is still on disk")
	}
	if d, _ := e.api.Store.Subject("a", []string{"sub-dora"}); len(d.Users) != 0 {
		t.Fatal("the person must be gone")
	}
}

func privacyPseudonym(e *enrolEnv, user string) string {
	return privacy.Pseudonym(e.api.Store.Privacy("a").Key, user)
}
