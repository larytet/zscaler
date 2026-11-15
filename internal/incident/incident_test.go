package incident

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

// three tenants: acme (served by en1 and en2, has a contact), beta (served by en1, only alert recipients), gamma (served by en3, nothing set)
func fixture(t *testing.T, key *seal.Key) (dir string, st *store.Store, now time.Time) {
	t.Helper()
	dir = t.TempDir()
	now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var err error
	if st, err = store.OpenWithKey(filepath.Join(dir, "store.json"), key); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"acme", "beta", "gamma"} {
		if _, err := st.CreateTenant(id, strings.ToUpper(id[:1])+id[1:]+" Ltd"); err != nil {
			t.Fatal(err)
		}
	}
	st.UpsertUser("acme", policy.User{Subject: "alice", Email: "alice@acme.example"})
	st.UpsertUser("acme", policy.User{Subject: "bob", Email: "bob@acme.example"})
	st.PutDevice("acme", store.Device{ID: "d1", User: "alice", Serial: "S1"})
	st.PutSecret("acme", store.Secret{Name: "crm", Host: "crm.example", Header: "Authorization", Value: "Bearer very-secret-value"})
	st.UpsertUser("beta", policy.User{Subject: "carol", Email: "carol@beta.example"})
	st.SetSecurityContact("acme", "Dana Owner", "dana@acme.example")
	st.SetAlertEmails("beta", []string{"it@beta.example"})
	lg, _ := audit.Open(filepath.Join(dir, "audit.jsonl"), func() time.Time { return now.Add(-2 * time.Hour) })
	lg.Append("acme", "owner", "policy.save", "web", nil, nil)
	lg.Append("acme", "owner", "admin.create", "dana", nil, nil)
	lg.Append("acme", "temp-support", "device.revoke", "d1", nil, nil)
	lg.Append("beta", "owner", "policy.save", "web", nil, nil)
	lg.Close()
	arch, err := decisions.OpenArchive(filepath.Join(dir, "decisions"), decisions.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	rec := func(tenant, en string, ts time.Time) broker.Record {
		return broker.Record{Tenant: tenant, Kind: "private", Action: "allow", Event: "open", User: "u", App: "erp", EN: en, TS: ts}
	}
	for _, r := range []broker.Record{
		rec("acme", "en1", now.Add(-24*time.Hour)), rec("acme", "en2", now.Add(-time.Hour)), rec("beta", "en1", now.Add(-time.Hour)),
		rec("gamma", "en3", now.Add(-48*time.Hour)), rec("acme", "en2", now.Add(-60*24*time.Hour)), // acme's en2 record from two months before the window
	} {
		if err := arch.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	arch.Close()
	return
}

func inScope(r Report) string {
	var ids []string
	for _, t := range r.Tenants {
		if t.Affected {
			ids = append(ids, t.Tenant)
		}
	}
	return strings.Join(ids, ",")
}

func TestScopeFollowsWhatWasLost(t *testing.T) { // AGT-049 (GAP-REQ-11)
	dir, st, now := fixture(t, nil)
	from, to := now.AddDate(0, 0, -30), now
	for _, c := range []struct {
		sc   Scenario
		want string
	}{
		{Scenario{Kind: "control-plane"}, "acme,beta,gamma"},
		{Scenario{Kind: "node", Node: "en1"}, "acme,beta"},
		{Scenario{Kind: "node", Node: "en2"}, "acme"}, // the older en2 record is outside the window and the only one for gamma is en3
		{Scenario{Kind: "node", Node: "en3"}, "gamma"},
		{Scenario{Kind: "node", Node: "en9"}, ""},
		{Scenario{Kind: "admin-token", Tenant: "beta"}, "beta"},
	} {
		r, err := Build(st, dir, nil, c.sc, from, to, time.Time{}, now)
		if err != nil {
			t.Fatalf("%+v: %v", c.sc, err)
		}
		if got := inScope(r); got != c.want {
			t.Errorf("%+v: in scope %q, want %q", c.sc, got, c.want)
		}
	}
	// a window that excludes the records excludes the tenant, for a node
	r, _ := Build(st, dir, nil, Scenario{Kind: "node", Node: "en2"}, now.AddDate(0, 0, -90), now, time.Time{}, now)
	if inScope(r) != "acme" {
		t.Errorf("a wider window: %q", inScope(r))
	}
	if _, err := Build(st, dir, nil, Scenario{Kind: "node", Node: "en2"}, now.Add(-30*time.Minute), now, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	// bad input is refused with a message, not guessed at
	for _, sc := range []Scenario{{Kind: "meteor"}, {Kind: "node"}, {Kind: "admin-token", Tenant: "nobody"}, {Kind: "admin-token"}} {
		if _, err := Build(st, dir, nil, sc, from, to, time.Time{}, now); err == nil {
			t.Errorf("%+v accepted", sc)
		}
	}
}

func TestReportSaysWhatIsHeldAndWhoToTellAndNothingSecret(t *testing.T) { // AGT-049
	dir, st, now := fixture(t, nil)
	aware := now.Add(-3 * time.Hour)
	r, err := Build(st, dir, nil, Scenario{Kind: "control-plane"}, now.AddDate(0, 0, -30), now, aware, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Deadline.Equal(aware.Add(72 * time.Hour)) {
		t.Errorf("deadline %v", r.Deadline)
	}
	var acme, beta, gamma TenantReport
	for _, tr := range r.Tenants {
		switch tr.Tenant {
		case "acme":
			acme = tr
		case "beta":
			beta = tr
		case "gamma":
			gamma = tr
		}
	}
	cat := func(tr TenantReport, what string) int {
		for _, c := range tr.Categories {
			if strings.HasPrefix(c.What, what) {
				return c.Count
			}
		}
		return 0
	}
	if cat(acme, "people") != 2 || cat(acme, "devices") != 1 || cat(acme, "stored credentials") != 1 || cat(acme, "decision records") != 3 || cat(beta, "people") != 1 || cat(gamma, "people") != 0 {
		t.Errorf("counts: acme %+v beta %+v", acme.Categories, beta.Categories)
	}
	if acme.ArchiveFrom != "2026-09-16" || acme.ArchiveTo != "2026-11-15" {
		t.Errorf("archive range %s %s", acme.ArchiveFrom, acme.ArchiveTo)
	}
	if acme.AuditActions != 3 || acme.AuditActors["temp-support"] != 1 || beta.AuditActions != 1 {
		t.Errorf("audit: %+v %+v", acme, beta)
	}
	if acme.Contact != "dana@acme.example" || acme.ContactName != "Dana Owner" || beta.Contact != "" || len(beta.FallbackTo) != 1 || len(gamma.FallbackTo) != 0 {
		t.Errorf("contacts: %+v %+v %+v", acme, beta, gamma)
	}
	txt := r.Text()
	for _, want := range []string{"3 of 3 tenants are in scope", "within 72 hours", "not legal advice", "Tell: Dana Owner <dana@acme.example>", "No security contact set. Alert recipients: it@beta.example", "NO CONTACT",
		"Whether anything was READ", "Audit chain: intact: 4 records", "NOT encrypted"} {
		if !strings.Contains(txt, want) {
			t.Errorf("the text lacks %q:\n%s", want, txt)
		}
	}
	// nothing secret or personal at the level of a person leaves with the report
	for _, never := range []string{"very-secret-value", "alice@acme.example", "carol@beta.example", "S1", "Bearer"} {
		if strings.Contains(txt, never) {
			t.Errorf("the report contains %q", never)
		}
	}
}

func TestReportSaysWhenTheStoreIsEncryptedAndWhenTheAuditLogIsBroken(t *testing.T) { // AGT-049
	key, _ := seal.ParseKey(seal.Generate())
	dir, st, now := fixture(t, key)
	r, err := Build(st, dir, key, Scenario{Kind: "control-plane"}, now.AddDate(0, 0, -30), now, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Sealed || !strings.Contains(r.Text(), "only if the master key was also lost") || strings.Contains(r.Text(), "NOT encrypted") {
		t.Errorf("sealed text:\n%s", r.Text())
	}
	if !strings.Contains(r.Text(), "No \"aware\" time given") {
		t.Error("no reminder to write down when the operator became aware")
	}
	// an altered audit log is called broken, not trusted
	ap := filepath.Join(dir, "audit.jsonl")
	b, _ := os.ReadFile(ap)
	os.WriteFile(ap, []byte(strings.Replace(string(b), "policy.save", "policy.sa_e", 1)), 0o600)
	r, _ = Build(st, dir, key, Scenario{Kind: "control-plane"}, now.AddDate(0, 0, -30), now, time.Time{}, now)
	if !strings.Contains(r.AuditOK, "BROKEN") {
		t.Errorf("an altered log: %q", r.AuditOK)
	}
	os.Remove(ap)
	r, _ = Build(st, dir, key, Scenario{Kind: "control-plane"}, now.AddDate(0, 0, -30), now, time.Time{}, now)
	if r.AuditOK != "no audit log" {
		t.Errorf("no log: %q", r.AuditOK)
	}
}
