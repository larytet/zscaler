package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/policy"
)

func twoTenants(t *testing.T) (*Store, string, string) {
	s, _ := Open("")
	a, err := s.CreateTenant("a", "A")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.CreateTenant("b", "B")
	return s, a, b
}

func pol() *policy.Policy {
	return &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Rules: []policy.Rule{
		{ID: "r", Priority: 1, Action: policy.Allow, Match: policy.Match{Groups: []string{"g"}}}}}
}

func TestTenantIsolation(t *testing.T) { // STO-001
	s, _, _ := twoTenants(t)
	s.PutSegment("a", broker.Segment{ID: "seg", Group: "g"})
	s.UpsertUser("a", policy.User{Subject: "alice"})
	s.PutDevice("a", Device{ID: "d1", User: "alice"})
	if _, err := s.PutPolicy("a", policy.Private, pol(), 0); err != nil {
		t.Fatal(err)
	}
	if segs, _ := s.Segments("b"); len(segs) != 0 {
		t.Fatal("b sees a's segments")
	}
	if _, ok := s.Segment("b", "seg"); ok {
		t.Fatal("b reads a's segment")
	}
	if _, ok := s.User("b", "alice"); ok {
		t.Fatal("b reads a's user")
	}
	if s.Policy("b", policy.Private) != nil {
		t.Fatal("b reads a's policy")
	}
	if ds, _ := s.Devices("b"); len(ds) != 0 {
		t.Fatal("b sees a's devices")
	}
	if _, err := s.RevokeDevice("b", "d1"); err != ErrNotFound {
		t.Fatalf("b revoked a's device: %v", err)
	}
	if err := s.DeleteSegment("b", "seg"); err != ErrNotFound {
		t.Fatalf("b deleted a's segment: %v", err)
	}
	if err := s.SetUserDisabled("b", "alice", true); err != ErrNotFound {
		t.Fatal("b disabled a's user")
	}
	if _, err := s.Segments("nope"); err != ErrNotFound {
		t.Fatal("unknown tenant")
	}
}

func TestOptimisticConcurrency(t *testing.T) { // STO-002
	s, _, _ := twoTenants(t)
	v, err := s.PutPolicy("a", policy.Private, pol(), 0)
	if err != nil || v != 1 {
		t.Fatalf("%d %v", v, err)
	}
	if _, err := s.PutPolicy("a", policy.Private, pol(), 0); err != ErrConflict {
		t.Fatalf("stale write: %v", err)
	}
	if v, err := s.PutPolicy("a", policy.Private, pol(), 1); err != nil || v != 2 {
		t.Fatalf("%d %v", v, err)
	}
}

func TestInvalidPolicyNotStored(t *testing.T) {
	s, _, _ := twoTenants(t)
	bad := pol()
	bad.DefaultAction = policy.Allow
	if _, err := s.PutPolicy("a", policy.Private, bad, 0); err == nil {
		t.Fatal("invalid policy stored")
	}
	if _, err := s.GetPolicy("a", policy.Private); err != ErrNotFound {
		t.Fatal("version bumped by invalid policy")
	}
	unknown := pol()
	unknown.Rules[0].Match.Apps = []string{"ghost"}
	if _, err := s.PutPolicy("a", policy.Private, unknown, 0); err == nil || !strings.Contains(err.Error(), "unknown segment") {
		t.Fatalf("unknown segment accepted: %v", err)
	}
}

func TestTokensHashedAndTenantFromToken(t *testing.T) { // SEC-010
	s, ta, tb := twoTenants(t)
	for _, h := range s.AdminHashes() {
		if h == ta || h == tb {
			t.Fatal("token stored in clear")
		}
	}
	if tenant, role, _, ok := s.Auth(ta); !ok || tenant != "a" || role != Admin {
		t.Fatal("auth a")
	}
	if tenant, _, _, ok := s.Auth(tb); !ok || tenant != "b" {
		t.Fatal("auth b")
	}
	if _, _, _, ok := s.Auth("wrong"); ok {
		t.Fatal("wrong token accepted")
	}
}

func TestPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	s, _ := Open(p)
	tok, _ := s.CreateTenant("a", "A")
	s.PutSegment("a", broker.Segment{ID: "seg", Group: "g"})
	s.PutPolicy("a", policy.Private, pol(), 0)
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"g"}})
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := s2.Auth(tok); !ok {
		t.Fatal("admin lost")
	}
	d := s2.Policy("a", policy.Private).Evaluate(policy.Request{Kind: policy.Private, User: policy.User{Groups: []string{"g"}}, App: "seg"})
	if d.Action != policy.Allow {
		t.Fatalf("reloaded policy not compiled/working: %+v", d)
	}
}

func TestLoginDoesNotReenableDisabledUser(t *testing.T) {
	s, _, _ := twoTenants(t)
	s.UpsertUser("a", policy.User{Subject: "alice"})
	s.SetUserDisabled("a", "alice", true)
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"x"}})
	if u, _ := s.User("a", "alice"); !u.Disabled {
		t.Fatal("login re-enabled a disabled user")
	}
}

func TestRestrictedGroupSurvivesIdPRefresh(t *testing.T) { // ZPA-072
	s, _, _ := twoTenants(t)
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"finance", "all-staff"}})
	if err := s.SetRestricted("a", "alice", true, "phished"); err != nil {
		t.Fatal(err)
	}
	has := func(u policy.User) bool {
		for _, g := range u.Groups {
			if g == policy.RestrictedGroup {
				return true
			}
		}
		return false
	}
	u, _ := s.User("a", "alice")
	if !has(u) || len(u.Groups) != 3 {
		t.Fatalf("%+v", u)
	}
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"hr"}}) // next login: the IdP reports new groups
	if u, _ := s.User("a", "alice"); !has(u) {
		t.Fatal("a login lifted the restriction")
	}
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"restricted"}}) // an IdP group of the same name must not double up
	if u, _ := s.User("a", "alice"); len(u.Groups) != 1 {
		t.Fatalf("duplicate group: %+v", u.Groups)
	}
	users, _ := s.Users("a")
	if !has(users[0]) {
		t.Fatal("Users() does not show the restriction")
	}
	if !has(s.Snapshot().Tenants["a"].Users[0]) {
		t.Fatal("the snapshot sent to enforcement nodes does not carry the restriction")
	}
	if err := s.SetRestricted("b", "alice", true, ""); err != ErrNotFound {
		t.Fatalf("tenant b restricted tenant a's user: %v", err)
	}
	if err := s.SetRestricted("a", "ghost", true, ""); err != ErrNotFound {
		t.Fatal("restricting an unknown user")
	}
	s.UpsertUser("a", policy.User{Subject: "alice", Groups: []string{"hr"}})
	s.SetRestricted("a", "alice", false, "")
	if u, _ := s.User("a", "alice"); has(u) {
		t.Fatal("unrestrict did not work")
	}
}

func TestGrantsExpireAndReachSnapshot(t *testing.T) { // ZPA-027
	s, _, _ := twoTenants(t)
	now := time.Now()
	s.PutGrant("a", Grant{User: "alice", App: "erp", Expires: now.Add(time.Hour), By: "owner"})
	s.PutGrant("a", Grant{User: "bob", App: "erp", Expires: now.Add(-time.Minute), By: "owner"}) // already expired
	if !s.Granted("a", "alice", "erp", now) {
		t.Fatal("grant not found")
	}
	if s.Granted("a", "alice", "wiki", now) || s.Granted("a", "bob", "erp", now) {
		t.Fatal("grant matched the wrong app or an expired one")
	}
	if s.Granted("b", "alice", "erp", now) {
		t.Fatal("grant leaked to another tenant")
	}
	if s.Granted("a", "alice", "erp", now.Add(2*time.Hour)) {
		t.Fatal("grant outlived its expiry")
	}
	snap := s.Snapshot().Tenants["a"]
	if len(snap.Grants) != 1 || snap.Grants[0].User != "alice" {
		t.Fatalf("only unexpired grants belong in the snapshot: %+v", snap.Grants)
	}
	if len(s.Snapshot().Tenants["b"].Grants) != 0 {
		t.Fatal("grant in another tenant's snapshot")
	}
	s.PutGrant("a", Grant{User: "alice", App: "erp", Expires: now.Add(10 * time.Minute)}) // replaces
	if len(s.Snapshot().Tenants["a"].Grants) != 1 {
		t.Fatal("a second grant for the same user and app must replace the first")
	}
	s.RevokeGrant("a", "alice", "erp")
	if s.Granted("a", "alice", "erp", now) {
		t.Fatal("revoke did not end the grant")
	}
}

func TestInspectionCAIsPerTenantAndKeyStaysInternal(t *testing.T) { // ARCH-021
	s, _, _ := twoTenants(t)
	if err := s.SetInspection("a", true, []string{"bank.example"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetInspection("b", true, nil); err != nil {
		t.Fatal(err)
	}
	ca, _ := s.Inspection("a")
	cb, _ := s.Inspection("b")
	if ca.CACert == "" || ca.CACert == cb.CACert {
		t.Fatal("tenants must have different intercept CAs")
	}
	if ca.CAKey != "" {
		t.Fatal("Inspection() leaked the private key")
	}
	s.SetInspection("a", false, nil)
	s.SetInspection("a", true, nil)
	if again, _ := s.Inspection("a"); again.CACert != ca.CACert {
		t.Fatal("re-enabling inspection created a new CA, which would break every device that trusts the old one")
	}
	snap := s.Snapshot().Tenants["a"]
	if snap.Inspect == nil || snap.Inspect.CAKey == "" || !snap.Inspect.Enabled {
		t.Fatalf("enabled inspection must reach enforcement nodes: %+v", snap.Inspect)
	}
	s.SetInspection("a", false, nil)
	if s.Snapshot().Tenants["a"].Inspect != nil {
		t.Fatal("disabled inspection must not ship the CA key")
	}
	if s.Snapshot().Tenants["b"].Inspect == nil {
		t.Fatal("tenant b's setting was lost")
	}
	if err := s.SetInspection("ghost", true, nil); err != ErrNotFound {
		t.Fatalf("%v", err)
	}
}

func TestInterceptSPKIIsStableAndPerTenant(t *testing.T) { // WB-003 groundwork
	s, _, _ := twoTenants(t)
	if _, ok := s.InterceptSPKI("a"); ok {
		t.Fatal("an SPKI before inspection was ever enabled")
	}
	s.SetInspection("a", true, nil)
	s.SetInspection("b", true, nil)
	a1, ok := s.InterceptSPKI("a")
	b1, _ := s.InterceptSPKI("b")
	if !ok || a1 == "" || a1 == b1 {
		t.Fatalf("each tenant needs its own key: %q %q", a1, b1)
	}
	s.SetInspection("a", false, nil)
	if _, ok := s.InterceptSPKI("a"); ok {
		t.Fatal("an SPKI is offered while inspection is off")
	}
	s.SetInspection("a", true, []string{"bank.example"})
	if a2, _ := s.InterceptSPKI("a"); a2 != a1 {
		t.Fatal("turning inspection off and on changed the key: every workspace would break")
	}
	if snap := s.Snapshot().Tenants["a"].Inspect; snap == nil || snap.LeafKey == "" {
		t.Fatal("the key must reach the enforcement nodes with the CA")
	}
	if cfg, _ := s.Inspection("a"); cfg.LeafKey != "" {
		t.Fatal("Inspection() leaked the leaf key")
	}
}

func TestSecretsAreWriteOnlyAndGuardedByPolicy(t *testing.T) { // AGT-006
	s, _, _ := twoTenants(t)
	if err := s.PutSecret("a", Secret{Name: "api", Host: "api.example.com", Header: "Authorization", Value: "VALUE1"}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Secrets("a")
	if len(list) != 1 || list[0].Value != "" || list[0].Host != "api.example.com" {
		t.Fatalf("listing must not carry the value: %+v", list)
	}
	if other, _ := s.Secrets("b"); len(other) != 0 {
		t.Fatal("another tenant sees the secret")
	}
	web := func(domain string) *policy.Policy {
		return &policy.Policy{Kind: policy.Web, DefaultAction: policy.Deny, Rules: []policy.Rule{
			{ID: "r", Priority: 1, Action: policy.Allow, Inject: "api", Match: policy.Match{Domains: []string{domain}}}}}
	}
	if _, err := s.PutPolicy("a", policy.Web, web("evil.example.net"), 0); err == nil {
		t.Fatal("a rule may only inject a secret on the host it is bound to")
	}
	missing := web("api.example.com")
	missing.Rules[0].Inject = "nope"
	if _, err := s.PutPolicy("a", policy.Web, missing, 0); err == nil {
		t.Fatal("a rule naming a secret that does not exist must be refused")
	}
	if _, err := s.PutPolicy("a", policy.Web, web("api.example.com"), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSecret("a", "api"); err == nil || !strings.Contains(err.Error(), "in use") && !strings.Contains(err.Error(), "used") && !strings.Contains(err.Error(), "inject") {
		t.Fatalf("deleting a secret a rule still uses must be refused: %v", err)
	}
}

func TestExactDataMatchSetsKeepOnlyHashes(t *testing.T) { // AGT-017 (store)
	s, _, _ := twoTenants(t)
	kept, skipped, err := s.PutEDM("a", "customers", []string{"CUST-004711", "CUST-004711", "abc", "has space", "jane.doe@example.com"})
	if err != nil || kept != 2 || skipped != 2 {
		t.Fatalf("%d %d %v", kept, skipped, err)
	}
	list, _ := s.EDMSets("a")
	if len(list) != 1 || list[0].Count != 2 || list[0].Salt != "" || list[0].Hashes != nil {
		t.Fatalf("the listing must show counts only: %+v", list)
	}
	if other, _ := s.EDMSets("b"); len(other) != 0 {
		t.Fatal("tenant b sees tenant a's data set")
	}
	if blob, _ := json.Marshal(s.Snapshot().Tenants["a"]); strings.Contains(string(blob), "CUST-004711") || strings.Contains(strings.ToLower(string(blob)), "jane.doe") {
		t.Fatal("a value was stored in clear")
	}
	if _, _, err := s.PutEDM("a", "bad name", []string{"CUST-004711"}); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, _, err := s.PutEDM("a", "empty", []string{"abc"}); err == nil {
		t.Fatal("a set with no usable value must be refused")
	}
	web := func(set string) *policy.Policy {
		return &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Rules: []policy.Rule{
			{ID: "r", Priority: 1, Action: policy.Deny, Match: policy.Match{DLP: []string{set}}}}}
	}
	if _, err := s.PutPolicy("a", policy.Web, web("edm:ghost"), 0); err == nil {
		t.Fatal("a rule naming a data set that does not exist must be refused")
	}
	if _, err := s.PutPolicy("a", policy.Web, web("edm:customers"), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEDM("a", "customers"); err == nil {
		t.Fatal("deleting a set a rule still uses must be refused")
	}
}

func TestDocumentSetsKeepOnlyHashedRuns(t *testing.T) { // AGT-020 (store)
	s, _, _ := twoTenants(t)
	text := "Acme Corp price list for 2027. The enterprise plan costs forty nine dollars per seat per month, billed annually."
	runs, skipped, err := s.PutEDMDocuments("a", "pricelist", []string{text, "too short"})
	if err != nil || runs < 10 || skipped != 1 {
		t.Fatalf("%d %d %v", runs, skipped, err)
	}
	if blob, _ := json.Marshal(s.Snapshot().Tenants["a"]); strings.Contains(strings.ToLower(string(blob)), "enterprise") {
		t.Fatal("document text was stored")
	}
	list, _ := s.EDMSets("a")
	if len(list) != 1 || list[0].Kind != "documents" || list[0].Hashes != nil {
		t.Fatalf("%+v", list)
	}
	if _, _, err := s.PutEDMDocuments("a", "empty", []string{"short"}); err == nil {
		t.Fatal("a set with no usable document must be refused")
	}
	if _, _, err := s.PutEDMDocuments("a", "x", make([]string, 21)); err == nil {
		t.Fatal("too many documents accepted")
	}
}

func TestPolicyHistoryIsBoundedAndPersisted(t *testing.T) { // AGT-021 (store)
	p := filepath.Join(t.TempDir(), "s.json")
	s, _ := Open(p)
	s.CreateTenant("a", "A")
	for i := 0; i < PolicyHistoryMax+5; i++ {
		if _, err := s.PutPolicyAs("a", policy.Web, &policy.Policy{DefaultAction: policy.Allow}, i, "bob", ""); err != nil {
			t.Fatal(err)
		}
	}
	vs, _ := s.PolicyVersions("a", policy.Web)
	if len(vs) != PolicyHistoryMax || vs[len(vs)-1].Version != PolicyHistoryMax+5 || vs[0].Version != 6 {
		t.Fatalf("%d versions, first %d last %d", len(vs), vs[0].Version, vs[len(vs)-1].Version)
	}
	if _, err := s.PolicyVersion("a", policy.Web, 1); err != ErrNotFound {
		t.Fatalf("an old version is dropped: %v", err)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if vs2, _ := s2.PolicyVersions("a", policy.Web); len(vs2) != PolicyHistoryMax || vs2[0].By != "bob" {
		t.Fatal("history must survive a restart")
	}
	// a policy saved before history existed still lists its current version
	s3, _ := Open("")
	s3.CreateTenant("a", "A")
	s3.PutPolicy("a", policy.Web, &policy.Policy{DefaultAction: policy.Allow}, 0)
	s3.d.Tenants["a"].PolicyHist = nil
	if vs, _ := s3.PolicyVersions("a", policy.Web); len(vs) != 1 || vs[0].Version != 1 {
		t.Fatalf("%+v", vs)
	}
}
