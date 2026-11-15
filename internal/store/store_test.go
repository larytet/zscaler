package store

import (
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
