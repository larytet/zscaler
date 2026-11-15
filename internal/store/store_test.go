package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
