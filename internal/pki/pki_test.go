package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t *testing.T, ca *CA, role string, ttl time.Duration) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	der, err := ca.Sign(&k.PublicKey, Identity{Tenant: "t1", Subject: "alice", Device: "d1", Role: role}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestIssueAndVerify(t *testing.T) { // PKI-001
	clk := &fakeClock{time.Now()}
	ca, _ := NewCA("t1-ca", clk.now)
	c := issue(t, ca, RoleDevice, DeviceTTL)
	id, err := ca.Verify(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tenant != "t1" || id.Subject != "alice" || id.Device != "d1" || id.Role != RoleDevice {
		t.Fatalf("%+v", id)
	}
	if got := c.NotAfter.Sub(clk.t); got < DeviceTTL-time.Second || got > DeviceTTL+time.Second {
		t.Fatalf("ttl %v", got)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("usage %v", c.ExtKeyUsage)
	}
}

func TestOtherTenantCARejected(t *testing.T) { // PKI-002
	a, _ := NewCA("a", nil)
	b, _ := NewCA("b", nil)
	if _, err := a.Verify(issue(t, b, RoleDevice, time.Hour), nil); err == nil {
		t.Fatal("cert from another CA accepted")
	}
}

func TestExpiryAndTolerance(t *testing.T) { // PKI-003
	clk := &fakeClock{time.Now()}
	ca, _ := NewCA("ca", clk.now)
	c := issue(t, ca, RoleDevice, time.Hour)
	clk.t = c.NotAfter.Add(time.Minute) // inside tolerance
	if _, err := ca.Verify(c, nil); err != nil {
		t.Fatalf("within tolerance: %v", err)
	}
	clk.t = c.NotAfter.Add(3 * time.Minute)
	if _, err := ca.Verify(c, nil); err == nil {
		t.Fatal("expired cert accepted")
	}
	clk.t = time.Now().Add(-time.Hour) // cert not yet valid (clock far behind)
	if _, err := ca.Verify(c, nil); err == nil {
		t.Fatal("not-yet-valid cert accepted")
	}
}

func TestRevocation(t *testing.T) { // PKI-004
	clk := &fakeClock{time.Now()}
	ca, _ := NewCA("ca", clk.now)
	rev := NewRevocations(clk.now)
	c := issue(t, ca, RoleDevice, time.Hour)
	rev.Revoke(c.SerialNumber.String(), c.NotAfter)
	if _, err := ca.Verify(c, rev); err != ErrRevoked {
		t.Fatalf("got %v", err)
	}
	clk.t = c.NotAfter.Add(time.Minute)
	if rev.Prune() != 0 {
		t.Fatal("pruned too early")
	}
	clk.t = c.NotAfter.Add(5 * time.Minute)
	if rev.Prune() != 1 || rev.Len() != 0 {
		t.Fatal("not pruned after expiry")
	}
}

func TestTokens(t *testing.T) { // PKI-005, AG-014
	clk := &fakeClock{time.Now()}
	tk := NewTokens(clk.now, time.Hour)
	tok := tk.Issue("t1", "grp")
	for _, s := range tk.Stored() {
		if strings.Contains(s, tok) {
			t.Fatal("plaintext token stored")
		}
	}
	if tenant, group, err := tk.Redeem(tok); err != nil || tenant != "t1" || group != "grp" {
		t.Fatalf("%v %v %v", tenant, group, err)
	}
	if _, _, err := tk.Redeem(tok); err == nil {
		t.Fatal("second use accepted")
	}
	tok2 := tk.Issue("t1", "grp")
	clk.t = clk.t.Add(61 * time.Minute)
	if _, _, err := tk.Redeem(tok2); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, _, err := tk.Redeem("garbage"); err == nil {
		t.Fatal("unknown token accepted")
	}
}

func TestMalformedSubject(t *testing.T) {
	ca, _ := NewCA("ca", nil)
	k := newKey(t)
	der, _ := ca.Sign(&k.PublicKey, Identity{Tenant: "only", Role: RoleDevice}, time.Hour)
	c, _ := x509.ParseCertificate(der)
	// "only//" splits into three empty-ish parts; subject/device empty is allowed to parse,
	// but a CN with no separators must be rejected:
	c.Subject.CommonName = "noslashes"
	if _, err := ParseIdentity(c); err == nil {
		t.Fatal("malformed subject accepted")
	}
}
