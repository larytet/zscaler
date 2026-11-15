package idp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/idp"
	tidp "github.com/larytet/zscaler/test/idp"
)

func setup(t *testing.T) (*tidp.Server, *idp.Verifier) {
	s := tidp.New("client-1")
	t.Cleanup(s.Close)
	return s, &idp.Verifier{Issuer: s.URL, ClientID: "client-1", GroupClaim: "groups"}
}

func TestValidToken(t *testing.T) { // IDP-001
	s, v := setup(t)
	c, err := v.Verify(s.Sign("k1", s.Good("u1", "alice@example.com", "n1", "finance", "all-staff")), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "u1" || c.Email != "alice@example.com" || len(c.Groups) != 2 || c.Groups[0] != "finance" {
		t.Fatalf("%+v", c)
	}
}

func TestCustomGroupClaim(t *testing.T) {
	s, v := setup(t)
	v.GroupClaim = "roles"
	cl := s.Good("u1", "a@x", "n")
	cl["roles"] = []string{"admins"}
	c, err := v.Verify(s.Sign("k1", cl), "n")
	if err != nil || len(c.Groups) != 1 || c.Groups[0] != "admins" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestRSAToken(t *testing.T) {
	s, v := setup(t)
	s.AddRSAKey("r1")
	if _, err := v.Verify(s.Sign("r1", s.Good("u1", "a@x", "n")), "n"); err != nil {
		t.Fatal(err)
	}
}

func TestBadTokens(t *testing.T) { // IDP-002, AG-002
	s, v := setup(t)
	mut := func(f func(c tidp.Claims)) string { c := s.Good("u1", "a@x", "n1"); f(c); return s.Sign("k1", c) }
	past := float64(time.Now().Add(-time.Hour).Unix())
	future := float64(time.Now().Add(time.Hour).Unix())
	good := s.Sign("k1", s.Good("u1", "a@x", "n1"))
	tampered := strings.Split(good, ".")
	tampered[1] = strings.Split(s.Sign("k1", s.Good("admin", "a@x", "n1")), ".")[1]
	for name, tok := range map[string]string{
		"wrong issuer":     mut(func(c tidp.Claims) { c["iss"] = "https://evil" }),
		"wrong audience":   mut(func(c tidp.Claims) { c["aud"] = "other" }),
		"audience list":    mut(func(c tidp.Claims) { c["aud"] = []string{"a", "b"} }),
		"expired":          mut(func(c tidp.Claims) { c["exp"] = past }),
		"missing exp":      mut(func(c tidp.Claims) { delete(c, "exp") }),
		"not yet valid":    mut(func(c tidp.Claims) { c["nbf"] = future }),
		"wrong nonce":      mut(func(c tidp.Claims) { c["nonce"] = "n2" }),
		"missing nonce":    mut(func(c tidp.Claims) { delete(c, "nonce") }),
		"email unverified": mut(func(c tidp.Claims) { c["email_verified"] = false }),
		"no subject":       mut(func(c tidp.Claims) { delete(c, "sub") }),
		"alg none":         s.SignAlg("none", "k1", s.Good("u1", "a@x", "n1")),
		"alg HS256":        s.SignAlg("HS256", "k1", s.Good("u1", "a@x", "n1")),
		"unadvertised key": s.SignUnadvertised("k1", s.Good("u1", "a@x", "n1")),
		"payload tampered": strings.Join(tampered, "."),
		"garbage":          "a.b.c",
		"empty":            "",
		"two parts":        "a.b",
	} {
		if _, err := v.Verify(tok, "n1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := v.Verify(good, ""); err == nil {
		t.Error("empty expected nonce accepted")
	}
	if _, err := v.Verify(good, "n1"); err != nil {
		t.Errorf("good token rejected after bad ones: %v", err)
	}
}

func TestAudienceListContainingClient(t *testing.T) {
	s, v := setup(t)
	cl := s.Good("u1", "a@x", "n")
	cl["aud"] = []string{"other", "client-1"}
	if _, err := v.Verify(s.Sign("k1", cl), "n"); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryTolerance(t *testing.T) {
	s, v := setup(t)
	cl := s.Good("u1", "a@x", "n")
	cl["exp"] = float64(time.Now().Add(-time.Minute).Unix()) // inside 2 min tolerance
	if _, err := v.Verify(s.Sign("k1", cl), "n"); err != nil {
		t.Fatalf("within tolerance: %v", err)
	}
	cl["exp"] = float64(time.Now().Add(-3 * time.Minute).Unix())
	if _, err := v.Verify(s.Sign("k1", cl), "n"); err == nil {
		t.Fatal("beyond tolerance accepted")
	}
}

func TestKeyRotationAndNoRefreshStorm(t *testing.T) { // IDP-003
	s, v := setup(t)
	now := time.Now()
	v.Now = func() time.Time { return now }
	if _, err := v.Verify(s.Sign("k1", s.Good("u1", "a@x", "n")), "n"); err != nil {
		t.Fatal(err)
	}
	base := s.JWKSHits.Load()
	// attacker floods tokens with unknown kids: no more than one refresh per interval
	for i := 0; i < 50; i++ {
		v.Verify(s.SignUnadvertised("evil", s.Good("u", "a@x", "n")), "n")
	}
	if extra := s.JWKSHits.Load() - base; extra > 1 {
		t.Fatalf("%d JWKS fetches for 50 bad tokens", extra)
	}
	// legitimate rotation: new key appears, accepted after the wait
	s.AddKey("k2")
	now = now.Add(11 * time.Second)
	if _, err := v.Verify(s.Sign("k2", s.Good("u1", "a@x", "n")), "n"); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	// old key removed: tokens signed with it fail after refresh
	s.RemoveKey("k1")
	now = now.Add(11 * time.Second)
	v.Verify(s.Sign("k2", s.Good("u1", "a@x", "n")), "n")
	if _, err := v.Verify(s.SignUnadvertised("k1", s.Good("u1", "a@x", "n")), "n"); err == nil {
		t.Fatal("forged token with old kid accepted")
	}
}

func TestUnreachableIdP(t *testing.T) {
	s, v := setup(t)
	tok := s.Sign("k1", s.Good("u1", "a@x", "n"))
	s.Close()
	if _, err := v.Verify(tok, "n"); err == nil {
		t.Fatal("token accepted with IdP down and no cached keys")
	}
}
