package en

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

func pol(app string) *policy.Policy {
	return &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Rules: []policy.Rule{
		{ID: "r", Priority: 1, Action: policy.Allow, Match: policy.Match{Groups: []string{"g"}, Apps: []string{app}}}}}
}

func seed(t *testing.T) *store.Store {
	st, _ := store.Open("")
	st.CreateTenant("t1", "T")
	st.PutSegment("t1", broker.Segment{ID: "erp", Group: "site1", Targets: []broker.Target{{Host: "h", Ports: []int{1}}}})
	st.UpsertUser("t1", policy.User{Subject: "alice", Groups: []string{"g"}})
	st.PutDevice("t1", store.Device{ID: "d1", User: "alice"})
	if _, err := st.PutPolicy("t1", policy.Private, pol("erp"), 0); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestApplyAndLookups(t *testing.T) {
	s := NewSyncState()
	if !s.Stale() {
		t.Fatal("a never-synced state must be stale")
	}
	s.Apply(seed(t).Snapshot())
	if s.Stale() {
		t.Fatal("stale right after sync")
	}
	if _, ok := s.Segment("t1", "erp"); !ok {
		t.Fatal("segment")
	}
	if _, ok := s.Segment("t2", "erp"); ok {
		t.Fatal("other tenant sees segment")
	}
	if u, ok := s.User("t1", "alice"); !ok || u.Groups[0] != "g" {
		t.Fatal("user")
	}
	d := s.Policy("t1", policy.Private).Evaluate(policy.Request{Kind: policy.Private, App: "erp", User: policy.User{Groups: []string{"g"}}})
	if d.Action != policy.Allow {
		t.Fatalf("%+v", d)
	}
	if s.DeviceRevoked("t1", "d1") {
		t.Fatal("not revoked yet")
	}
}

func TestStaleness(t *testing.T) { // CP-009
	now := time.Now()
	s := NewSyncState()
	s.Now = func() time.Time { return now }
	s.Apply(seed(t).Snapshot())
	now = now.Add(14 * time.Minute)
	if s.Stale() {
		t.Fatal("stale too early")
	}
	now = now.Add(2 * time.Minute)
	if !s.Stale() {
		t.Fatal("not stale after 16 minutes")
	}
	s.Apply(seed(t).Snapshot())
	if s.Stale() {
		t.Fatal("still stale after a successful sync")
	}
}

func TestBadPolicyKeepsPrevious(t *testing.T) { // CP-010 (EN side)
	st := seed(t)
	s := NewSyncState()
	s.Apply(st.Snapshot())
	bad := st.Snapshot()
	bad.Tenants["t1"].Policies[policy.Private] = &policy.Policy{Kind: policy.Private, DefaultAction: policy.Allow} // invalid
	if errs := s.Apply(bad); len(errs) == 0 {
		t.Fatal("expected a compile error")
	}
	p := s.Policy("t1", policy.Private)
	if p == nil || p.Evaluate(policy.Request{Kind: policy.Private, App: "erp", User: policy.User{Groups: []string{"g"}}}).Action != policy.Allow {
		t.Fatal("previous good policy was not kept")
	}
}

func TestDiff(t *testing.T) {
	st := seed(t)
	old := st.Snapshot()
	st.RevokeDevice("t1", "d1")
	st.SetUserDisabled("t1", "alice", true)
	revs, dis := Diff(old, st.Snapshot())
	if len(revs) != 1 || revs[0] != [2]string{"t1", "d1"} || len(dis) != 1 || dis[0] != [2]string{"t1", "alice"} {
		t.Fatalf("%v %v", revs, dis)
	}
	if r, d := Diff(st.Snapshot(), st.Snapshot()); len(r)+len(d) != 0 {
		t.Fatal("no change should give an empty diff")
	}
	if r, d := Diff(nil, st.Snapshot()); len(r) != 1 || len(d) != 1 {
		t.Fatal("first snapshot should report everything already revoked")
	}
}

func TestOnChangeCallback(t *testing.T) {
	st := seed(t)
	s := NewSyncState()
	var got [][2]string
	s.OnChange = func(old, cur *store.Snapshot) { _, got = Diff(old, cur) }
	s.Apply(st.Snapshot())
	st.SetUserDisabled("t1", "alice", true)
	s.Apply(st.Snapshot())
	if len(got) != 1 || got[0][1] != "alice" {
		t.Fatalf("%v", got)
	}
}

// --- poller against a real enrolment server ---

func enKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, base64.StdEncoding.EncodeToString(der)
}

func TestPollerAndENEnrolment(t *testing.T) {
	st := seed(t)
	al, _ := audit.Open(filepath.Join(t.TempDir(), "a"), nil)
	defer al.Close()
	api := &cp.API{Store: st, Audit: al, Tokens: pki.NewTokens(nil, time.Hour), BootstrapToken: "boot"}
	ca, _ := pki.NewCA("ca", nil)
	e := &cp.Enrol{API: api, CA: ca, Rev: pki.NewRevocations(nil)}
	srv := httptest.NewUnstartedServer(e.Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}
	srv.StartTLS()
	defer srv.Close()
	admin := httptest.NewServer(api.Handler())
	defer admin.Close()

	enrol := func(tok string, key string) (int, cp.EnrolResult) {
		b, _ := json.Marshal(map[string]string{"token": tok, "public_key": key})
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		resp, err := cl.Post(srv.URL+"/enrol/en", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out cp.EnrolResult
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &out)
		return resp.StatusCode, out
	}
	issue := func(auth string) (int, string) {
		req, _ := http.NewRequest("POST", admin.URL+"/v1/ens/tokens", bytes.NewReader([]byte(`{"names":["en.local","127.0.0.1"]}`)))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var o struct{ Token string }
		json.NewDecoder(resp.Body).Decode(&o)
		return resp.StatusCode, o.Token
	}
	if c, _ := issue(""); c != 401 {
		t.Fatalf("EN token without bootstrap auth: %d", c)
	}
	if c, _ := issue("wrong"); c != 401 {
		t.Fatalf("EN token with wrong auth: %d", c)
	}
	// a tenant connector token must not work as an EN token
	connTok := api.Tokens.Issue("t1", "site1")
	k, pub := enKey(t)
	if c, _ := enrol(connTok, pub); c != 401 {
		t.Fatalf("connector token accepted as EN token: %d", c)
	}
	code, tok := issue("boot")
	if code != 200 {
		t.Fatal(code)
	}
	code, out := enrol(tok, pub)
	if code != 200 {
		t.Fatalf("EN enrol: %d", code)
	}
	der, _ := base64.StdEncoding.DecodeString(out.Cert)
	leaf, _ := x509.ParseCertificate(der)
	id, err := ca.Verify(leaf, nil)
	if err != nil || id.Role != pki.RoleEN {
		t.Fatalf("%+v %v", id, err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "en.local" || len(leaf.IPAddresses) != 1 {
		t.Fatalf("SANs %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if time.Until(leaf.NotAfter) < 6*24*time.Hour {
		t.Fatal("EN certificate lifetime too short")
	}
	if c, _ := enrol(tok, pub); c != 401 {
		t.Fatal("EN token reused")
	}

	// polling with the EN certificate works; without it, or with a device certificate, it does not
	state := NewSyncState()
	cfg := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	p := &Poller{URL: srv.URL, TLS: cfg, State: state}
	if err := p.Once(); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Segment("t1", "erp"); !ok || state.Stale() {
		t.Fatal("state not populated by poll")
	}
	noCert := &Poller{URL: srv.URL, TLS: &tls.Config{InsecureSkipVerify: true}, State: NewSyncState()}
	if err := noCert.Once(); err == nil {
		t.Fatal("sync allowed without a certificate")
	}
	dk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dder, _ := ca.Sign(&dk.PublicKey, pki.Identity{Tenant: "t1", Subject: "alice", Device: "d1", Role: pki.RoleDevice}, time.Hour)
	devPoller := &Poller{URL: srv.URL, State: NewSyncState(),
		TLS: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{{Certificate: [][]byte{dder}, PrivateKey: dk}}}}
	if err := devPoller.Once(); err == nil {
		t.Fatal("a device certificate may not read the whole state")
	}
}

func TestRefusesPolicyRollback(t *testing.T) { // SEC-007 (partial: replay protection; the policy signature itself is not implemented)
	st := seed(t)
	s := NewSyncState()
	s.Apply(st.Snapshot()) // version 1
	if _, err := st.PutPolicy("t1", policy.Private, pol("erp"), 1); err != nil {
		t.Fatal(err)
	}
	s.Apply(st.Snapshot()) // version 2
	if v := s.Policy("t1", policy.Private).Version; v != 2 {
		t.Fatalf("version %d", v)
	}
	old := seed(t).Snapshot() // an attacker replays a version 1 snapshot
	if errs := s.Apply(old); len(errs) == 0 {
		t.Fatal("rollback was not reported")
	}
	if v := s.Policy("t1", policy.Private).Version; v != 2 {
		t.Fatalf("policy rolled back to version %d", v)
	}
}
