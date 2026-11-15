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
	"github.com/larytet/zscaler/internal/signed"
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
	"github.com/larytet/zscaler/internal/tenancy"
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
	signer, _ := pki.LoadOrCreateSigner(t.TempDir())
	e := &cp.Enrol{API: api, CA: ca, Rev: pki.NewRevocations(nil), PolicyKey: signer}
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
	p := &Poller{URL: srv.URL, TLS: cfg, State: state, PolicyPub: &signer.PublicKey}
	if err := p.Once(); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Segment("t1", "erp"); !ok || state.Stale() {
		t.Fatal("state not populated by poll")
	}
	noCert := &Poller{URL: srv.URL, TLS: &tls.Config{InsecureSkipVerify: true}, State: NewSyncState(), PolicyPub: &signer.PublicKey}
	if err := noCert.Once(); err == nil {
		t.Fatal("sync allowed without a certificate")
	}
	dk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dder, _ := ca.Sign(&dk.PublicKey, pki.Identity{Tenant: "t1", Subject: "alice", Device: "d1", Role: pki.RoleDevice}, time.Hour)
	devPoller := &Poller{URL: srv.URL, State: NewSyncState(),
		PolicyPub: &signer.PublicKey,
		TLS:       &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{{Certificate: [][]byte{dder}, PrivateKey: dk}}}}
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

func TestPollerRefusesUnsignedAndTamperedState(t *testing.T) { // SEC-007
	st := seed(t)
	signer, _ := pki.LoadOrCreateSigner(t.TempDir())
	attacker, _ := pki.LoadOrCreateSigner(t.TempDir())
	var mode string
	var last []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(st.Snapshot())
		switch mode {
		case "good":
			env, _ := signed.Sign(signer, time.Now().UnixNano(), time.Now(), payload)
			last, _ = json.Marshal(env)
			w.Write(last)
		case "replay":
			w.Write(last)
		case "forged":
			env, _ := signed.Sign(attacker, time.Now().UnixNano(), time.Now(), payload)
			json.NewEncoder(w).Encode(env)
		case "tampered":
			env, _ := signed.Sign(signer, time.Now().UnixNano(), time.Now(), payload)
			env.Payload = bytes.Replace(env.Payload, []byte(`"Disabled":false`), []byte(`"Disabled":true`), -1)
			json.NewEncoder(w).Encode(env)
		case "unsigned":
			w.Write(payload)
		}
	}))
	defer srv.Close()
	state := NewSyncState()
	p := &Poller{URL: srv.URL, State: state, PolicyPub: &signer.PublicKey}
	mode = "good"
	if err := p.Once(); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Segment("t1", "erp"); !ok {
		t.Fatal("good state not applied")
	}
	for _, m := range []string{"replay", "forged", "tampered", "unsigned"} {
		fresh := NewSyncState()
		q := &Poller{URL: srv.URL, State: fresh, PolicyPub: &signer.PublicKey, lastSeq: p.lastSeq}
		mode = m
		if err := q.Once(); err == nil {
			t.Errorf("%s state was accepted", m)
		}
		if _, ok := fresh.Segment("t1", "erp"); ok {
			t.Errorf("%s state was applied", m)
		}
	}
	// a poller with no pinned key applies nothing at all
	mode = "good"
	none := &Poller{URL: srv.URL, State: NewSyncState()}
	if err := none.Once(); err == nil || none.State.Stale() == false {
		t.Fatal("a poller without a pinned key must refuse state")
	}
}

func TestInspectionReachesENAndBadCAStaysOff(t *testing.T) {
	st := seed(t)
	st.SetInspection("t1", true, []string{"bank.example"})
	s := NewSyncState()
	if errs := s.Apply(st.Snapshot()); len(errs) != 0 {
		t.Fatal(errs)
	}
	on, exempt, ca := s.Inspection("t1")
	if !on || ca == nil || len(exempt) != 1 {
		t.Fatalf("%v %v %v", on, exempt, ca)
	}
	k, _ := enKey(t)
	if _, err := ca.SignServer(&k.PublicKey, "example.com", time.Hour); err != nil {
		t.Fatalf("the EN's copy of the CA cannot sign: %v", err)
	}
	if on, _, _ := s.Inspection("nobody"); on {
		t.Fatal("unknown tenant inspected")
	}
	snap := st.Snapshot()
	snap.Tenants["t1"].Inspect.CAKey = "not a key"
	s2 := NewSyncState()
	if errs := s2.Apply(snap); len(errs) == 0 {
		t.Fatal("a broken intercept CA must be reported")
	}
	if on, _, _ := s2.Inspection("t1"); on {
		t.Fatal("inspection must stay OFF when the CA is unusable (fail open to an opaque tunnel, never to a bad certificate)")
	}
}

func TestTenancyRestrictionReachesTheNode(t *testing.T) { // AGT-024 (DATA-002a)
	st := seed(t)
	st.CreateTenant("t2", "Other")
	cfg := tenancy.Config{Slack: &tenancy.Slack{Allowed: []string{"T01ABCDEF"}}}
	if err := st.SetTenancy("t1", &cfg); err != nil {
		t.Fatal(err)
	}
	s := NewSyncState()
	if errs := s.Apply(st.Snapshot()); len(errs) > 0 {
		t.Fatal(errs)
	}
	if v, hs := s.TenancyHeaders("t1", "acme.slack.com"); v != "slack" || len(hs) != 2 {
		t.Fatalf("%q %v", v, hs)
	}
	if v, _ := s.TenancyHeaders("t1", "example.com"); v != "" {
		t.Fatal("an unrelated host was restricted")
	}
	if v, _ := s.TenancyHeaders("t2", "acme.slack.com"); v != "" {
		t.Fatal("tenant isolation: another tenant's restriction applies")
	}
	if v, _ := s.TenancyHeaders("nope", "acme.slack.com"); v != "" {
		t.Fatal("an unknown tenant was restricted")
	}
	// removing the restriction removes it at the node
	st.SetTenancy("t1", nil)
	s.Apply(st.Snapshot())
	if v, _ := s.TenancyHeaders("t1", "acme.slack.com"); v != "" {
		t.Fatal("the restriction outlived its removal")
	}
}
