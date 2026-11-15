package cp

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
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
	tidp "github.com/larytet/zscaler/test/idp"
)

type enrolEnv struct {
	*env
	ca   *pki.CA
	idp  *tidp.Server
	en   *httptest.Server
	rev  *pki.Revocations
	tenA string
}

func newEnrolEnv(t *testing.T) *enrolEnv {
	e := newEnv(t)
	ca, _ := pki.NewCA("ca", nil)
	rev := pki.NewRevocations(nil)
	ip := tidp.New("cid")
	t.Cleanup(ip.Close)
	if c, b, _ := e.call("PUT", "/v1/idp", e.adminA, map[string]string{"issuer": ip.URL, "client_id": "cid"}); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	en := &Enrol{API: e.api, CA: ca, Rev: rev}
	srv := httptest.NewUnstartedServer(en.Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &enrolEnv{env: e, ca: ca, idp: ip, en: srv, rev: rev, tenA: "a"}
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, base64.StdEncoding.EncodeToString(der)
}

func (e *enrolEnv) post(path string, body any, cert *tls.Certificate) (int, []byte) {
	e.t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true} // test server uses a throwaway cert
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	b, _ := json.Marshal(body)
	resp, err := cl.Post(e.en.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *enrolEnv) get(path string, cert *tls.Certificate) (int, []byte) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := cl.Get(e.en.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *enrolEnv) enrolDevice(t *testing.T, sub string, groups ...string) (certOut, *ecdsa.PrivateKey, string, int, []byte) {
	k, pub := newKey(t)
	tok := e.idp.Sign("k1", e.idp.Good(sub, sub+"@example.com", "n1", groups...))
	code, b := e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": tok, "nonce": "n1", "public_key": pub}, nil)
	var out certOut
	json.Unmarshal(b, &out)
	return out, k, pub, code, b
}

func tlsCert(t *testing.T, o certOut, k *ecdsa.PrivateKey) *tls.Certificate {
	der, _ := base64.StdEncoding.DecodeString(o.Cert)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestDeviceEnrolment(t *testing.T) { // AG-001
	e := newEnrolEnv(t)
	out, _, _, code, b := e.enrolDevice(t, "u1", "finance")
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	der, _ := base64.StdEncoding.DecodeString(out.Cert)
	c, _ := x509.ParseCertificate(der)
	id, err := e.ca.Verify(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tenant != "a" || id.Subject != "u1" || id.Role != pki.RoleDevice || id.Device != out.DeviceID {
		t.Fatalf("%+v", id)
	}
	if ttl := time.Until(c.NotAfter); ttl > pki.DeviceTTL+time.Minute || ttl < pki.DeviceTTL-time.Minute {
		t.Fatalf("ttl %v", ttl)
	}
	if !strings.Contains(out.CA, "BEGIN CERTIFICATE") {
		t.Fatal("no CA in response")
	}
	u, ok := e.api.Store.User("a", "u1")
	if !ok || u.Email != "u1@example.com" || len(u.Groups) != 1 {
		t.Fatalf("user not created: %+v", u)
	}
	if devs, _ := e.api.Store.Devices("a"); len(devs) != 1 || devs[0].Serial != c.SerialNumber.String() {
		t.Fatalf("device not registered: %+v", devs)
	}
}

func TestEnrolmentBadTokens(t *testing.T) { // AG-002
	e := newEnrolEnv(t)
	_, pub := newKey(t)
	cases := map[string]tidp.Claims{}
	g := func() tidp.Claims { return e.idp.Good("u1", "u1@example.com", "n1") }
	c1 := g()
	c1["aud"] = "other"
	cases["wrong aud"] = c1
	c2 := g()
	c2["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	cases["expired"] = c2
	c3 := g()
	c3["nonce"] = "other"
	cases["wrong nonce"] = c3
	c4 := g()
	c4["email_verified"] = false
	cases["unverified"] = c4
	for name, cl := range cases {
		code, _ := e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": e.idp.Sign("k1", cl), "nonce": "n1", "public_key": pub}, nil)
		if code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	code, _ := e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": e.idp.SignUnadvertised("k1", g()), "nonce": "n1", "public_key": pub}, nil)
	if code != 401 {
		t.Errorf("forged: %d", code)
	}
	if users, _ := e.api.Store.Users("a"); len(users) != 0 {
		t.Fatal("a failed enrolment created a user")
	}
	// unknown tenant gives the same answer as a bad token
	code, _ = e.post("/enrol/device", map[string]string{"tenant": "nope", "id_token": "x", "nonce": "n", "public_key": pub}, nil)
	if code != 401 {
		t.Errorf("unknown tenant: %d", code)
	}
	// tenant b has no IdP configured
	code, _ = e.post("/enrol/device", map[string]string{"tenant": "b", "id_token": e.idp.Sign("k1", g()), "nonce": "n1", "public_key": pub}, nil)
	if code != 401 {
		t.Errorf("tenant without idp: %d", code)
	}
	code, _ = e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": e.idp.Sign("k1", g()), "nonce": "n1", "public_key": "!!"}, nil)
	if code != 400 {
		t.Errorf("bad key: %d", code)
	}
}

func TestGroupsRefreshOnRelogin(t *testing.T) { // AG-004
	e := newEnrolEnv(t)
	e.enrolDevice(t, "u1", "finance")
	e.enrolDevice(t, "u1", "hr")
	u, _ := e.api.Store.User("a", "u1")
	if len(u.Groups) != 1 || u.Groups[0] != "hr" {
		t.Fatalf("groups %v", u.Groups)
	}
}

func TestDisabledUserCannotEnrolOrRenew(t *testing.T) { // AG-005
	e := newEnrolEnv(t)
	out, k, pub, code, _ := e.enrolDevice(t, "u1", "finance")
	if code != 200 {
		t.Fatal(code)
	}
	e.api.Store.SetUserDisabled("a", "u1", true)
	if c, _ := e.post("/enrol/renew", map[string]string{"public_key": pub}, tlsCert(t, out, k)); c != 403 {
		t.Errorf("renew by disabled user: %d", c)
	}
	_, _, _, code, _ = e.enrolDevice(t, "u1", "finance")
	if code != 403 {
		t.Errorf("enrol by disabled user: %d", code)
	}
	u, _ := e.api.Store.User("a", "u1")
	if !u.Disabled {
		t.Error("login re-enabled the user")
	}
}

func TestRenewAndRevoked(t *testing.T) { // AG-006, AG-007 server side
	e := newEnrolEnv(t)
	out, k, pub, _, _ := e.enrolDevice(t, "u1", "finance")
	code, b := e.post("/enrol/renew", map[string]string{"public_key": pub}, tlsCert(t, out, k))
	if code != 200 {
		t.Fatalf("renew %d %s", code, b)
	}
	var out2 certOut
	json.Unmarshal(b, &out2)
	if out2.DeviceID != out.DeviceID || out2.Cert == out.Cert {
		t.Fatal("renewal should keep the device id and issue a new cert")
	}
	// wrong key
	_, otherPub := newKey(t)
	if c, _ := e.post("/enrol/renew", map[string]string{"public_key": otherPub}, tlsCert(t, out, k)); c != 403 {
		t.Errorf("renew with another key: %d", c)
	}
	// no certificate
	if c, _ := e.post("/enrol/renew", map[string]string{"public_key": pub}, nil); c != 401 {
		t.Errorf("renew without cert: %d", c)
	}
	// revoked device
	der, _ := base64.StdEncoding.DecodeString(out2.Cert)
	c2, _ := x509.ParseCertificate(der)
	e.rev.Revoke(c2.SerialNumber.String(), c2.NotAfter)
	if c, _ := e.post("/enrol/renew", map[string]string{"public_key": pub}, tlsCert(t, out2, k)); c != 401 {
		t.Errorf("renew with revoked cert: %d", c)
	}
	// admin revoked the device in the store: re-login must also fail
	e.api.Store.RevokeDevice("a", out.DeviceID)
	tok := e.idp.Sign("k1", e.idp.Good("u1", "u1@example.com", "n1"))
	if c, _ := e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": tok, "nonce": "n1", "public_key": pub}, nil); c != 403 {
		t.Errorf("re-enrol of revoked device: %d", c)
	}
}

func TestConnectorEnrolment(t *testing.T) { // AG-014
	e := newEnrolEnv(t)
	issue := func() string {
		c, b, _ := e.call("POST", "/v1/connectors/tokens", e.adminA, map[string]string{"group": "site1"})
		if c != 200 {
			t.Fatalf("%d %s", c, b)
		}
		var o struct{ Token string }
		json.Unmarshal(b, &o)
		return o.Token
	}
	tok := issue()
	k, pub := newKey(t)
	code, b := e.post("/enrol/connector", map[string]string{"token": tok, "name": "c1", "public_key": pub}, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var out certOut
	json.Unmarshal(b, &out)
	der, _ := base64.StdEncoding.DecodeString(out.Cert)
	c, _ := x509.ParseCertificate(der)
	id, err := e.ca.Verify(c, nil)
	if err != nil || id.Role != pki.RoleConnector || id.Tenant != "a" || id.Subject != "site1" || id.Device != "c1" {
		t.Fatalf("%+v %v", id, err)
	}
	// second use of the token
	if code, _ := e.post("/enrol/connector", map[string]string{"token": tok, "name": "c2", "public_key": pub}, nil); code != 401 {
		t.Errorf("reused token: %d", code)
	}
	// garbage token
	if code, _ := e.post("/enrol/connector", map[string]string{"token": "junk", "public_key": pub}, nil); code != 401 {
		t.Errorf("junk token: %d", code)
	}
	// tenant cannot be chosen by the caller
	if code, _ := e.post("/enrol/connector", map[string]string{"token": issue(), "public_key": pub, "tenant": "b"}, nil); code != 400 {
		t.Errorf("unknown field tenant accepted: %d", code)
	}
	// targets: only the caller's group
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "site1", "targets": []broker.Target{{Host: "10.0.0.5", Ports: []int{5432}}}})
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "other", "group": "site2", "targets": []broker.Target{{Host: "10.9.9.9", Ports: []int{22}}}})
	code, b = e.get("/enrol/targets", tlsCert(t, out, k))
	if code != 200 || !strings.Contains(string(b), "10.0.0.5") || strings.Contains(string(b), "10.9.9.9") {
		t.Fatalf("targets %d %s", code, b)
	}
	if code, _ := e.get("/enrol/targets", nil); code != 401 {
		t.Errorf("targets without cert: %d", code)
	}
	// a device cert cannot read connector targets
	dev, dk, _, _, _ := e.enrolDevice(t, "u1")
	if code, _ := e.get("/enrol/targets", tlsCert(t, dev, dk)); code != 401 {
		t.Errorf("device read targets: %d", code)
	}
}

func TestConnectorTokenExpires(t *testing.T) {
	e := newEnrolEnv(t)
	clk := &struct{ t time.Time }{time.Now()}
	e.api.Tokens = pki.NewTokens(func() time.Time { return clk.t }, time.Hour)
	tok := e.api.Tokens.Issue("a", "site1")
	clk.t = clk.t.Add(61 * time.Minute)
	_, pub := newKey(t)
	if code, _ := e.post("/enrol/connector", map[string]string{"token": tok, "public_key": pub}, nil); code != 401 {
		t.Fatalf("expired token: %d", code)
	}
}

func TestRenewRefusedWhenAdminRevoked(t *testing.T) {
	e := newEnrolEnv(t)
	out, k, pub, _, _ := e.enrolDevice(t, "u1", "finance")
	e.api.Store.RevokeDevice("a", out.DeviceID)
	if c, _ := e.post("/enrol/renew", map[string]string{"public_key": pub}, tlsCert(t, out, k)); c != 403 {
		t.Fatalf("renewal of an admin-revoked device: %d", c)
	}
}

func enCert(t *testing.T, e *enrolEnv) *tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := e.ca.Sign(&k.PublicKey, pki.Identity{Tenant: "platform", Subject: "en", Device: "en1", Role: pki.RoleEN}, time.Hour, "en.local")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestIngestAndAlertsEndpoint(t *testing.T) {
	e := newEnrolEnv(t)
	e.api.Alerts = alerts.New()
	recs := []broker.Record{}
	for i := 0; i < 10; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "u1", App: "erp"})
	}
	if c, _ := e.post("/ingest/records", recs, nil); c != 401 {
		t.Fatalf("ingest without a certificate: %d", c)
	}
	dev, dk, _, _, _ := e.enrolDevice(t, "u1")
	if c, _ := e.post("/ingest/records", recs, tlsCert(t, dev, dk)); c != 401 {
		t.Fatalf("a device certificate may not ingest: %d", c)
	}
	if c, b := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatalf("ingest: %d %s", c, b)
	}
	if c, _ := e.post("/ingest/records", make([]broker.Record, 5001), enCert(t, e)); c != 400 {
		t.Fatalf("oversize batch accepted: %d", c)
	}
	code, b, _ := e.call("GET", "/v1/alerts?open=1", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), "repeated-denies") || !strings.Contains(string(b), "recommended_action") {
		t.Fatalf("alerts: %d %s", code, b)
	}
	code, b, _ = e.call("GET", "/v1/alerts", e.adminB, nil)
	if code != 200 || strings.Contains(string(b), "repeated-denies") {
		t.Fatalf("tenant b sees tenant a alerts: %s", b)
	}
}

func TestDecisionSearch(t *testing.T) {
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	recs := []broker.Record{
		{Tenant: "a", Kind: "private", Action: "allow", Event: "open", User: "u1", App: "erp", TS: time.Now()},
		{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "u2", App: "erp", Rule: "r1", TS: time.Now()},
		{Tenant: "b", Kind: "private", Action: "deny", Event: "open", User: "x", App: "secret", TS: time.Now()},
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	code, b, _ := e.call("GET", "/v1/decisions?action=deny", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), `"u2"`) || strings.Contains(string(b), `"u1"`) || strings.Contains(string(b), "secret") {
		t.Fatalf("%d %s", code, b)
	}
	if _, b, _ = e.call("GET", "/v1/decisions", e.adminB, nil); strings.Contains(string(b), `"u1"`) || !strings.Contains(string(b), "secret") {
		t.Fatalf("tenant isolation: %s", b)
	}
	if code, _, _ = e.call("GET", "/v1/decisions?since=yesterday", e.adminA, nil); code != 400 {
		t.Fatalf("bad since accepted: %d", code)
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if code, _, _ = e.call("GET", "/v1/decisions?user=u1", viewer, nil); code != 200 {
		t.Fatalf("viewer: %d", code)
	}
}

func TestDigestEndpoint(t *testing.T) {
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	e.api.Alerts = alerts.New()
	now := time.Now()
	var recs []broker.Record
	for i := 0; i < 6; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "u1", App: "erp", TS: now})
	}
	recs = append(recs, broker.Record{Tenant: "a", Kind: "web", Action: "deny", Event: "open", User: "u1", TS: now},
		broker.Record{Tenant: "b", Kind: "private", Action: "deny", Event: "open", User: "zz", App: "secret", TS: now})
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	code, b, _ := e.call("GET", "/v1/digest?days=7", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), `"private_sessions_denied":6`) || !strings.Contains(string(b), `"web_requests_blocked":1`) || strings.Contains(string(b), "secret") {
		t.Fatalf("%d %s", code, b)
	}
	_, txt, _ := e.call("GET", "/v1/digest?format=text", e.adminA, nil)
	if !strings.Contains(string(txt), "What to do this week") || !strings.Contains(string(txt), "u1 was blocked 6 times from erp") {
		t.Fatalf("%s", txt)
	}
	_, other, _ := e.call("GET", "/v1/digest", e.adminB, nil)
	if strings.Contains(string(other), `"u1"`) || !strings.Contains(string(other), `"private_sessions_denied":1`) {
		t.Fatalf("tenant b must see only its own activity: %s", other)
	}
}

func TestSimulateEndpoint(t *testing.T) {
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	now := time.Now()
	var recs []broker.Record
	for i := 0; i < 3; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "bob", App: "erp", Groups: []string{"hr"}, TS: now})
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	draft := map[string]any{"policy": map[string]any{"default_action": "deny", "rules": []map[string]any{{
		"id": "hr-erp", "priority": 1, "action": "allow", "match": map[string]any{"groups": []string{"hr"}, "apps": []string{"erp"}}}}}}
	code, b, _ := e.call("POST", "/v1/policies/private/simulate", e.adminA, draft)
	if code != 200 || !strings.Contains(string(b), `"newly_allowed":3`) || !strings.Contains(string(b), `"draft_rule":"hr-erp"`) {
		t.Fatalf("%d %s", code, b)
	}
	if c, _, _ := e.call("GET", "/v1/policies/private", e.adminA, nil); c != 404 {
		t.Fatal("simulation stored the draft")
	}
	if code, _, _ := e.call("POST", "/v1/policies/web/simulate", e.adminA, draft); code != 400 {
		t.Fatalf("web simulation should be refused: %d", code)
	}
	if code, _, _ := e.call("POST", "/v1/policies/private/simulate", e.adminA, map[string]any{}); code != 400 {
		t.Fatalf("missing draft: %d", code)
	}
	bad := map[string]any{"policy": map[string]any{"default_action": "allow", "rules": []any{}}}
	if code, _, _ := e.call("POST", "/v1/policies/private/simulate", e.adminA, bad); code != 400 {
		t.Fatalf("invalid draft accepted: %d", code)
	}
	// tenant b has no history and must not see a's decisions replayed
	_, bb, _ := e.call("POST", "/v1/policies/private/simulate", e.adminB, draft)
	if strings.Contains(string(bb), `"newly_allowed":3`) {
		t.Fatalf("tenant isolation: %s", bb)
	}
}

func TestSuggestionsAndInvestigate(t *testing.T) {
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	now := time.Now()
	var recs []broker.Record
	good := &broker.PostureSnap{DiskEncrypted: ptrTrue(), FirewallOn: ptrTrue()}
	for i := 0; i < 4; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "bob", App: "erp", Groups: []string{"hr"}, Posture: good, TS: now})
	}
	recs = append(recs, broker.Record{Tenant: "b", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "bob", App: "secret", Groups: []string{"x"}, Posture: good, TS: now})
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	code, b, _ := e.call("GET", "/v1/suggestions", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), `"hr"`) || !strings.Contains(string(b), `"erp"`) || strings.Contains(string(b), "secret") {
		t.Fatalf("%d %s", code, b)
	}
	code, b, _ = e.call("GET", "/v1/investigate?user=bob", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), "blocked 4 of 4 times") || strings.Contains(string(b), "secret") {
		t.Fatalf("%d %s", code, b)
	}
	if code, _, _ = e.call("GET", "/v1/investigate", e.adminA, nil); code != 400 {
		t.Fatalf("user is required: %d", code)
	}
	_, b, _ = e.call("GET", "/v1/investigate?user=bob", e.adminB, nil)
	if strings.Contains(string(b), "erp") || !strings.Contains(string(b), "blocked 1 of 1") {
		t.Fatalf("tenant b sees only its own: %s", b)
	}
}

func ptrTrue() *bool { b := true; return &b }

func TestRiskScoresFlowToStateAndPolicy(t *testing.T) { // ARCH-007
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	e.api.Alerts = alerts.New()
	e.api.Store.UpsertUser("a", policy.User{Subject: "u1", Groups: []string{"g"}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "u2", Groups: []string{"g"}})
	now := time.Now()
	var recs []broker.Record
	for i := 0; i < 10; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Event: "open", Action: "deny", User: "u1", App: "erp", TS: now})
	}
	recs = append(recs, broker.Record{Tenant: "a", Kind: "posture", Action: "pass", User: "u1", Device: "d1"},
		broker.Record{Tenant: "a", Kind: "posture", Action: "fail", Reason: "disk encryption is off", User: "u1", Device: "d1"})
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	e.api.RefreshRisk()
	u1, _ := e.api.Store.User("a", "u1")
	u2, _ := e.api.Store.User("a", "u2")
	if u1.Risk != 70 || u2.Risk != 0 {
		t.Fatalf("u1 risk %d (want 70: posture 40 + many denies 30), u2 risk %d", u1.Risk, u2.Risk)
	}
	// the score reaches enforcement nodes in the snapshot, so a rule can use it
	for _, u := range e.api.Store.Snapshot().Tenants["a"].Users {
		if u.Subject == "u1" && u.Risk != 70 {
			t.Fatalf("snapshot lost the risk score: %+v", u)
		}
	}
	min := 70
	p := &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Rules: []policy.Rule{
		{ID: "high-risk", Priority: 1, Action: policy.Deny, Match: policy.Match{MinRisk: &min}},
		{ID: "ok", Priority: 2, Action: policy.Allow, Match: policy.Match{Groups: []string{"g"}}}}}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(policy.Request{Kind: policy.Private, User: u1}); d.RuleID != "high-risk" {
		t.Fatalf("%+v", d)
	}
	if d := p.Evaluate(policy.Request{Kind: policy.Private, User: u2}); d.RuleID != "ok" {
		t.Fatalf("%+v", d)
	}
	code, b, _ := e.call("GET", "/v1/risk", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), `"score":70`) || !strings.Contains(string(b), "below the security baseline") {
		t.Fatalf("%d %s", code, b)
	}
	if _, b, _ = e.call("GET", "/v1/risk", e.adminB, nil); strings.Contains(string(b), "u1") {
		t.Fatalf("tenant isolation: %s", b)
	}
}
