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
	"fmt"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/captures"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/incidents"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestApprovalEndpoints(t *testing.T) { // ZPA-027
	e := newEnrolEnv(t)
	e.api.Approvals = approvals.New()
	var notified atomic.Int64
	e.api.OnApprovalRequest = func(approvals.Request) { notified.Add(1) }
	rec := broker.Record{Tenant: "a", Kind: "private", Event: "open", Action: "deny", Reason: "approval-required", Rule: "jit", User: "alice", App: "erp", TS: time.Now()}
	other := rec
	other.Reason = "default" // an ordinary denial must not open a request
	if c, _ := e.post("/ingest/records", []broker.Record{rec, rec, rec, other}, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	time.Sleep(100 * time.Millisecond)
	code, b, _ := e.call("GET", "/v1/approvals?state=pending", e.adminA, nil)
	var list []approvals.Request
	json.Unmarshal(b, &list)
	if code != 200 || len(list) != 1 || list[0].Attempts != 3 || list[0].User != "alice" || notified.Load() != 1 {
		t.Fatalf("%d %s notified=%d", code, b, notified.Load())
	}
	id := fmt.Sprint(list[0].ID)
	if _, b, _ := e.call("GET", "/v1/approvals", e.adminB, nil); strings.Contains(string(b), "alice") {
		t.Fatalf("tenant b sees tenant a's requests: %s", b)
	}
	if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/approve", e.adminB, nil); c != 404 {
		t.Fatalf("tenant b approved tenant a's request: %d", c)
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/approve", viewer, nil); c != 403 {
		t.Fatalf("viewer approved: %d", c)
	}
	for _, bad := range []int{-5, 481, 100000} { // 0 means "use the default", so it is not an error
		if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/approve", e.adminA, map[string]int{"minutes": bad}); c != 400 {
			t.Errorf("minutes=%d accepted: %d", bad, c)
		}
	}
	if e.api.Store.Granted("a", "alice", "erp", time.Now()) {
		t.Fatal("a rejected approval created a grant")
	}
	if c, b, _ := e.call("POST", "/v1/approvals/"+id+"/approve", e.adminA, map[string]int{"minutes": 30}); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	if !e.api.Store.Granted("a", "alice", "erp", time.Now()) || e.api.Store.Granted("a", "alice", "erp", time.Now().Add(31*time.Minute)) {
		t.Fatal("grant missing or too long")
	}
	if e.api.Store.Granted("b", "alice", "erp", time.Now()) {
		t.Fatal("grant leaked to another tenant")
	}
	if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/approve", e.adminA, nil); c != 409 {
		t.Fatalf("approved twice: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/deny", e.adminA, nil); c != 409 {
		t.Fatalf("denied after approving: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/approvals/"+id+"/end", e.adminA, nil); c != 200 || e.api.Store.Granted("a", "alice", "erp", time.Now()) {
		t.Fatal("end did not remove the grant")
	}
	if c, _, _ := e.call("POST", "/v1/approvals/999/approve", e.adminA, nil); c != 404 {
		t.Fatalf("unknown id: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/approvals/abc/approve", e.adminA, nil); c != 404 {
		t.Fatalf("bad id: %d", c)
	}
	_, b, _ = e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(b), "access.approve") || !strings.Contains(string(b), "access.end") {
		t.Fatalf("not audited: %s", b)
	}
	// a second request can be denied
	e.post("/ingest/records", []broker.Record{rec}, enCert(t, e))
	_, b, _ = e.call("GET", "/v1/approvals?state=pending", e.adminA, nil)
	json.Unmarshal(b, &list)
	if len(list) != 1 {
		t.Fatalf("a new attempt after a decision should open a new request: %s", b)
	}
	if c, _, _ := e.call("POST", "/v1/approvals/"+fmt.Sprint(list[0].ID)+"/deny", e.adminA, nil); c != 200 || e.api.Store.Granted("a", "alice", "erp", time.Now()) {
		t.Fatal("deny must not create a grant")
	}
}

func TestHealthEndpoint(t *testing.T) { // DEX-003
	e := newEnrolEnv(t)
	e.api.Health = devhealth.New()
	disk := 96
	recs := []broker.Record{
		{Tenant: "a", Kind: "health", User: "alice", Device: "d1", Health: &devhealth.Snapshot{DiskUsedPct: &disk}},
		{Tenant: "b", Kind: "health", User: "eve", Device: "d9", Health: &devhealth.Snapshot{DiskUsedPct: &disk}},
		{Tenant: "a", Kind: "health", User: "bob", Device: "d2"}, // no numbers: ignored
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	code, b, _ := e.call("GET", "/v1/health", e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), "alice's disk is 96% full") || strings.Contains(string(b), "eve") || strings.Contains(string(b), `"bob"`) {
		t.Fatalf("%d %s", code, b)
	}
	if _, b, _ = e.call("GET", "/v1/health", e.adminB, nil); strings.Contains(string(b), "alice") {
		t.Fatalf("tenant isolation: %s", b)
	}
}

func TestAIAgentLifecycle(t *testing.T) { // AI-001, AI-002
	e := newEnrolEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "wiki", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{2}}}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice", Email: "alice@example.com", Groups: []string{"finance"}})
	create := func(body map[string]any) (int, map[string]any) {
		c, b, _ := e.call("POST", "/v1/ai-agents", e.adminA, body)
		var out map[string]any
		json.Unmarshal(b, &out)
		return c, out
	}
	for name, body := range map[string]map[string]any{
		"bad name":          {"name": "Bad Name!", "operator": "alice", "apps": []string{"erp"}},
		"no apps":           {"name": "bot", "operator": "alice", "apps": []string{}},
		"unknown app":       {"name": "bot", "operator": "alice", "apps": []string{"ghost"}},
		"unknown operator":  {"name": "bot", "operator": "nobody", "apps": []string{"erp"}},
		"too long":          {"name": "bot", "operator": "alice", "apps": []string{"erp"}, "minutes": 5000},
		"agent as operator": {"name": "bot", "operator": "agent:other", "apps": []string{"erp"}},
	} {
		if c, _ := create(body); c != 400 {
			t.Errorf("%s accepted: %d", name, c)
		}
	}
	code, out := create(map[string]any{"name": "code-helper", "operator": "alice", "apps": []string{"erp"}, "minutes": 30})
	if code != 200 || out["agent"] != "agent:code-helper" || out["operator"] != "alice" {
		t.Fatalf("%d %v", code, out)
	}
	tok := out["enrolment_token"].(string)
	// the identity exists, is in the ai-agent group only, and holds a grant for exactly the listed app
	u, ok := e.api.Store.User("a", "agent:code-helper")
	if !ok || len(u.Groups) != 1 || u.Groups[0] != AIAgentGroup || !strings.Contains(u.Email, "alice") {
		t.Fatalf("%+v", u)
	}
	if !e.api.Store.Granted("a", "agent:code-helper", "erp", time.Now()) || e.api.Store.Granted("a", "agent:code-helper", "wiki", time.Now()) {
		t.Fatal("grant must cover exactly the listed apps")
	}
	if e.api.Store.Granted("a", "agent:code-helper", "erp", time.Now().Add(31*time.Minute)) {
		t.Fatal("grant outlived its time limit")
	}
	// the token is single-use, and it enrols a device cert whose subject is the agent
	_, pub := newKey(t)
	c, b := e.post("/enrol/service", map[string]string{"token": tok, "public_key": pub}, nil)
	var cert certOut
	json.Unmarshal(b, &cert)
	if c != 200 || cert.Cert == "" {
		t.Fatalf("%d %s", c, b)
	}
	der, _ := base64.StdEncoding.DecodeString(cert.Cert)
	leaf, _ := x509.ParseCertificate(der)
	id, err := e.ca.Verify(leaf, nil)
	if err != nil || id.Subject != "agent:code-helper" || id.Role != pki.RoleDevice || id.Tenant != "a" {
		t.Fatalf("%+v %v", id, err)
	}
	if c, _ := e.post("/enrol/service", map[string]string{"token": tok, "public_key": pub}, nil); c != 401 {
		t.Fatalf("service token reused: %d", c)
	}
	// tenant isolation and roles
	if _, b, _ := e.call("GET", "/v1/ai-agents", e.adminB, nil); strings.Contains(string(b), "code-helper") {
		t.Fatalf("tenant b sees tenant a's agents: %s", b)
	}
	if c, _, _ := e.call("DELETE", "/v1/ai-agents/code-helper", e.adminB, nil); c != 404 {
		t.Fatalf("tenant b removed tenant a's agent: %d", c)
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("POST", "/v1/ai-agents", viewer, map[string]any{"name": "x", "operator": "alice", "apps": []string{"erp"}}); c != 403 {
		t.Fatalf("viewer created an agent: %d", c)
	}
	if c, b, _ := e.call("GET", "/v1/ai-agents", viewer, nil); c != 200 || !strings.Contains(string(b), `"operator":"alice"`) {
		t.Fatalf("%d %s", c, b)
	}
	// removing the agent disables it and ends its grants at once; it cannot enrol again or renew
	if c, _, _ := e.call("DELETE", "/v1/ai-agents/code-helper", e.adminA, nil); c != 200 {
		t.Fatal(c)
	}
	if e.api.Store.Granted("a", "agent:code-helper", "erp", time.Now()) {
		t.Fatal("grant survived removal")
	}
	tok2 := e.api.Tokens.Issue("a", ServiceTokenPrefix+"agent:code-helper")
	if c, _ := e.post("/enrol/service", map[string]string{"token": tok2, "public_key": pub}, nil); c != 403 {
		t.Fatalf("a removed agent enrolled: %d", c)
	}
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "ai-agent.create") || !strings.Contains(string(ab), "ai-agent.remove") || !strings.Contains(string(ab), "alice") {
		t.Fatalf("not audited with the operator: %s", ab)
	}
}

func TestTokenKindsAreNotInterchangeable(t *testing.T) {
	e := newEnrolEnv(t)
	_, pub := newKey(t)
	conn := e.api.Tokens.Issue("a", "site1")
	svc := e.api.Tokens.Issue("a", ServiceTokenPrefix+"agent:x")
	en := e.api.Tokens.Issue("", ENTokenPrefix+"localhost")
	// every wrong pairing is refused ...
	for name, c := range map[string]struct{ path, tok string }{
		"service token at connector": {"/enrol/connector", svc}, "EN token at connector": {"/enrol/connector", en},
		"connector token at service": {"/enrol/service", conn}, "EN token at service": {"/enrol/service", en},
		"connector token at EN": {"/enrol/en", conn}, "service token at EN": {"/enrol/en", svc},
	} {
		if code, _ := e.post(c.path, map[string]string{"token": c.tok, "public_key": pub}, nil); code != 401 {
			t.Errorf("%s accepted: %d", name, code)
		}
	}
	// ... and a refused attempt does not burn the token: it still works at the right endpoint
	if code, _ := e.post("/enrol/connector", map[string]string{"token": conn, "public_key": pub}, nil); code != 200 {
		t.Errorf("connector token was burnt by a misdirected attempt: %d", code)
	}
	if code, _ := e.post("/enrol/en", map[string]string{"token": en, "public_key": pub}, nil); code != 200 {
		t.Errorf("EN token was burnt by a misdirected attempt: %d", code)
	}
}

func TestWorkspaceEnrolmentAndRenewal(t *testing.T) { // WBT-003
	e := newEnrolEnv(t)
	k, pub := newKey(t)
	tok := e.idp.Sign("k1", e.idp.Good("u1", "u1@example.com", "n1", "all-staff"))
	code, b := e.post("/enrol/device", map[string]any{"tenant": "a", "id_token": tok, "nonce": "n1", "public_key": pub, "workspace": true}, nil)
	var out certOut
	json.Unmarshal(b, &out)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	der, _ := base64.StdEncoding.DecodeString(out.Cert)
	leaf, _ := x509.ParseCertificate(der)
	id, err := e.ca.Verify(leaf, nil)
	if err != nil || id.Role != pki.RoleWorkspace {
		t.Fatalf("%+v %v", id, err)
	}
	if ttl := time.Until(leaf.NotAfter); ttl > WorkspaceTTL+time.Minute {
		t.Fatalf("workspace credential lives %v, more than %v", ttl, WorkspaceTTL)
	}
	// renewal keeps the role and the short lifetime
	code, b = e.post("/enrol/renew", map[string]string{"public_key": pub}, tlsCert(t, out, k))
	var out2 certOut
	json.Unmarshal(b, &out2)
	der2, _ := base64.StdEncoding.DecodeString(out2.Cert)
	leaf2, _ := x509.ParseCertificate(der2)
	id2, _ := e.ca.Verify(leaf2, nil)
	if code != 200 || id2.Role != pki.RoleWorkspace || time.Until(leaf2.NotAfter) > WorkspaceTTL+time.Minute {
		t.Fatalf("%d %+v ttl %v", code, id2, time.Until(leaf2.NotAfter))
	}
	// an ordinary enrolment is not a workspace
	_, pub2 := newKey(t)
	tok2 := e.idp.Sign("k1", e.idp.Good("u1", "u1@example.com", "n2", "all-staff"))
	_, b = e.post("/enrol/device", map[string]any{"tenant": "a", "id_token": tok2, "nonce": "n2", "public_key": pub2}, nil)
	var out3 certOut
	json.Unmarshal(b, &out3)
	der3, _ := base64.StdEncoding.DecodeString(out3.Cert)
	leaf3, _ := x509.ParseCertificate(der3)
	if id3, _ := e.ca.Verify(leaf3, nil); id3.Role != pki.RoleDevice {
		t.Fatalf("an ordinary enrolment produced role %q", id3.Role)
	}
	// a workspace certificate may not read connector targets or sync state
	if c, _ := e.get("/enrol/targets", tlsCert(t, out, k)); c != 401 {
		t.Fatalf("workspace read connector targets: %d", c)
	}
	// safe defaults: sensitive apps need the workspace, standard ones do not
	priv, _ := SafeDefaults([]broker.Segment{{ID: "std", Class: "standard"}, {ID: "hr", Class: "sensitive"}})
	if err := priv.Compile(nil); err != nil {
		t.Fatal(err)
	}
	u := policy.User{Groups: []string{"all-staff"}}
	if d := priv.Evaluate(policy.Request{Kind: policy.Private, User: u, App: "hr"}); d.Action != policy.Deny || d.Reason != "workspace-required" {
		t.Fatalf("%+v", d)
	}
	if d := priv.Evaluate(policy.Request{Kind: policy.Private, User: u, App: "hr", Workspace: true}); d.Action != policy.Allow {
		t.Fatalf("%+v", d)
	}
	if c, _, _ := e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "s", "group": "g", "class": "sensitive", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}}); c != 200 {
		t.Fatalf("segment class sensitive refused: %d", c)
	}
}

func TestInspectionPinEndpoint(t *testing.T) { // WB-003 groundwork
	e := newEnrolEnv(t)
	k, pub := newKey(t)
	tok := e.idp.Sign("k1", e.idp.Good("u1", "u1@example.com", "n1", "all-staff"))
	_, b := e.post("/enrol/device", map[string]any{"tenant": "a", "id_token": tok, "nonce": "n1", "public_key": pub, "workspace": true}, nil)
	var out certOut
	json.Unmarshal(b, &out)
	ask := func(c *tls.Certificate) (int, map[string]any) {
		code, body := e.get("/enrol/inspection", c)
		var m map[string]any
		json.Unmarshal(body, &m)
		return code, m
	}
	if code, m := ask(tlsCert(t, out, k)); code != 200 || m["enabled"] != false || m["spki_sha256"] != "" {
		t.Fatalf("inspection off: %d %v", code, m)
	}
	if code, _ := ask(nil); code != 401 {
		t.Fatalf("no certificate: %d", code)
	}
	e.api.Store.SetInspection("a", true, nil)
	code, m := ask(tlsCert(t, out, k))
	want, _ := e.api.Store.InterceptSPKI("a")
	if code != 200 || m["enabled"] != true || m["spki_sha256"] != want || want == "" {
		t.Fatalf("%d %v want %q", code, m, want)
	}
	// a connector certificate has no business asking
	ctok := e.api.Tokens.Issue("a", "site1")
	ck, cpub := newKey(t)
	_, cb := e.post("/enrol/connector", map[string]string{"token": ctok, "public_key": cpub}, nil)
	var cout certOut
	json.Unmarshal(cb, &cout)
	if code, _ := ask(tlsCert(t, cout, ck)); code != 401 {
		t.Fatalf("connector certificate: %d", code)
	}
}

func TestInspectionCAEndpointForDevices(t *testing.T) { // ZIA-034
	e := newEnrolEnv(t)
	k, pub := newKey(t)
	tok := e.idp.Sign("k1", e.idp.Good("u1", "u1@example.com", "n1", "all-staff"))
	_, b := e.post("/enrol/device", map[string]any{"tenant": "a", "id_token": tok, "nonce": "n1", "public_key": pub}, nil)
	var out certOut
	json.Unmarshal(b, &out)
	if code, _ := e.get("/enrol/inspection-ca", tlsCert(t, out, k)); code != 404 {
		t.Fatalf("CA offered while inspection is off: %d", code)
	}
	e.api.Store.SetInspection("a", true, nil)
	code, body := e.get("/enrol/inspection-ca", tlsCert(t, out, k))
	if code != 200 || !strings.Contains(string(body), "BEGIN CERTIFICATE") || strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := e.get("/enrol/inspection-ca", nil); code != 401 {
		t.Fatalf("no certificate: %d", code)
	}
	// another tenant's device gets its own CA, never this one
	e.api.Store.SetInspection("b", true, nil)
	ca, _ := e.api.Store.Inspection("a")
	cb, _ := e.api.Store.Inspection("b")
	if ca.CACert == cb.CACert {
		t.Fatal("tenants share a CA")
	}
}

func TestIncidentsEndpoint(t *testing.T) { // ZIA-022c
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	e.api.Alerts = alerts.New()
	now := time.Now()
	var recs []broker.Record
	for i := 0; i < 6; i++ {
		recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "alice", App: "erp", TS: now})
	}
	recs = append(recs,
		broker.Record{Tenant: "a", Kind: "web", Event: "open", Action: "deny", Reason: "dlp-response", User: "alice", DLP: []string{"credit-card"}, TS: now},
		broker.Record{Tenant: "b", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "zed", App: "x", TS: now})
	for i := 0; i < 5; i++ {
		recs = append(recs, broker.Record{Tenant: "b", Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "zed", App: "x", TS: now})
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	code, b, _ := e.call("GET", "/v1/incidents", e.adminA, nil)
	var list []incidents.Incident
	json.Unmarshal(b, &list)
	if code != 200 || len(list) != 1 || list[0].User != "alice" || list[0].Severity != incidents.High || strings.Contains(string(b), "zed") {
		t.Fatalf("%d %s", code, b)
	}
	if !strings.Contains(string(b), "credit-card") || strings.Contains(string(b), "4111") {
		t.Fatalf("%s", b)
	}
	_, b, _ = e.call("GET", "/v1/incidents", e.adminB, nil)
	if strings.Contains(string(b), "alice") || !strings.Contains(string(b), "zed") {
		t.Fatalf("tenant isolation: %s", b)
	}
}

func TestCaptureEndpoints(t *testing.T) { // ZIA-022b
	e := newEnrolEnv(t)
	e.api.Captures = captures.New()
	e.api.Decisions = decisions.New()
	mk := func(tenant, user string) broker.Record {
		return broker.Record{Tenant: tenant, Kind: "capture", User: user, Device: "d1", Capture: &broker.Capture{Rule: "watch", Method: "POST", Host: "ai.example", Path: "/chat", Verdict: "allow", Status: 200, ReqBody: "aGVsbG8="}}
	}
	if c, _ := e.post("/ingest/records", []broker.Record{mk("a", "alice"), mk("b", "eve")}, enCert(t, e)); c != 200 {
		t.Fatal(c)
	}
	// a capture is not an access decision: it must not show up in decision search or the digest
	if got, _ := e.api.Decisions.Query("a", decisions.Filter{}); len(got) != 0 {
		t.Fatalf("captures leaked into decisions: %+v", got)
	}
	code, b, _ := e.call("GET", "/v1/captures", e.adminA, nil)
	var list []captures.Summary
	json.Unmarshal(b, &list)
	if code != 200 || len(list) != 1 || list[0].User != "alice" || list[0].ReqBytes != 5 || strings.Contains(string(b), "aGVsbG8") || strings.Contains(string(b), "eve") {
		t.Fatalf("the list shows metadata only and only this tenant's: %d %s", code, b)
	}
	id := fmt.Sprint(list[0].ID)
	// the content needs the admin role, even to list it
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("GET", "/v1/captures", viewer, nil); c != 403 {
		t.Fatalf("viewer listed captures: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/captures/"+id, viewer, nil); c != 403 {
		t.Fatalf("viewer read a capture: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/captures/"+id, e.adminB, nil); c != 404 {
		t.Fatalf("tenant b read tenant a's capture: %d", c)
	}
	code, b, _ = e.call("GET", "/v1/captures/"+id, e.adminA, nil)
	if code != 200 || !strings.Contains(string(b), "aGVsbG8=") {
		t.Fatalf("%d %s", code, b)
	}
	if c, _, _ := e.call("GET", "/v1/captures/9999", e.adminA, nil); c != 404 {
		t.Fatalf("unknown id: %d", c)
	}
	// reading is audited
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "capture.read") || !strings.Contains(string(ab), "ai.example") {
		t.Fatalf("a read of captured content must be in the audit log: %s", ab)
	}
	// purge: scoped to the tenant, audited
	if c, b, _ := e.call("DELETE", "/v1/captures", viewer, nil); c != 403 {
		t.Fatalf("viewer purged: %d %s", c, b)
	}
	if c, b, _ := e.call("DELETE", "/v1/captures", e.adminA, nil); c != 200 || !strings.Contains(string(b), `"purged":1`) {
		t.Fatalf("%d %s", c, b)
	}
	if _, b, _ := e.call("GET", "/v1/captures", e.adminB, nil); !strings.Contains(string(b), "eve") {
		t.Fatalf("tenant a's purge removed tenant b's captures: %s", b)
	}
	_, ab, _ = e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "capture.purge") {
		t.Fatal("purge not audited")
	}
}

func TestReadOnlyPackEndpoint(t *testing.T) { // AGT-007 (endpoint)
	e := newEnrolEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice", Email: "alice@example.com"})
	e.call("POST", "/v1/ai-agents", e.adminA, map[string]any{"name": "bot", "operator": "alice", "apps": []string{"erp"}})
	e.call("PUT", "/v1/secrets/crm", e.adminA, map[string]any{"host": "api.crm.example", "header": "Authorization", "value": "v"})
	url := "/v1/ai-agents/bot/readonly-pack?domains=api.crm.example&model=api.model.example&inject=crm"
	c, b, _ := e.call("GET", url, e.adminA, nil)
	if c != 200 || !strings.Contains(b2s(b), "agent-read-only") || !strings.Contains(b2s(b), "NOT blocked") {
		t.Fatalf("%d %s", c, b)
	}
	var pack struct{ Rules []policy.Rule }
	json.Unmarshal(b, &pack)
	// the returned rules are accepted by the policy endpoint as they are
	if c, b, _ := e.call("PUT", "/v1/policies/web", e.adminA, map[string]any{"default_action": "allow", "rules": pack.Rules}, "If-Match", "0"); c != 200 {
		t.Fatalf("pack rules refused: %d %s", c, b)
	}
	for url, want := range map[string]int{
		"/v1/ai-agents/ghost/readonly-pack?domains=a.example":             404,
		"/v1/ai-agents/bot/readonly-pack":                                 400,
		"/v1/ai-agents/bot/readonly-pack?domains=a.example&inject=nosuch": 400,
		"/v1/ai-agents/bot/readonly-pack?domains=https://a.example/x":     400,
	} {
		if c, _, _ := e.call("GET", url, e.adminA, nil); c != want {
			t.Errorf("%s: %d, want %d", url, c, want)
		}
	}
	if c, _, _ := e.call("GET", "/v1/ai-agents/bot/readonly-pack?domains=a.example", e.adminB, nil); c != 404 {
		t.Fatalf("another tenant must not see the agent: %d", c)
	}
}

func b2s(b []byte) string { return string(b) }

func TestShadowAIAndLintEndpoints(t *testing.T) { // AGT-011, AGT-012 (API)
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice", Email: "alice@example.com"})
	e.call("POST", "/v1/ai-agents", e.adminA, map[string]any{"name": "bot", "operator": "alice", "apps": []string{"erp"}})
	e.api.Decisions.Add(broker.Record{Tenant: "a", Kind: "web", User: "alice", Target: "chatgpt.com:443", Action: "allow", Event: "open", TS: time.Now()})
	e.api.Decisions.Add(broker.Record{Tenant: "b", Kind: "web", User: "zed", Target: "chatgpt.com:443", Action: "allow", Event: "open", TS: time.Now()})
	c, b, _ := e.call("GET", "/v1/shadow-ai?days=7", e.adminA, nil)
	if c != 200 || !strings.Contains(string(b), "ChatGPT") || !strings.Contains(string(b), "alice") || strings.Contains(string(b), "zed") {
		t.Fatalf("%d %s", c, b)
	}
	if c, _, _ := e.call("GET", "/v1/shadow-ai?days=99", e.adminA, nil); c != 400 {
		t.Fatalf("%d", c)
	}
	// with a permissive web policy the agent holds all three legs
	e.call("PUT", "/v1/policies/web", e.adminA, map[string]any{"default_action": "allow", "rules": []any{}}, "If-Match", "0")
	c, b, _ = e.call("GET", "/v1/ai-agents/bot/lint", e.adminA, nil)
	if c != 200 || !strings.Contains(string(b), `"warning":true`) {
		t.Fatalf("%d %s", c, b)
	}
	if c, _, _ := e.call("GET", "/v1/ai-agents/ghost/lint", e.adminA, nil); c != 404 {
		t.Fatalf("%d", c)
	}
	if c, _, _ := e.call("GET", "/v1/ai-agents/bot/lint", e.adminB, nil); c != 404 {
		t.Fatalf("another tenant sees the agent: %d", c)
	}
}

func TestAgentRegistryLastUseAndUnused(t *testing.T) { // AGT-016 (AGS-005)
	e := newEnrolEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice", Email: "alice@example.com"})
	for _, n := range []string{"busy", "idle"} {
		e.call("POST", "/v1/ai-agents", e.adminA, map[string]any{"name": n, "operator": "alice", "apps": []string{"erp"}})
	}
	type row struct {
		Agent   string
		LastUse *time.Time `json:"last_use"`
		Unused  bool
		Access  *time.Time `json:"access_until"`
	}
	list := func() map[string]row {
		_, b, _ := e.call("GET", "/v1/ai-agents", e.adminA, nil)
		var rs []row
		json.Unmarshal(b, &rs)
		m := map[string]row{}
		for _, r := range rs {
			m[r.Agent] = r
		}
		return m
	}
	if m := list(); m["agent:busy"].LastUse != nil || m["agent:busy"].Unused || m["agent:busy"].Access == nil {
		t.Fatalf("a new agent is not unused, has no last use yet, and shows when access ends: %+v", m["agent:busy"])
	}
	now := time.Now()
	e.api.Store.NoteAgentUse("a", "agent:busy", now)
	e.api.Store.NoteAgentUse("a", "alice", now) // a person is not an agent: ignored
	if m := list(); m["agent:busy"].LastUse == nil {
		t.Fatal("last use not shown")
	}
	if _, ok := e.api.Store.AgentTimes("a")["alice"]; ok {
		t.Fatal("a person was recorded in the agent registry")
	}
	// 31 days without use is flagged; a recent use clears it
	e.api.Store.NoteAgentCreated("a", "agent:idle", now.Add(-31*24*time.Hour))
	if m := list(); !m["agent:idle"].Unused || m["agent:busy"].Unused {
		t.Fatalf("%+v", m)
	}
	e.api.Store.NoteAgentUse("a", "agent:idle", now)
	if m := list(); m["agent:idle"].Unused {
		t.Fatal("a used agent must not be flagged")
	}
	// tenant isolation
	if _, b, _ := e.call("GET", "/v1/ai-agents", e.adminB, nil); strings.Contains(string(b), "idle") {
		t.Fatal("tenant b sees tenant a's agents")
	}
}

func TestPolicyHistoryDiffAndRollback(t *testing.T) { // AGT-021 (ADM-004)
	e := newEnrolEnv(t)
	put := func(im string, rules []map[string]any, def string) int {
		c, _, _ := e.call("PUT", "/v1/policies/web", e.adminA, map[string]any{"default_action": def, "rules": rules}, "If-Match", im)
		return c
	}
	r1 := []map[string]any{{"id": "block-games", "priority": 1, "action": "deny", "match": map[string]any{"categories": []string{"gambling"}}}}
	r2 := []map[string]any{{"id": "block-games", "priority": 1, "action": "deny", "match": map[string]any{"categories": []string{"gambling", "games"}}},
		{"id": "warn-social", "priority": 2, "action": "warn", "match": map[string]any{"categories": []string{"social"}}}}
	if put("0", r1, "allow") != 200 || put("1", r2, "allow") != 200 || put("2", nil, "deny") != 200 {
		t.Fatal("setup")
	}
	c, b, _ := e.call("GET", "/v1/policies/web/versions", e.adminA, nil)
	var vs []struct {
		Version int
		By      string
		Policy  any
	}
	json.Unmarshal(b, &vs)
	if c != 200 || len(vs) != 3 || vs[0].Version != 1 || vs[2].Version != 3 || vs[0].Policy != nil {
		t.Fatalf("%d %s", c, b)
	}
	if vs[0].By == "" {
		t.Fatal("who saved the version must be recorded")
	}
	// diff 1 to 3: the rule is gone and the default changed
	c, b, _ = e.call("GET", "/v1/policies/web/diff?from=1&to=3", e.adminA, nil)
	if c != 200 || !strings.Contains(string(b), "rule_removed") || !strings.Contains(string(b), "default_action") || !strings.Contains(string(b), "gambling") {
		t.Fatalf("%d %s", c, b)
	}
	if c, b, _ = e.call("GET", "/v1/policies/web/diff?from=2", e.adminA, nil); c != 200 || !strings.Contains(string(b), `"to":3`) {
		t.Fatalf("to defaults to the current version: %d %s", c, b)
	}
	// one version's body can be read
	if c, b, _ = e.call("GET", "/v1/policies/web/versions/2", e.adminA, nil); c != 200 || !strings.Contains(string(b), "warn-social") {
		t.Fatalf("%d %s", c, b)
	}
	// rollback needs the current version in If-Match, an existing version, and write rights
	if c, _, _ = e.call("POST", "/v1/policies/web/rollback", e.adminA, map[string]any{"version": 1}, "If-Match", "1"); c != 409 && c != 412 {
		t.Fatalf("a stale If-Match must be refused: %d", c)
	}
	if c, _, _ = e.call("POST", "/v1/policies/web/rollback", e.adminA, map[string]any{"version": 99}, "If-Match", "3"); c != 404 {
		t.Fatalf("%d", c)
	}
	if c, _, _ = e.call("POST", "/v1/policies/web/rollback", e.adminA, map[string]any{"version": 1}); c != 428 {
		t.Fatalf("If-Match is required: %d", c)
	}
	if c, _, _ = e.call("POST", "/v1/policies/web/rollback", e.adminB, map[string]any{"version": 1}, "If-Match", "0"); c == 200 {
		t.Fatal("another tenant must not be able to roll back this one")
	}
	c, b, _ = e.call("POST", "/v1/policies/web/rollback", e.adminA, map[string]any{"version": 1}, "If-Match", "3")
	if c != 200 || !strings.Contains(string(b), `"version":4`) || !strings.Contains(string(b), `"restored":1`) {
		t.Fatalf("%d %s", c, b)
	}
	// the live policy is version 1's content again, saved as version 4; nothing was rewritten
	if c, b, _ = e.call("GET", "/v1/policies/web/diff?from=1&to=4", e.adminA, nil); c != 200 || !strings.Contains(string(b), `"same":true`) {
		t.Fatalf("version 4 must equal version 1: %d %s", c, b)
	}
	if c, b, _ = e.call("GET", "/v1/policies/web/versions", e.adminA, nil); !strings.Contains(string(b), "rollback to version 1") || strings.Count(string(b), `"version"`) != 4 {
		t.Fatalf("%s", b)
	}
	if c, b, _ = e.call("GET", "/v1/audit", e.adminA, nil); !strings.Contains(string(b), "policy.rollback") {
		t.Fatalf("a rollback must be audited: %s", b)
	}
	// tenant isolation of the history
	if c, b, _ = e.call("GET", "/v1/policies/web/versions/2", e.adminB, nil); c == 200 {
		t.Fatalf("tenant b read tenant a's history: %s", b)
	}
}
