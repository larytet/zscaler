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

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/pki"
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
