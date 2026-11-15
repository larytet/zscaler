package agent

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/store"
	tidp "github.com/larytet/zscaler/test/idp"
)

type rig struct {
	t   *testing.T
	idp *tidp.Server
	st  *store.Store
	api *cp.API
	en  *httptest.Server
	ca  *pki.CA
	rev *pki.Revocations
	cfg Config
}

func newRig(t *testing.T) *rig {
	st, _ := store.Open("")
	al, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"), nil)
	t.Cleanup(func() { al.Close() })
	api := &cp.API{Store: st, Audit: al, Tokens: pki.NewTokens(nil, time.Hour)}
	if _, err := st.CreateTenant("t1", "T1"); err != nil {
		t.Fatal(err)
	}
	ip := tidp.New("cid")
	t.Cleanup(ip.Close)
	st.SetIDP("t1", store.IDP{Issuer: ip.URL, ClientID: "cid", GroupClaim: "groups"})
	ca, _ := pki.NewCA("ca", nil)
	rev := pki.NewRevocations(nil)
	en := &cp.Enrol{API: api, CA: ca, Rev: rev}
	srv := httptest.NewUnstartedServer(en.Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return &rig{t: t, idp: ip, st: st, api: api, en: srv, ca: ca, rev: rev, cfg: Config{
		Tenant: "t1", Issuer: ip.URL, ClientID: "cid", EnrolURL: srv.URL, EnrolCAPEM: pemCA, ENName: "en.local",
		Apps: map[string]string{"erp.ztx": "erp"}}}
}

func (r *rig) agent() *Agent {
	a, err := New(filepath.Join(r.t.TempDir(), "agent"), r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// follow acts as the browser: it follows the IdP redirect to the agent's loopback callback.
func follow(authURL string) error {
	resp, err := http.Get(authURL)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("callback returned %d", resp.StatusCode)
	}
	return nil
}

func TestEnrolEndToEnd(t *testing.T) { // AG-001
	r := newRig(t)
	a := r.agent()
	if err := a.Enrol(context.Background(), follow); err != nil {
		t.Fatal(err)
	}
	exp, ok := a.Expires()
	if !ok || time.Until(exp) < 11*time.Hour {
		t.Fatalf("cert expiry %v", exp)
	}
	if st, _ := os.Stat(a.path("device.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	if st, _ := os.Stat(a.Dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
	if u, ok := r.st.User("t1", "u1"); !ok || len(u.Groups) != 1 || u.Groups[0] != "all-staff" {
		t.Fatalf("user %+v", u)
	}
	// reload from disk in a fresh agent
	b, _ := New(a.Dir, r.cfg)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if e2, ok := b.Expires(); !ok || !e2.Equal(exp) {
		t.Fatal("reloaded cert differs")
	}
}

func TestForgedCallbackIgnored(t *testing.T) { // AG-003
	r := newRig(t)
	open := func(authURL string) error {
		// attacker hits the callback first with a wrong state
		q := mustQuery(t, authURL)
		resp, err := http.Get(q.Get("redirect_uri") + "?code=stolen&state=wrong")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("wrong state accepted: %d", resp.StatusCode)
		}
		return follow(authURL) // then the real flow still works
	}
	res, err := Login(context.Background(), r.idp.URL, "cid", open)
	if err != nil || res.IDToken == "" {
		t.Fatalf("%v", err)
	}
}

func TestLoginOnlyForgedCallbackFails(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	open := func(authURL string) error {
		q := mustQuery(t, authURL)
		resp, err := http.Get(q.Get("redirect_uri") + "?code=x&state=wrong")
		if err == nil {
			resp.Body.Close()
		}
		return nil
	}
	if _, err := Login(ctx, r.idp.URL, "cid", open); err == nil {
		t.Fatal("login succeeded with only a forged callback")
	}
}

func TestLoginRejectsMismatchedDiscovery(t *testing.T) {
	r := newRig(t)
	if _, err := Login(context.Background(), r.idp.URL+"/", "cid", follow); err == nil {
		t.Fatal("issuer with trailing slash must not match discovery issuer")
	}
}

func TestCallbackIsLoopbackAndSingleUse(t *testing.T) { // SEC-016
	r := newRig(t)
	var redirect string
	open := func(authURL string) error {
		redirect = mustQuery(t, authURL).Get("redirect_uri")
		return follow(authURL)
	}
	if _, err := Login(context.Background(), r.idp.URL, "cid", open); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(redirect, "http://127.0.0.1:") {
		t.Fatalf("redirect %q is not loopback", redirect)
	}
	if resp, err := http.Get(redirect + "?code=x&state=y"); err == nil {
		resp.Body.Close()
		t.Fatal("callback listener still open after login")
	}
}

func mustQuery(t *testing.T, u string) interface{ Get(string) string } {
	req, _ := http.NewRequest("GET", u, nil)
	return req.URL.Query()
}

func TestLoopbackOnly(t *testing.T) { // AG-009
	for _, bad := range []string{"0.0.0.0:1080", "192.168.1.5:1080", ":1080", "example.com:1080", "[::]:1080"} {
		if _, err := New(t.TempDir(), Config{SocksAddr: bad}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:1080", "[::1]:9100"} {
		if _, err := New(t.TempDir(), Config{SocksAddr: ok}); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
}

func TestPAC(t *testing.T) { // AG-010
	a := &Agent{Cfg: Config{SocksAddr: "127.0.0.1:1080", HTTPAddr: "127.0.0.1:3129"}}
	pac := a.PAC()
	for _, want := range []string{`dnsDomainIs(host, ".ztx")`, `SOCKS5 127.0.0.1:1080`, `PROXY 127.0.0.1:3129`, `DIRECT`} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC lacks %q", want)
		}
	}
}

type fakeStream struct {
	net.Conn
}

func (f fakeStream) CloseWrite() error { return nil }

func socksDial(t *testing.T, a *Agent, open Opener, host string, port int, atyp byte, raw []byte) byte {
	t.Helper()
	c, s := net.Pipe()
	go a.socksConn(s, open)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	var rep [2]byte
	io.ReadFull(c, rep[:])
	req := []byte{5, 1, 0, atyp}
	if atyp == 3 {
		req = append(req, byte(len(host)))
		req = append(req, host...)
	} else {
		req = append(req, raw...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	go c.Write(append(req, pb[:]...))
	var resp [10]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatal(err)
	}
	return resp[1]
}

func TestSOCKS(t *testing.T) {
	a := &Agent{Cfg: Config{Apps: map[string]string{"erp.ztx": "seg-erp"}}}
	var gotApp string
	var gotPort int
	open := func(app string, port int) (Stream, error) {
		gotApp, gotPort = app, port
		c, s := net.Pipe()
		go func() { io.Copy(io.Discard, s) }()
		return fakeStream{c}, nil
	}
	if code := socksDial(t, a, open, "ERP.ztx", 5432, 3, nil); code != 0 || gotApp != "seg-erp" || gotPort != 5432 {
		t.Fatalf("code %d app %q port %d", code, gotApp, gotPort)
	}
	gotApp = ""
	if code := socksDial(t, a, open, "unknown.ztx", 1, 3, nil); code != 2 || gotApp != "" {
		t.Fatalf("unknown name: code %d, opened %q", code, gotApp)
	}
	if code := socksDial(t, a, open, "", 80, 1, []byte{10, 0, 0, 5}); code != 8 || gotApp != "" {
		t.Fatalf("raw IPv4 must be refused: %d", code)
	}
	if code := socksDial(t, a, open, "", 80, 4, make([]byte, 16)); code != 8 {
		t.Fatalf("raw IPv6 must be refused: %d", code)
	}
	deny := func(app string, port int) (Stream, error) { return nil, errors.New("mux: stream rejected: policy") }
	if code := socksDial(t, a, deny, "erp.ztx", 1, 3, nil); code != 2 {
		t.Fatalf("policy deny should map to 'not allowed': %d", code)
	}
	down := func(app string, port int) (Stream, error) {
		return nil, errors.New("mux: stream rejected: unavailable")
	}
	if code := socksDial(t, a, down, "erp.ztx", 1, 3, nil); code != 4 {
		t.Fatalf("unavailable should map to host unreachable: %d", code)
	}
}

func TestSOCKSRefusesNonSocks(t *testing.T) {
	a := &Agent{}
	c, s := net.Pipe()
	done := make(chan struct{})
	go func() { a.socksConn(s, nil); close(done) }()
	c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("did not close on non-SOCKS input")
	}
}

func TestPostureCollectFailClosed(t *testing.T) {
	fail := func(name string, args ...string) (string, error) { return "", errors.New("not found") }
	r := Collect(Probes{OS: "linux", Run: fail, Version: func() string { return "6.8" }})
	if r.DiskEncrypted != nil || r.FirewallOn != nil {
		t.Fatalf("failed probes must be unknown: %+v", r)
	}
	ok := func(name string, args ...string) (string, error) {
		switch name {
		case "lsblk":
			return "disk\ncrypt\n", nil
		case "ufw":
			return "Status: active\n", nil
		}
		return "", errors.New("x")
	}
	r = Collect(Probes{OS: "linux", Run: ok})
	if r.DiskEncrypted == nil || !*r.DiskEncrypted || r.FirewallOn == nil || !*r.FirewallOn {
		t.Fatalf("%+v", r)
	}
	mac := func(name string, args ...string) (string, error) {
		if name == "fdesetup" {
			return "FileVault is Off.\n", nil
		}
		return "Firewall is enabled. (State = 1)", nil
	}
	r = Collect(Probes{OS: "darwin", Run: mac})
	if r.DiskEncrypted == nil || *r.DiskEncrypted || r.FirewallOn == nil || !*r.FirewallOn {
		t.Fatalf("%+v", r)
	}
	if r = Collect(Probes{OS: "windows", Run: fail}); r.FirewallOn != nil {
		t.Fatal("windows firewall probe is not implemented and must stay unknown")
	}
}

func TestRenew(t *testing.T) { // AG-007
	r := newRig(t)
	a := r.agent()
	if err := a.Enrol(context.Background(), follow); err != nil {
		t.Fatal(err)
	}
	before := a.leaf.SerialNumber.String()
	if err := a.Renew(); err != nil {
		t.Fatal(err)
	}
	if a.leaf.SerialNumber.String() == before {
		t.Fatal("renewal did not issue a new certificate")
	}
	// the loop renews immediately when the lead time exceeds the remaining lifetime
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prev := a.leaf.SerialNumber.String()
	go a.RenewLoop(ctx, 24*time.Hour, nil)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		cur := a.leaf.SerialNumber.String()
		a.mu.Unlock()
		if cur != prev {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("RenewLoop did not renew")
}

func TestRenewFailsWhenDisabled(t *testing.T) { // AG-008
	r := newRig(t)
	a := r.agent()
	if err := a.Enrol(context.Background(), follow); err != nil {
		t.Fatal(err)
	}
	r.st.SetUserDisabled("t1", "u1", true)
	if err := a.Renew(); err == nil {
		t.Fatal("disabled user renewed")
	}
	if _, ok := a.Expires(); !ok {
		t.Fatal("failed renewal must not discard the existing certificate")
	}
}

func TestCorruptStateRecovers(t *testing.T) { // RES-006
	r := newRig(t)
	a := r.agent()
	if err := a.Enrol(context.Background(), follow); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(a.path("device.crt"), []byte("junk"), 0o600)
	b, _ := New(a.Dir, r.cfg)
	if err := b.Load(); err == nil || !strings.Contains(err.Error(), "re-enrol") {
		t.Fatalf("expected a re-enrol hint, got %v", err)
	}
	os.WriteFile(a.path("device.key"), []byte("junk"), 0o600)
	c, _ := New(a.Dir, r.cfg)
	if err := c.Load(); err == nil {
		t.Fatal("corrupt key accepted")
	}
	// removing the files and enrolling again works
	os.Remove(a.path("device.key"))
	os.Remove(a.path("device.crt"))
	d, _ := New(a.Dir, r.cfg)
	if err := d.Enrol(context.Background(), follow); err != nil {
		t.Fatalf("re-enrol after corruption: %v", err)
	}
}

func TestStatusNotEnrolled(t *testing.T) {
	a := &Agent{Cfg: Config{Apps: map[string]string{"a.ztx": "x"}}}
	s := a.Status()
	if s.Enrolled || s.Connected || len(s.Apps) != 1 {
		t.Fatalf("%+v", s)
	}
	if _, err := a.tlsConfig("x"); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("%v", err)
	}
}
