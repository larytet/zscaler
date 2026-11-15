package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"github.com/larytet/zscaler/test/faults"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/posture"
)

type fakeState struct {
	mu    sync.Mutex
	pol   *policy.Policy
	segs  map[string]Segment
	users map[string]policy.User
}

func (f *fakeState) Policy(tenant string, k policy.Kind) *policy.Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pol
}
func (f *fakeState) Segment(tenant, id string) (Segment, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.segs[tenant+"/"+id]
	return s, ok
}
func (f *fakeState) User(tenant, sub string) (policy.User, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[tenant+"/"+sub]
	return u, ok
}
func (f *fakeState) setUser(tenant string, u policy.User) {
	f.mu.Lock()
	f.users[tenant+"/"+u.Subject] = u
	f.mu.Unlock()
}

type rig struct {
	t      *testing.T
	ca     *pki.CA
	en     *EN
	enAddr string
	st     *fakeState
	logs   *recLog
	app    *echoApp
}

type recLog struct {
	mu sync.Mutex
	r  []Record
}

func (l *recLog) add(r Record) { l.mu.Lock(); l.r = append(l.r, r); l.mu.Unlock() }
func (l *recLog) find(f func(Record) bool) *Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.r {
		if f(l.r[i]) {
			return &l.r[i]
		}
	}
	return nil
}

type echoApp struct {
	ln    net.Listener
	conns atomic.Int64
}

func newEcho(t *testing.T) *echoApp {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &echoApp{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			a.conns.Add(1)
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return a
}

func (a *echoApp) port() int { return a.ln.Addr().(*net.TCPAddr).Port }

func bp(b bool) *bool { return &b }

func newRig(t *testing.T) *rig {
	t.Helper()
	ca, err := pki.NewCA("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	app := newEcho(t)
	st := &fakeState{
		segs: map[string]Segment{"t1/seg-db": {ID: "seg-db", Group: "site1", Targets: []Target{{Host: "127.0.0.1", Ports: []int{app.port()}}}}},
		users: map[string]policy.User{
			"t1/alice": {Subject: "alice", Email: "alice@example.com", Groups: []string{"finance"}},
			"t1/bob":   {Subject: "bob", Email: "bob@example.com", Groups: []string{"hr"}},
		},
	}
	pol := &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Version: 7, Rules: []policy.Rule{{
		ID: "r-fin", Priority: 10, Action: policy.Allow, Reason: "finance reaches db",
		Match: policy.Match{Groups: []string{"finance"}, Apps: []string{"seg-db"},
			Posture: &policy.PostureMatch{DiskEncrypted: bp(true), MaxAgeSeconds: 3600}}}}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	st.pol = pol

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := ca.Sign(&key.PublicKey, pki.Identity{Tenant: "t1", Subject: "en", Device: "en1", Role: pki.RoleEN}, 24*time.Hour, "en.local")
	logs := &recLog{}
	en := &EN{Name: "en1", CA: ca, Rev: pki.NewRevocations(nil), State: st, Log: logs.add,
		Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ReevalEvery: time.Hour}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go en.Serve(ln)
	t.Cleanup(func() { en.Close(); ln.Close() })
	return &rig{t: t, ca: ca, en: en, enAddr: ln.Addr().String(), st: st, logs: logs, app: app}
}

type creds struct {
	tls  *tls.Config
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func (r *rig) creds(ca *pki.CA, role, subject, device string) creds {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := ca.Sign(&key.PublicKey, pki.Identity{Tenant: "t1", Subject: subject, Device: device, Role: role}, time.Hour)
	if err != nil {
		r.t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return creds{key: key, cert: c, tls: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs:      r.ca.Pool(), ServerName: "en.local", MinVersion: tls.VersionTLS13}}
}

func (r *rig) startConnector(name string, allow func(string, int) bool) context.CancelFunc {
	cr := r.creds(r.ca, pki.RoleConnector, "site1", name)
	ctx, cancel := context.WithCancel(context.Background())
	c := &Connector{Addr: r.enAddr, TLS: cr.tls, Allow: allow}
	go c.Run(ctx)
	r.t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for r.en.ConnectorCount("t1", "site1") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return cancel
}

func (r *rig) allowApp(h string, p int) bool { return h == "127.0.0.1" && p == r.app.port() }

func (r *rig) agent(user, device string, goodPosture bool) (*Conn, creds) {
	cr := r.creds(r.ca, pki.RoleDevice, user, device)
	conn, err := Dial(r.enAddr, cr.tls)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { conn.Close() })
	if err := r.sendPosture(conn, cr, device, goodPosture); err != nil {
		r.t.Fatalf("posture: %v", err)
	}
	return conn, cr
}

var tsCounter atomic.Int64

func (r *rig) sendPosture(conn *Conn, cr creds, device string, disk bool) error {
	rep := posture.Report{DeviceID: device, TS: time.Now().UTC().Add(-time.Minute + time.Duration(tsCounter.Add(1))*time.Millisecond),
		Nonce: posture.NewNonce(), OS: "linux", OSVersion: "6.8", DiskEncrypted: &disk}
	tok, _ := posture.Sign(cr.key, rep)
	return conn.SendPosture(tok)
}

func roundTrip(t *testing.T, s io.ReadWriteCloser, msg []byte) {
	t.Helper()
	go s.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil || string(got) != string(msg) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestAllowedRoundTrip(t *testing.T) { // PA-001
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1<<20)
	rand.Read(data)
	roundTrip(t, s, data)
	s.Close()
	time.Sleep(200 * time.Millisecond)
	if rec := r.logs.find(func(x Record) bool { return x.Action == "allow" && x.Rule == "r-fin" && x.Version == 7 }); rec == nil {
		t.Fatal("no allow record with rule and version")
	}
	if rec := r.logs.find(func(x Record) bool { return x.Event == "close" && x.BytesUp == 1<<20 }); rec == nil {
		t.Fatalf("no close record with byte counts: %+v", r.logs.r)
	}
}

func TestDeniedWrongGroupNoAppContact(t *testing.T) { // PA-002
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("bob", "d2", true)
	_, err := conn.OpenApp("seg-db", "", r.app.port())
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("err %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if r.app.conns.Load() != 0 {
		t.Fatal("app was contacted for a denied request")
	}
	if r.logs.find(func(x Record) bool { return x.Action == "deny" && x.User == "bob" }) == nil {
		t.Fatal("no deny record")
	}
}

func TestPostureDenied(t *testing.T) { // PA-003
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", false) // disk encryption off
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
		t.Fatal("non-compliant device allowed")
	}
}

func TestNoPostureDenied(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	conn, err := Dial(r.enAddr, cr.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
		t.Fatal("device without a posture report allowed")
	}
}

func TestUnknownAppAndRawTarget(t *testing.T) { // PA-005, PA-006, PA-017 (port outside the segment list)
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	if _, err := conn.OpenApp("nope", "", 80); err == nil || !strings.Contains(err.Error(), "unknown-app") {
		t.Fatalf("unknown app: %v", err)
	}
	if _, err := conn.OpenApp("seg-db", "10.9.9.9", r.app.port()); err == nil || !strings.Contains(err.Error(), "bad-target") {
		t.Fatalf("raw ip: %v", err)
	}
	if _, err := conn.OpenApp("seg-db", "", r.app.port()+1); err == nil || !strings.Contains(err.Error(), "bad-target") {
		t.Fatalf("wrong port: %v", err)
	}
	if r.app.conns.Load() != 0 {
		t.Fatal("app contacted")
	}
}

func TestConnectorRefusesOutsideAllowList(t *testing.T) { // PA-007, SEC-006: EN is "compromised"
	r := newRig(t)
	// connector only allows a different port than the segment lists
	r.startConnector("c1", func(h string, p int) bool { return false })
	conn, _ := r.agent("alice", "d1", true)
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
		t.Fatal("connector dialled a target outside its allow-list")
	}
	if r.app.conns.Load() != 0 {
		t.Fatal("app contacted")
	}
}

func TestNoConnectorUnavailable(t *testing.T) { // PA-011
	r := newRig(t)
	conn, _ := r.agent("alice", "d1", true)
	start := time.Now()
	_, err := conn.OpenApp("seg-db", "", r.app.port())
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("too slow")
	}
}

func TestConnectorFailover(t *testing.T) { // PA-009, PA-010 (reconnect with backoff is PA-012, see TestRES001ConnectorSurvivesENRestart)
	r := newRig(t)
	cancel1 := r.startConnector("c1", r.allowApp)
	r.startConnector("c2", r.allowApp)
	for r.en.ConnectorCount("t1", "site1") < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	conn, _ := r.agent("alice", "d1", true)
	cancel1() // kill one while idle
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 5; i++ {
		s, err := conn.OpenApp("seg-db", "", r.app.port())
		if err != nil {
			t.Fatalf("open %d after one connector died: %v", i, err)
		}
		roundTrip(t, s, []byte("hi"))
		s.Close()
	}
}

func TestRevokeDeviceClosesSessions(t *testing.T) { // AG-006, SEC-002
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, cr := r.agent("alice", "d1", true)
	conn2, _ := r.agent("alice", "d9", true) // second device of same user
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("x"))
	start := time.Now()
	r.en.RevokeDevice(cr.cert.SerialNumber.String(), "t1", "d1", cr.cert.NotAfter)
	buf := make([]byte, 1)
	if _, err := s.Read(buf); err == nil {
		t.Fatal("session still alive after revoke")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("revocation too slow")
	}
	if _, err := Dial(r.enAddr, cr.tls); err == nil {
		// handshake succeeds at TLS layer; EN closes after verifying the cert
		c, _ := Dial(r.enAddr, cr.tls)
		if c != nil {
			if _, err := c.OpenApp("seg-db", "", r.app.port()); err == nil {
				t.Fatal("revoked device opened a session")
			}
		}
	}
	s2, err := conn2.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("other device affected: %v", err)
	}
	s2.Close()
}

func TestDisableUserClosesAndDenies(t *testing.T) { // AG-005, SCN-002
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("x"))
	r.st.setUser("t1", policy.User{Subject: "alice", Email: "alice@example.com", Groups: []string{"finance"}, Disabled: true})
	r.en.DisableUser("t1", "alice")
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("session alive after disable")
	}
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
		t.Fatal("disabled user opened a session")
	}
}

func TestReevalClosesWhenPostureDrops(t *testing.T) { // PA-004
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, cr := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("x"))
	if n := r.en.ReevalNow(); n != 0 {
		t.Fatalf("closed %d healthy sessions", n)
	}
	if err := r.sendPosture(conn, cr, "d1", false); err != nil { // disk encryption turned off
		t.Fatal(err)
	}
	if n := r.en.ReevalNow(); n != 1 {
		t.Fatalf("expected 1 session closed, got %d", n)
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("session alive")
	}
}

func TestPostureReplayAndForgery(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	conn, err := Dial(r.enAddr, cr.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rep := posture.Report{DeviceID: "d1", TS: time.Now().UTC(), Nonce: posture.NewNonce(), OS: "linux", DiskEncrypted: bp(true)}
	tok, _ := posture.Sign(cr.key, rep)
	if err := conn.SendPosture(tok); err != nil {
		t.Fatal(err)
	}
	if err := conn.SendPosture(tok); err == nil {
		t.Fatal("replayed posture accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rep.TS, rep.Nonce = rep.TS.Add(time.Second), posture.NewNonce()
	forged, _ := posture.Sign(other, rep)
	if err := conn.SendPosture(forged); err == nil {
		t.Fatal("posture signed by another key accepted")
	}
	rep.DeviceID = "someone-else"
	rep.TS, rep.Nonce = rep.TS.Add(time.Second), posture.NewNonce()
	wrong, _ := posture.Sign(cr.key, rep)
	if err := conn.SendPosture(wrong); err == nil {
		t.Fatal("posture for another device accepted")
	}
}

func TestForeignCAAndWrongRole(t *testing.T) { // SEC-004, SEC-005
	r := newRig(t)
	foreign, _ := pki.NewCA("evil", nil)
	cr := r.creds(foreign, pki.RoleDevice, "alice", "d1")
	conn, err := Dial(r.enAddr, cr.tls)
	if err == nil {
		// TLS 1.3 reports client-cert rejection on first use
		_, err = conn.OpenApp("seg-db", "", r.app.port())
		conn.Close()
	}
	if err == nil {
		t.Fatal("cert from foreign CA accepted")
	}
	// an agent cert cannot register as a connector: it never appears in the registry
	r.agent("alice", "d1", true)
	if r.en.ConnectorCount("t1", "alice") != 0 {
		t.Fatal("device registered as connector")
	}
	// rogue EN: connector with a different CA pool refuses to connect
	rogue := r.creds(r.ca, pki.RoleConnector, "site1", "c9")
	rogue.tls.RootCAs = x509.NewCertPool()
	if _, err := Dial(r.enAddr, rogue.tls); err == nil {
		t.Fatal("client trusted an EN certificate from an unknown CA")
	}
}

func TestRepeatedSessionsNoLeak(t *testing.T) { // PA-013
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	for i := 0; i < 200; i++ {
		s, err := conn.OpenApp("seg-db", "", r.app.port())
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		roundTrip(t, s, []byte("ping"))
		s.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.en.ActiveSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := r.en.ActiveSessions(); n != 0 {
		t.Fatalf("%d sessions leaked", n)
	}
}

type staleState struct {
	*fakeState
	stale   atomic.Bool
	revoked sync.Map
}

func (s *staleState) Stale() bool { return s.stale.Load() }
func (s *staleState) DeviceRevoked(tenant, device string) bool {
	_, ok := s.revoked.Load(tenant + "/" + device)
	return ok
}

func TestStaleStateDeniesNewSessions(t *testing.T) { // CP-009
	r := newRig(t)
	ss := &staleState{fakeState: r.st}
	r.en.State = ss
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("x")) // live session keeps working
	ss.stale.Store(true)
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("new session with stale state: %v", err)
	}
	roundTrip(t, s, []byte("y")) // established session is not dropped (ARCH-002)
	ss.stale.Store(false)
	s2, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	s2.Close()
}

func TestAdminRevokedDeviceRefusedAtConnect(t *testing.T) {
	r := newRig(t)
	ss := &staleState{fakeState: r.st}
	r.en.State = ss
	ss.revoked.Store("t1/d1", true)
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	conn, err := Dial(r.enAddr, cr.tls)
	if err == nil {
		_, err = conn.OpenApp("seg-db", "", r.app.port())
		conn.Close()
	}
	if err == nil {
		t.Fatal("device revoked in the control plane was served")
	}
}

func TestEmitsPostureAndConnectorEvents(t *testing.T) { // feeds ALR-002, ALR-003
	r := newRig(t)
	cancel := r.startConnector("c1", r.allowApp)
	if r.logs.find(func(x Record) bool {
		return x.Kind == "connector" && x.Event == "connected" && x.App == "site1" && x.Device == "c1"
	}) == nil {
		t.Fatal("no connector connected event")
	}
	conn, cr := r.agent("alice", "d1", true) // helper sends disk=true but no firewall flag: baseline fails
	_ = conn
	rec := r.logs.find(func(x Record) bool { return x.Kind == "posture" && x.Device == "d1" })
	if rec == nil || rec.Action != "fail" || !strings.Contains(rec.Reason, "firewall") {
		t.Fatalf("posture event: %+v", rec)
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for r.logs.find(func(x Record) bool { return x.Kind == "connector" && x.Event == "disconnected" }) == nil {
		if time.Now().After(deadline) {
			t.Fatal("no connector disconnected event")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = cr
}

func goroutinesSettle(t *testing.T, base int, slack int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= base+slack {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: %d now, %d before (slack %d)", n, base, slack)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRES002LatencyTolerated(t *testing.T) { // 2 x 100 ms added per direction
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	fp, err := faults.New(r.enAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	fp.Delay = 100 * time.Millisecond
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	conn, err := Dial(fp.Addr(), cr.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := r.sendPosture(conn, cr, "d1", true); err != nil {
		t.Fatal(err)
	}
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("open under latency: %v", err)
	}
	data := make([]byte, 256<<10)
	rand.Read(data)
	roundTrip(t, s, data)
	s.Close()
}

func TestRES003CutMidFrameNoLeak(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	time.Sleep(200 * time.Millisecond)
	base := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		fp, err := faults.New(r.enAddr)
		if err != nil {
			t.Fatal(err)
		}
		fp.CutAfter = int64(2000 + i*137) // cuts land in different places, including mid-frame and mid-handshake
		cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
		if conn, err := Dial(fp.Addr(), cr.tls); err == nil {
			r.sendPosture(conn, cr, "d1", true)
			if s, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
				s.Write(make([]byte, 4096))
				s.Close()
			}
			conn.Close()
		}
		fp.Close()
	}
	// the EN keeps serving afterwards
	conn, _ := r.agent("alice", "d2", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("EN unhealthy after cuts: %v", err)
	}
	roundTrip(t, s, []byte("still alive"))
	s.Close()
	conn.Close()
	goroutinesSettle(t, base, 15)
	if n := r.en.ActiveSessions(); n != 0 {
		t.Fatalf("%d sessions leaked", n)
	}
}

func TestRES001ConnectorSurvivesENRestart(t *testing.T) { // component-level; the real-process version is in test/e2e
	r := newRig(t)
	fp, err := faults.New(r.enAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	cr := r.creds(r.ca, pki.RoleConnector, "site1", "c1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Connector{Addr: fp.Addr(), TLS: cr.tls, Allow: r.allowApp}).Run(ctx)
	waitConnectors := func() {
		deadline := time.Now().Add(10 * time.Second)
		for r.en.ConnectorCount("t1", "site1") == 0 {
			if time.Now().After(deadline) {
				t.Fatal("connector did not (re)connect")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitConnectors()
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("a"))
	fp.CutAll() // the connector's link dies, as if the EN restarted
	deadline := time.Now().Add(5 * time.Second)
	for r.en.ConnectorCount("t1", "site1") != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	waitConnectors()
	s2, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("no session after the connector reconnected: %v", err)
	}
	roundTrip(t, s2, []byte("b"))
}

func TestStolenCertWithoutKey(t *testing.T) { // SEC-001
	r := newRig(t)
	victim := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	thief, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := victim.tls.Clone()
	cfg.Certificates = []tls.Certificate{{Certificate: victim.tls.Certificates[0].Certificate, PrivateKey: thief}}
	conn, err := Dial(r.enAddr, cfg)
	if err == nil {
		_, err = conn.OpenApp("seg-db", "", r.app.port())
		conn.Close()
	}
	if err == nil {
		t.Fatal("a certificate without its private key was accepted")
	}
}

func TestCrossTenantSegmentIsUnknown(t *testing.T) { // SEC-003
	r := newRig(t)
	r.st.mu.Lock()
	r.st.segs["t2/seg-secret"] = Segment{ID: "seg-secret", Group: "site1", Targets: []Target{{Host: "127.0.0.1", Ports: []int{r.app.port()}}}}
	r.st.mu.Unlock()
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true) // tenant t1
	if _, err := conn.OpenApp("seg-secret", "", r.app.port()); err == nil || !strings.Contains(err.Error(), "unknown-app") {
		t.Fatalf("tenant t1 reached a tenant t2 segment: %v", err)
	}
	if r.app.conns.Load() != 0 {
		t.Fatal("app contacted")
	}
}

func TestOldTLSRefused(t *testing.T) { // SEC-011
	r := newRig(t)
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	for _, max := range []uint16{tls.VersionTLS12, tls.VersionTLS11} {
		cfg := cr.tls.Clone()
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, max
		if c, err := Dial(r.enAddr, cfg); err == nil {
			c.Close()
			t.Fatalf("broker accepted TLS version %#x", max)
		}
	}
	if c, err := Dial(r.enAddr, cr.tls); err != nil {
		t.Fatalf("TLS 1.3 refused: %v", err)
	} else {
		c.Close()
	}
}

func TestUpstreamRefusesConnection(t *testing.T) { // PA-015
	r := newRig(t)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close() // nothing listens there any more
	r.st.mu.Lock()
	r.st.segs["t1/seg-dead"] = Segment{ID: "seg-dead", Group: "site1", Targets: []Target{{Host: "127.0.0.1", Ports: []int{deadPort}}}}
	r.st.mu.Unlock()
	pol := &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Version: 8, Rules: []policy.Rule{{
		ID: "all", Priority: 1, Action: policy.Allow, Match: policy.Match{Groups: []string{"finance"}}}}}
	pol.Compile(nil)
	r.st.mu.Lock()
	r.st.pol = pol
	r.st.mu.Unlock()
	r.startConnector("c1", func(h string, p int) bool { return true })
	conn, _ := r.agent("alice", "d1", true)
	_, err := conn.OpenApp("seg-dead", "", deadPort)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected a clear 'unavailable' error, got %v", err)
	}
	if r.logs.find(func(x Record) bool { return x.App == "seg-dead" && x.Action == "deny" && x.Reason != "" }) == nil {
		t.Fatal("failure not logged")
	}
}

func TestPerIdentityConnectionLimit(t *testing.T) { // SEC-012
	r := newRig(t)
	r.en.mu.Lock()
	r.en.MaxConnsPerIdentity = 3
	r.en.mu.Unlock()
	cr := r.creds(r.ca, pki.RoleDevice, "alice", "d1")
	for i := 0; i < 3; i++ {
		c, err := Dial(r.enAddr, cr.tls)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := r.sendPosture(c, cr, "d1", true); err != nil {
			t.Fatalf("connection %d within the limit failed: %v", i, err)
		}
	}
	extra, err := Dial(r.enAddr, cr.tls)
	if err == nil {
		err = r.sendPosture(extra, cr, "d1", true)
		extra.Close()
	}
	if err == nil {
		t.Fatal("a fourth connection for the same identity was served")
	}
	r.agent("alice", "d2", true) // another device is unaffected
}

func TestLogSinkUnhealthyRefusesNewSessions(t *testing.T) { // SEC-014
	r := newRig(t)
	var healthy atomic.Bool
	healthy.Store(true)
	r.en.mu.Lock()
	r.en.SinkHealthy = healthy.Load
	r.en.mu.Unlock()
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, []byte("x"))
	healthy.Store(false) // the decision log can no longer be written
	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("a new session was allowed with no way to record it: %v", err)
	}
	roundTrip(t, s, []byte("y")) // established sessions are not dropped
	healthy.Store(true)
	s2, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("no recovery when the sink came back: %v", err)
	}
	s2.Close()
}

func TestRecordsCarryDecisionInputs(t *testing.T) { // feeds the simulator
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	rec := r.logs.find(func(x Record) bool { return x.Action == "allow" && x.Event == "open" })
	if rec == nil || len(rec.Groups) != 1 || rec.Groups[0] != "finance" {
		t.Fatalf("groups missing: %+v", rec)
	}
	if rec.Posture == nil || rec.Posture.DiskEncrypted == nil || !*rec.Posture.DiskEncrypted || rec.Posture.ReportedAt.IsZero() {
		t.Fatalf("posture missing: %+v", rec)
	}
}

type grantState struct {
	*fakeState
	granted atomic.Bool
}

func (g *grantState) Granted(tenant, user, app string, now time.Time) bool { return g.granted.Load() }

func TestRequireApprovalFlow(t *testing.T) { // ZPA-027
	r := newRig(t)
	gs := &grantState{fakeState: r.st}
	r.en.mu.Lock()
	r.en.State = gs
	r.en.mu.Unlock()
	pol := &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Version: 9, Rules: []policy.Rule{{
		ID: "jit", Priority: 1, Action: policy.Approve, Match: policy.Match{Groups: []string{"finance"}, Apps: []string{"seg-db"}}}}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.mu.Lock()
	r.st.pol = pol
	r.st.mu.Unlock()
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)

	if _, err := conn.OpenApp("seg-db", "", r.app.port()); err == nil {
		t.Fatal("access without approval")
	}
	rec := r.logs.find(func(x Record) bool { return x.Reason == "approval-required" && x.Action == "deny" && x.Rule == "jit" })
	if rec == nil {
		t.Fatal("the denial must say approval is required, so the control plane can open a request")
	}
	if r.app.conns.Load() != 0 {
		t.Fatal("app contacted before approval")
	}
	gs.granted.Store(true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatalf("approved access refused: %v", err)
	}
	roundTrip(t, s, []byte("x"))
	if r.logs.find(func(x Record) bool { return x.Action == "allow" && x.Reason == "approved" && x.Rule == "jit" }) == nil {
		t.Fatal("approved access not logged as such")
	}
	// the grant ends: the live session is closed at the next re-evaluation
	gs.granted.Store(false)
	if n := r.en.ReevalNow(); n != 1 {
		t.Fatalf("expected the session to be closed when the grant ended, closed %d", n)
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("session survived the end of the grant")
	}
}
