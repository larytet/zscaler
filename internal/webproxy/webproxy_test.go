package webproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

type state struct{ pol *policy.Policy }

func (s state) Policy(string, policy.Kind) *policy.Policy { return s.pol }
func (state) Segment(string, string) (broker.Segment, bool) {
	return broker.Segment{}, false
}
func (state) User(t, sub string) (policy.User, bool) {
	return policy.User{Subject: sub, Email: sub + "@example.com", Groups: []string{"staff"}}, true
}

type rig struct {
	t       *testing.T
	ca      *pki.CA
	addr    string
	cli     *tls.Config
	logs    []broker.Record
	mu      sync.Mutex
	origin  *httptest.Server
	hits    atomic.Int64
	tlsOrig *httptest.Server
}

func newRig(t *testing.T) *rig {
	ca, _ := pki.NewCA("t", nil)
	r := &rig{t: t, ca: ca}
	r.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.hits.Add(1)
		fmt.Fprint(w, "origin-ok")
	}))
	r.tlsOrig = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { fmt.Fprint(w, "tls-ok") }))
	t.Cleanup(r.origin.Close)
	t.Cleanup(r.tlsOrig.Close)
	exempt := map[string]bool{hostport(r.origin.URL): true, hostport(r.tlsOrig.URL): true}

	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 3, Rules: []policy.Rule{
		{ID: "bad", Priority: 10, Action: policy.Deny, Match: policy.Match{Categories: []string{"malware"}}},
		{ID: "warn", Priority: 20, Action: policy.Warn, Match: policy.Match{Categories: []string{"file-sharing"}}},
	}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	cl := NewClassifier(map[string][]string{
		"malware":      {"evil.test"},
		"file-sharing": {"share.test"},
	})
	p := &Proxy{CA: ca, Rev: pki.NewRevocations(nil), State: state{pol}, Classifier: cl, Name: "en1",
		Exempt: func(a netip.AddrPort) bool { return exempt[a.String()] },
		Log:    func(rec broker.Record) { r.mu.Lock(); r.logs = append(r.logs, rec); r.mu.Unlock() }}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := ca.Sign(&key.PublicKey, pki.Identity{Tenant: "t1", Subject: "en", Device: "en1", Role: pki.RoleEN}, time.Hour, "en.local")
	srv := p.Server(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(tls.NewListener(ln, srv.TLSConfig))
	t.Cleanup(func() { srv.Close() })
	r.addr = ln.Addr().String()
	r.cli = r.clientTLS(ca)
	return r
}

func hostport(u string) string {
	return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
}

func (r *rig) clientTLS(ca *pki.CA) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := ca.Sign(&key.PublicKey, pki.Identity{Tenant: "t1", Subject: "alice", Device: "d1", Role: pki.RoleDevice}, time.Hour)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs: r.ca.Pool(), ServerName: "en.local", MinVersion: tls.VersionTLS13}
}

// do sends one raw request over a fresh mTLS connection to the proxy.
func (r *rig) do(raw string) (*http.Response, string) {
	r.t.Helper()
	c, err := tls.Dial("tcp", r.addr, r.cli)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, raw)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (r *rig) get(url string) (*http.Response, string) {
	u := strings.TrimPrefix(url, "http://")
	host := strings.SplitN(u, "/", 2)[0]
	return r.do(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", url, host))
}

func (r *rig) find(f func(broker.Record) bool) *broker.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.logs {
		if f(r.logs[i]) {
			return &r.logs[i]
		}
	}
	return nil
}

func TestAllowedHTTP(t *testing.T) { // WEB-001
	r := newRig(t)
	resp, body := r.get(r.origin.URL + "/x")
	if resp.StatusCode != 200 || body != "origin-ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker.Record) bool { return x.Action == "allow" && x.Version == 3 }) == nil {
		t.Fatal("no allow record")
	}
}

func TestConnectNoInterception(t *testing.T) { // WEB-002
	r := newRig(t)
	c, err := tls.Dial("tcp", r.addr, r.cli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target := hostport(r.tlsOrig.URL)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", resp, err)
	}
	// TLS to the origin through the tunnel: the certificate must be the origin's own
	pool := x509.NewCertPool()
	pool.AddCert(r.tlsOrig.Certificate())
	inner := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{RootCAs: pool, ServerName: "example.com"})
	if err := inner.Handshake(); err != nil {
		t.Fatalf("inner handshake (proxy must not intercept): %v", err)
	}
	if got := inner.ConnectionState().PeerCertificates[0].Raw; string(got) != string(r.tlsOrig.Certificate().Raw) {
		t.Fatal("certificate was replaced")
	}
	io.WriteString(inner, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	rs, _ := http.ReadResponse(bufio.NewReader(inner), nil)
	b, _ := io.ReadAll(rs.Body)
	if string(b) != "tls-ok" {
		t.Fatalf("%q", b)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestBlockedCategory(t *testing.T) { // WEB-003, WEB-004, WEB-005
	r := newRig(t)
	for host, wantBlock := range map[string]bool{"evil.test": true, "a.b.evil.test": true, "notevil.test": false, "evil.test.example": false} {
		resp, body := r.do(fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host))
		if wantBlock {
			if resp.StatusCode != 403 || !strings.Contains(body, "malware") || !regexp.MustCompile(`reference <b>[0-9a-f]{12}</b>`).MatchString(body) {
				t.Errorf("%s: %d %q", host, resp.StatusCode, body)
			}
		} else if resp.StatusCode == 403 {
			t.Errorf("%s wrongly blocked", host)
		}
	}
	if r.hits.Load() != 0 {
		t.Fatal("origin contacted")
	}
}

func TestWarnHTTPContinueOnce(t *testing.T) { // WEB-006
	r := newRig(t)
	get := func(path string) (*http.Response, string) {
		return r.do(fmt.Sprintf("GET http://share.test%s HTTP/1.1\r\nHost: share.test\r\nConnection: close\r\n\r\n", path))
	}
	resp, body := get("/f?a=1")
	if resp.StatusCode != 200 || !strings.Contains(body, "Continue anyway") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	m := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(body)
	link := strings.ReplaceAll(m[1], "&amp;", "&")
	path := strings.TrimPrefix(link, "http://share.test")
	if !strings.Contains(path, "a=1") {
		t.Fatalf("original query lost: %s", path)
	}
	// following the link reaches the (unresolvable here) origin, i.e. is allowed through: 502, not the warning
	resp2, body2 := get(path)
	if strings.Contains(body2, "Continue anyway") {
		t.Fatal("token not accepted")
	}
	_ = resp2
	// second use of the same token shows the warning again
	_, body3 := get(path)
	if !strings.Contains(body3, "Continue anyway") {
		t.Fatal("token reusable")
	}
	// forged token
	_, body4 := get("/f?ztx_continue=99999999999.deadbeef")
	if !strings.Contains(body4, "Continue anyway") {
		t.Fatal("forged token accepted")
	}
}

func TestWarnOverConnectIsAllowAndLogged(t *testing.T) { // WEB-007
	r := newRig(t)
	c, _ := tls.Dial("tcp", r.addr, r.cli)
	defer c.Close()
	fmt.Fprint(c, "CONNECT share.test:443 HTTP/1.1\r\nHost: share.test:443\r\n\r\n")
	http.ReadResponse(bufio.NewReader(c), nil) // 502: not resolvable, but the decision was made
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker.Record) bool { return x.Reason == "warn-not-displayable" && x.Action == "allow" }) == nil {
		t.Fatalf("no warn-not-displayable record: %+v", r.logs)
	}
}

func TestSSRFBlocked(t *testing.T) { // WEB-008, WEB-009
	r := newRig(t)
	other, _ := net.Listen("tcp", "127.0.0.1:0") // loopback listener that is NOT exempt
	defer other.Close()
	var contacted atomic.Int64
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			contacted.Add(1)
			c.Close()
		}
	}()
	targets := []string{other.Addr().String(), "169.254.169.254:80", "10.0.0.1:80", "[::1]:80", "192.168.1.1:80", "localhost:" + fmt.Sprint(other.Addr().(*net.TCPAddr).Port), "0.0.0.0:80", "100.64.0.1:80"}
	for _, tg := range targets {
		resp, _ := r.get("http://" + tg + "/")
		if resp.StatusCode != 502 {
			t.Errorf("%s: status %d", tg, resp.StatusCode)
		}
		c, _ := tls.Dial("tcp", r.addr, r.cli)
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tg, tg)
		cr, _ := http.ReadResponse(bufio.NewReader(c), nil)
		if cr == nil || cr.StatusCode != 502 {
			t.Errorf("CONNECT %s: %v", tg, cr)
		}
		c.Close()
	}
	if contacted.Load() != 0 {
		t.Fatal("proxy connected to a loopback target")
	}
}

func TestNoClientCert(t *testing.T) { // WEB-010
	r := newRig(t)
	cfg := r.cli.Clone()
	cfg.Certificates = nil
	c, err := tls.Dial("tcp", r.addr, cfg)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(c, "GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n")
		_, err = http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
	}
	if err == nil {
		t.Fatal("proxy served a client without a certificate")
	}
	foreign, _ := pki.NewCA("evil", nil)
	cfg2 := r.clientTLS(foreign)
	c2, err := tls.Dial("tcp", r.addr, cfg2)
	if err == nil {
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(c2, "GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n")
		_, err = http.ReadResponse(bufio.NewReader(c2), nil)
		c2.Close()
	}
	if err == nil {
		t.Fatal("proxy served a client with a foreign certificate")
	}
}

func TestHeaderLimit(t *testing.T) { // WEB-011
	r := newRig(t)
	resp, _ := r.do("GET " + r.origin.URL + "/ HTTP/1.1\r\nHost: x\r\nX-Big: " + strings.Repeat("a", 40<<10) + "\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 431 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestNoQueryOrBodyInLogs(t *testing.T) { // WEB-012
	r := newRig(t)
	r.do(fmt.Sprintf("POST %s/p?token=SECRETQUERY HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\nConnection: close\r\n\r\nSECRETBODY", r.origin.URL, hostport(r.origin.URL)))
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	b, _ := json.Marshal(r.logs)
	r.mu.Unlock()
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "/p") {
		t.Fatalf("logs leak request data: %s", b)
	}
}

func TestClassifier(t *testing.T) {
	c := NewClassifier(map[string][]string{"a": {"x.com"}, "b": {"x.com", "y.x.com"}})
	got := c.Categories("Z.Y.X.com.")
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if len(c.Categories("notx.com")) != 0 || len(c.Categories("com")) != 0 {
		t.Fatal("false match")
	}
}

func TestBlockedRanges(t *testing.T) {
	for ip, want := range map[string]bool{"127.0.0.1": true, "::1": true, "10.1.2.3": true, "172.16.0.1": true, "192.168.0.1": true,
		"169.254.169.254": true, "::ffff:10.0.0.1": true, "fd00::1": true, "8.8.8.8": false, "2606:4700::1111": false} {
		if blocked(netip.MustParseAddr(ip)) != want {
			t.Errorf("%s want %v", ip, want)
		}
	}
}
