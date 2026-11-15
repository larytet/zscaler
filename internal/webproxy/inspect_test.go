package webproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

// inspectOrigin is a TLS origin that tells the caller what it received.
func inspectOrigin(t *testing.T, r *rig, untrusted ...bool) *httptest.Server {
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		b, _ := io.ReadAll(q.Body)
		fmt.Fprintf(w, "origin saw %s %s body=%d", q.Method, q.URL.Path, len(b))
	}))
	t.Cleanup(o.Close)
	r.exemptAdd(hostport(o.URL))
	if len(untrusted) == 0 || !untrusted[0] {
		r.up.AddCert(o.Certificate())
	}
	return o
}

// tunnel opens CONNECT through the proxy and returns a TLS client over it.
func (r *rig) tunnel(t *testing.T, target string, roots *x509.CertPool) (*tls.Conn, *bufio.Reader, error) {
	c, err := tls.Dial("tcp", r.addr, r.cli)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", resp, err)
	}
	host := strings.Split(target, ":")[0]
	inner := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{RootCAs: roots, ServerName: host})
	inner.SetDeadline(time.Now().Add(5 * time.Second))
	if err := inner.Handshake(); err != nil {
		return nil, nil, err
	}
	inner.SetDeadline(time.Time{})
	return inner, bufio.NewReader(inner), nil
}

func get(t *testing.T, c *tls.Conn, br *bufio.Reader, method, host, path, body string) (int, string) {
	t.Helper()
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", method, path, host, len(body), body)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

func enableInspection(r *rig, exempt ...string) {
	r.st.set(func(s *state) { s.enabled, s.exempt, s.ca = true, exempt, r.tenCA })
}

func TestInspectionDecryptsAndAppliesPathRules(t *testing.T) { // ZIA-040, ARCH-021, ZPA-074 (web)
	r := newRig(t)
	o := inspectOrigin(t, r)
	host := strings.Split(hostport(o.URL), ":")[0]
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 4, Rules: []policy.Rule{
		{ID: "no-upload", Priority: 1, Action: policy.Deny, Match: policy.Match{Domains: []string{host}, Paths: []string{"/upload"}, Methods: []string{"POST"}}},
		{ID: "no-secret", Priority: 2, Action: policy.Deny, Match: policy.Match{Domains: []string{host}, Paths: []string{"/admin/secret"}}},
	}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) { s.pol = pol })

	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatalf("handshake against the tenant's inspection CA: %v", err)
	}
	// the client sees a certificate from the tenant's CA, not the origin's
	cert := c.ConnectionState().PeerCertificates[0]
	if string(cert.Raw) == string(o.Certificate().Raw) || cert.Issuer.CommonName != r.tenCA.Cert.Subject.CommonName {
		t.Fatalf("not intercepted: issuer %q", cert.Issuer.CommonName)
	}
	// ordinary requests are decrypted, checked and forwarded, several on one connection
	if code, body := get(t, c, br, "GET", hostport(o.URL), "/ok", ""); code != 200 || body != "origin saw GET /ok body=0" {
		t.Fatalf("%d %q", code, body)
	}
	if code, body := get(t, c, br, "POST", hostport(o.URL), "/other", "abc"); code != 200 || body != "origin saw POST /other body=3" {
		t.Fatalf("%d %q", code, body)
	}
	// path and method rules, which are only possible after decryption
	if code, body := get(t, c, br, "POST", hostport(o.URL), "/upload", "file"); code != 403 || !strings.Contains(body, "blocked") {
		t.Fatalf("upload not blocked: %d %q", code, body)
	}
	if code, _ := get(t, c, br, "GET", hostport(o.URL), "/upload", ""); code != 200 {
		t.Fatalf("a GET of /upload must be allowed (only POST is blocked): %d", code)
	}
	if code, _ := get(t, c, br, "GET", hostport(o.URL), "/admin/secret/x", ""); code != 403 {
		t.Fatalf("path prefix rule: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	if rec := r.find(func(x broker_Record) bool { return x.Inspected && x.Rule == "no-upload" && x.Action == "deny" }); rec == nil {
		t.Fatal("per-request decision with the rule was not logged")
	}
	r.mu.Lock()
	for _, rec := range r.logs {
		if strings.Contains(fmt.Sprint(rec), "/upload") || strings.Contains(fmt.Sprint(rec), "/admin") {
			t.Errorf("a URL path leaked into the decision log: %+v", rec)
		}
	}
	r.mu.Unlock()
}

func TestInspectionDomainFrontingRefused(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	enableInspection(r)
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, c, br, "GET", "evil.example.com", "/", ""); code != http.StatusMisdirectedRequest {
		t.Fatalf("a request for another host inside the tunnel was served: %d", code)
	}
}

func TestExemptDomainsAreNotDecrypted(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	host := strings.Split(hostport(o.URL), ":")[0]
	enableInspection(r, host) // e.g. a bank
	pool := x509.NewCertPool()
	pool.AddCert(o.Certificate())
	c, br, err := r.tunnel(t, hostport(o.URL), pool) // trusts only the origin: works only if untouched
	if err != nil {
		t.Fatalf("an exempt domain was intercepted: %v", err)
	}
	if string(c.ConnectionState().PeerCertificates[0].Raw) != string(o.Certificate().Raw) {
		t.Fatal("certificate was replaced for an exempt domain")
	}
	if code, body := get(t, c, br, "GET", hostport(o.URL), "/x", ""); code != 200 || !strings.Contains(body, "origin saw GET /x") {
		t.Fatalf("%d %q", code, body)
	}
}

func TestInspectionOffTunnelsUntouched(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	pool := x509.NewCertPool()
	pool.AddCert(o.Certificate())
	if _, _, err := r.tunnel(t, hostport(o.URL), pool); err != nil {
		t.Fatalf("with inspection off the tunnel must be opaque: %v", err)
	}
}

func TestUntrustedInterceptCAIsLoggedForTheAdmin(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	enableInspection(r)
	if _, _, err := r.tunnel(t, hostport(o.URL), x509.NewCertPool()); err == nil {
		t.Fatal("a client that does not trust the inspection CA completed the handshake")
	}
	time.Sleep(100 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "inspection-handshake-failed" }) == nil {
		t.Fatal("the admin gets no signal that a device or app rejects the inspection CA (they need it to add an exemption)")
	}
}

func TestInspectionUsesUpstreamVerification(t *testing.T) {
	r := newRig(t)
	enableInspection(r)
	// an origin whose certificate comes from a CA the proxy does not know
	stranger, _ := pki.NewCA("unknown CA", nil)
	der, _ := stranger.SignServer(&r.leafKeyForTest().PublicKey, "127.0.0.1", time.Hour)
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { io.WriteString(w, "should never be relayed") }))
	o.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: r.leafKeyForTest()}}}
	o.StartTLS()
	defer o.Close()
	r.exemptAdd(hostport(o.URL))
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, c, br, "GET", hostport(o.URL), "/", "")
	if code != http.StatusBadGateway || strings.Contains(body, "should never") {
		t.Fatalf("the proxy relayed to a server whose certificate it could not verify: %d %q", code, body)
	}
}

func TestInspectedWarnShowsAPageOverHTTPS(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	host := strings.Split(hostport(o.URL), ":")[0]
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 5, Rules: []policy.Rule{
		{ID: "w", Priority: 1, Action: policy.Warn, Match: policy.Match{Domains: []string{host}}}}}
	pol.Compile(nil)
	r.st.set(func(s *state) { s.pol = pol })
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, c, br, "GET", hostport(o.URL), "/page", "")
	if code != 200 || !strings.Contains(body, "Continue anyway") || !strings.Contains(body, "https://") {
		t.Fatalf("a warning page can now be shown over HTTPS: %d %q", code, body)
	}
}

func (r *rig) leafKeyForTest() *ecdsa.PrivateKey {
	r.keyOnce.Do(func() { r.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	return r.key
}

func dlpRig(t *testing.T) (*rig, *httptest.Server, *tls.Conn, *bufio.Reader, *received) {
	r := newRig(t)
	got := &received{}
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		b, _ := io.ReadAll(q.Body)
		got.set(b)
		fmt.Fprintf(w, "origin got %d bytes", len(b))
	}))
	t.Cleanup(o.Close)
	r.exemptAdd(hostport(o.URL))
	r.up.AddCert(o.Certificate())
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 6, Rules: []policy.Rule{
		{ID: "no-pii", Priority: 1, Action: policy.Deny, Match: policy.Match{DLP: []string{"credit-card", "us-ssn", "aws-access-key"}}}}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) { s.pol = pol })
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	return r, o, c, br, got
}

type received struct {
	mu sync.Mutex
	b  []byte
}

func (r *received) set(b []byte) { r.mu.Lock(); r.b = b; r.mu.Unlock() }
func (r *received) get() []byte  { r.mu.Lock(); defer r.mu.Unlock(); return r.b }

func TestDLPBlocksSensitiveUploadsAndPassesCleanOnes(t *testing.T) { // DATA-001 (basic), AI-003 (basic)
	r, o, c, br, got := dlpRig(t)
	host := hostport(o.URL)
	secret := `{"name":"Alice","card":"4111 1111 1111 1111"}`
	code, body := get(t, c, br, "POST", host, "/submit", secret)
	if code != 403 || !strings.Contains(body, "credit-card") || strings.Contains(body, "4111") {
		t.Fatalf("a card number was not blocked, or the block page echoed it: %d %q", code, body)
	}
	if len(got.get()) != 0 {
		t.Fatal("the origin received a body that should have been blocked")
	}
	clean := `{"name":"Alice","note":"order 42 shipped on 2026-11-15"}`
	if code, body := get(t, c, br, "POST", host, "/submit", clean); code != 200 || body != fmt.Sprintf("origin got %d bytes", len(clean)) || string(got.get()) != clean {
		t.Fatalf("a clean upload must arrive intact: %d %q got=%q", code, body, got.get())
	}
	if code, _ := get(t, c, br, "POST", host, "/k", "aws_key=AKIAIOSFODNN7EXAMPLE"); code != 403 {
		t.Fatalf("cloud key not blocked: %d", code)
	}
	if code, _ := get(t, c, br, "GET", host, "/card=4111111111111111", ""); code != 200 {
		t.Fatalf("only request bodies are scanned: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	rec := r.find(func(x broker_Record) bool { return x.Rule == "no-pii" && x.Action == "deny" })
	if rec == nil || len(rec.DLP) != 1 || rec.DLP[0] != "credit-card" {
		t.Fatalf("the log must name the data type: %+v", rec)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if s := fmt.Sprint(l); strings.Contains(s, "4111") || strings.Contains(s, "AKIA") {
			t.Fatalf("sensitive data reached the decision log: %s", s)
		}
	}
}

func TestDLPChunkedBodies(t *testing.T) {
	_, o, c, br, got := dlpRig(t)
	host := hostport(o.URL)
	fmt.Fprintf(c, "POST /c HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ncard=411\r\n8\r\n11111111\r\n5\r\n11111\r\n0\r\n\r\n", host)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || len(got.get()) != 0 {
		t.Fatalf("a card split across chunks was not caught: %d", resp.StatusCode)
	}
}

func TestDLPOversizeBodyIsForwardedAndTheGapIsLogged(t *testing.T) {
	r, o, c, br, got := dlpRig(t)
	host := hostport(o.URL)
	big := strings.Repeat("x", MaxScanBytes+10) + " 4111111111111111"
	code, body := get(t, c, br, "POST", host, "/big", big)
	if code != 200 || body != fmt.Sprintf("origin got %d bytes", len(big)) || len(got.get()) != len(big) {
		t.Fatalf("an oversize body must still arrive complete: %d %q (%d bytes)", code, body, len(got.get()))
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "dlp-skipped-too-large" }) == nil {
		t.Fatal("the unscanned body was not logged, so the gap would be invisible")
	}
}

func TestNoScanningWhenNoRuleUsesDLP(t *testing.T) {
	r := newRig(t)
	o := inspectOrigin(t, r)
	enableInspection(r) // the rig's default policy has no dlp rules
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, c, br, "POST", hostport(o.URL), "/x", "4111111111111111"); code != 200 {
		t.Fatalf("without a dlp rule nothing is blocked on content: %d", code)
	}
}

type keyedState struct {
	*state
	key *ecdsa.PrivateKey
}

func (k keyedState) InterceptKey(string) *ecdsa.PrivateKey { return k.key }

func TestInspectionCertificatesUseTheTenantKey(t *testing.T) { // WB-003 groundwork
	r := newRig(t)
	o := inspectOrigin(t, r)
	enableInspection(r)
	tenantKey := r.leafKeyForTest()
	r.proxy.State = keyedState{state: r.st, key: tenantKey}
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, _, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	got := c.ConnectionState().PeerCertificates[0]
	want, _ := x509.MarshalPKIXPublicKey(&tenantKey.PublicKey)
	have, _ := x509.MarshalPKIXPublicKey(got.PublicKey)
	if string(want) != string(have) {
		t.Fatal("the minted certificate does not carry the tenant's stable key, so the workspace pin would not match")
	}
}
