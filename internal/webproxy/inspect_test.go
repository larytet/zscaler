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
