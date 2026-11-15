//go:build real

package real

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// webSite is the HTTPS origin in the cluster, standing in for a web site. It is reached through a
// node port on the cluster node's address, because the enforcement node runs outside the cluster.
// (The private app of the private-access tests is not exposed this way: it stays dark.)
type webSite struct {
	ip       string
	port     int
	hostport string
	certPEM  []byte
	keyPEM   []byte
	certFile string
	pool     *x509.CertPool
}

// withWebSite is passed to newWorldN: it works out the origin's address and certificate before the
// enforcement nodes start, because they are told to trust that certificate and may dial that address.
func withWebSite(w *world) {
	t := w.t
	ip := strings.TrimSpace(mustSh(t, w.docker+" inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "+w.nodeCtr))
	if net.ParseIP(ip) == nil {
		t.Skipf("cannot find the cluster node's address on the 'kind' docker network (%q): the web tests need a kind cluster", ip)
	}
	site := &webSite{ip: ip, port: 30000 + mrand.Intn(2700)}
	site.hostport = fmt.Sprintf("%s:%d", ip, site.port)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ztx-real-origin"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(ip)}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	site.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	site.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	site.certFile = filepath.Join(w.dir, "origin.pem")
	os.WriteFile(site.certFile, site.certPEM, 0o600)
	site.pool = x509.NewCertPool()
	site.pool.AppendCertsFromPEM(site.certPEM)
	w.site = site
	// lab-only switches, as in the single-machine e2e: the origin is on a private address, and its
	// certificate is not from a public authority
	w.enExtra = append(w.enExtra, "--lab-allow-dial", site.hostport, "--lab-upstream-ca", site.certFile)
}

// deployOrigin runs the origin in the cluster, behind a node port.
func (w *world) deployOrigin() {
	t := w.t
	img := w.loadImage("origin", "originapp")
	w.apply(fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: origin-tls
  labels:
%[1]s
type: kubernetes.io/tls
stringData:
  tls.crt: |
%[2]s
  tls.key: |
%[3]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: origin
  labels:
%[1]s
spec:
  replicas: 1
  selector:
    matchLabels: {app: origin}
  template:
    metadata:
      labels: {app: origin}
    spec:
      containers:
      - name: origin
        image: %[4]s
        imagePullPolicy: IfNotPresent
        args: ["--listen", ":8443"]
        volumeMounts: [{name: tls, mountPath: /tls}]
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 200m, memory: 64Mi}}
      volumes:
      - name: tls
        secret: {secretName: origin-tls}
---
apiVersion: v1
kind: Service
metadata:
  name: origin
  labels:
%[1]s
spec:
  type: NodePort
  selector: {app: origin}
  ports: [{port: 8443, targetPort: 8443, nodePort: %[5]d}]
`, labels, indent(string(w.site.certPEM), "    "), indent(string(w.site.keyPEM), "    "), img, w.site.port))
	w.mustK("rollout status deployment/origin -n " + w.ns + " --timeout=120s")
	eventually(t, "the origin to answer directly", 30*time.Second, func() bool {
		_, err := w.originSeen()
		return err == nil
	})
}

// originSeen reads what the origin has received, bypassing the platform (the test is on the node).
func (w *world) originSeen() ([]string, error) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: w.site.pool}}}
	resp, err := c.Get("https://" + w.site.hostport + "/__seen")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(b)) == "" {
		return nil, nil
	}
	return strings.Split(string(b), "\n"), nil
}

// inspectionPool returns a pool holding the tenant's inspection CA, as a managed device would trust it.
func (w *world) inspectionPool() *x509.CertPool {
	w.t.Helper()
	req, _ := http.NewRequest("GET", w.adminU+"/v1/inspection/ca.pem", nil)
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.admin.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		w.t.Fatalf("no inspection CA: %s", b)
	}
	return p
}

// webResult is what a request through the platform returned.
type webResult struct {
	code   int
	body   string
	issuer string // issuer of the certificate the client was shown
	err    error
}

// get sends a request to the origin through the agent's HTTP proxy, trusting the given roots.
func (w *world) get(a *agentInst, roots *x509.CertPool, method, path, body string, hdr map[string]string) webResult {
	px, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", a.ports["http"]))
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(px), TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}}
	req, _ := http.NewRequest(method, "https://"+w.site.hostport+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return webResult{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := webResult{code: resp.StatusCode, body: string(b)}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.issuer = resp.TLS.PeerCertificates[0].Issuer.CommonName
	}
	return r
}

// putWebPolicy replaces the web policy, tracking the version.
func (w *world) putWebPolicy(def string, rules []map[string]any) {
	w.t.Helper()
	w.must("PUT", "/v1/policies/web", map[string]any{"default_action": def, "rules": rules})
	n := 0
	fmt.Sscan(w.ifMatch, &n)
	w.ifMatch = fmt.Sprint(n + 1)
}

// startWeb sets up the world for web tests: safe defaults (version 1 of the web policy), the origin,
// and an agent. It returns after the platform answers for the origin.
func startWeb(t *testing.T) (*world, *agentInst) {
	w := newWorldN(t, 1, withWebSite)
	w.must("POST", "/v1/policies/safe-defaults", nil)
	w.ifMatch = "1"
	w.deployOrigin()
	a := w.newAgent("laptop", map[string]string{})
	return w, a
}
