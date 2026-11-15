package webproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/dlp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

// Inspector is an optional State extension: whether a tenant's web traffic is
// decrypted, which domains are exempt, and the per-tenant CA that signs the
// certificates shown to its devices (ZIA-040, ARCH-021).
type Inspector interface {
	Inspection(tenant string) (enabled bool, exempt []string, ca *pki.CA)
}

// interceptCA returns the CA to use for this connection, or nil to tunnel it untouched.
func (p *Proxy) interceptCA(tenant, host string) *pki.CA {
	in, ok := p.State.(Inspector)
	if !ok {
		return nil
	}
	enabled, exempt, ca := in.Inspection(tenant)
	if !enabled || ca == nil {
		return nil
	}
	for _, d := range exempt {
		if host == d || strings.HasSuffix(host, "."+d) {
			return nil // exempt: banking, health, certificate-pinned apps
		}
	}
	return ca
}

// leaf returns a certificate for host signed by the tenant's CA, cached.
func (p *Proxy) leaf(tenant, host string, ca *pki.CA) (*tls.Certificate, error) {
	key := tenant + "|" + host
	if v, ok := p.leaves.Load(key); ok {
		if c := v.(*tls.Certificate); c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter.Add(-time.Hour)) {
			return c, nil
		}
	}
	p.leafMu.Lock()
	defer p.leafMu.Unlock()
	signKey := p.leafKey
	if ki, ok := p.State.(interface {
		InterceptKey(string) *ecdsa.PrivateKey
	}); ok {
		if k := ki.InterceptKey(tenant); k != nil {
			signKey = k // the tenant's stable key, so the workspace can pin it
		}
	}
	der, err := ca.SignServer(&signKey.PublicKey, host, 12*time.Hour)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signKey}
	if c.Leaf, err = x509ParseCertificate(der); err != nil {
		return nil, err
	}
	p.leaves.Store(key, c)
	return c, nil
}

// inspect decrypts one CONNECT tunnel and applies the web policy to every request in it.
func (p *Proxy) inspect(w http.ResponseWriter, r *http.Request, id pki.Identity, user policy.User, host string, port int, rec broker.Record, ca *pki.CA) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unsupported", http.StatusInternalServerError)
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		c.Close()
		return
	}
	cert, err := p.leaf(id.Tenant, host, ca)
	if err != nil {
		c.Close()
		return
	}
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		// Most often the device does not trust the tenant's inspection CA, or the app pins
		// its certificate. The admin sees this and can exempt the domain.
		rec.Event, rec.Reason, rec.Action = "close", "inspection-handshake-failed", "allow"
		p.Log(rec)
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	target := net.JoinHostPort(host, strconv.Itoa(port))
	h := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		p.inspectedRequest(w, q, id, user, host, target, rec)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10, IdleTimeout: 60 * time.Second}
	srv.Serve(&oneConn{c: tc, done: make(chan struct{})})
}

func (p *Proxy) inspectedRequest(w http.ResponseWriter, q *http.Request, id pki.Identity, user policy.User, host, target string, base broker.Record) {
	rec := base // carries Workspace from the connection
	rec.TS = time.Now().UTC()
	rec.Inspected = true
	rec.Event = "open"
	// A request for another host inside this tunnel is domain fronting: refuse it.
	if h, _ := splitHost(q.Host); h != host {
		rec.Action, rec.Reason = "deny", "host-mismatch"
		p.Log(rec)
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	pol := p.State.Policy(id.Tenant, policy.Web)
	d := policy.Decision{Action: policy.Deny, Reason: "no-policy"}
	cats := p.Classifier.Categories(host)
	var hits []string
	if pol != nil {
		if pol.UsesDLP() && q.Body != nil && q.Body != http.NoBody && (q.Method == "POST" || q.Method == "PUT" || q.Method == "PATCH") {
			var skipped bool
			hits, skipped = scanBody(q)
			if skipped {
				note := rec // visible in the log: the rule could not see this body
				note.Action, note.Reason = "info", "dlp-skipped-too-large"
				p.Log(note)
			}
		}
		d = pol.Evaluate(policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(),
			Device: policy.Device{ID: id.Device}, Workspace: id.Role == pki.RoleWorkspace, Inspected: true, Path: q.URL.Path, Method: q.Method, DLPHits: hits})
		rec.Version = pol.Version
		rec.DLP = hits
	}
	rec.Rule, rec.Reason = d.RuleID, d.Reason
	ref := refID()
	switch d.Action {
	case policy.Deny:
		rec.Action = "deny"
		p.Log(rec)
		if len(hits) > 0 && d.RuleID != "" && ruleUsesDLP(pol, d.RuleID) {
			dlpBlockPage(w, host, hits, ref)
			return
		}
		blockPage(w, host, cats, ref)
		return
	case policy.Warn:
		q.URL.Scheme, q.URL.Host = "https", q.Host // so the continue link stays on HTTPS
		if !p.warnPassed(q, id, host) {
			rec.Action = "warn"
			p.Log(rec)
			p.warnPage(w, q, id, host, cats, ref)
			return
		}
	}
	rec.Action = "allow"
	p.Log(rec)
	out := q.Clone(q.Context())
	out.RequestURI = ""
	out.URL.Scheme, out.URL.Host = "https", target
	out.Host = q.Host
	for _, hh := range hopHeaders {
		out.Header.Del(hh)
	}
	resp, err := p.tlsTransp.RoundTrip(out)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, hh := range hopHeaders {
		resp.Header.Del(hh)
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	copyBody(w, resp.Body)
}

func splitHost(hp string) (string, string) {
	h, port, err := net.SplitHostPort(hp)
	if err != nil {
		return policy.NormalizeHost(hp), ""
	}
	return policy.NormalizeHost(h), port
}

// oneConn is a listener that yields a single, already-accepted connection.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (o *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	o.once.Do(func() { c = o.c })
	if c != nil {
		return &closeNotify{Conn: c, done: o.done}, nil
	}
	<-o.done // the connection is finished: stop the server
	return nil, errors.New("closed")
}
func (o *oneConn) Close() error   { return nil }
func (o *oneConn) Addr() net.Addr { return o.c.LocalAddr() }

type closeNotify struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// MaxScanBytes is the largest request body that is scanned. A larger body is forwarded
// unscanned and the proxy logs dlp-skipped-too-large, so the gap is visible.
const MaxScanBytes = 1 << 20

// scanBody reads at most MaxScanBytes of the request body, scans it, and puts the body
// back so it can still be forwarded. skipped is true when the body was too large to scan.
func scanBody(q *http.Request) (hits []string, skipped bool) {
	if q.ContentLength > MaxScanBytes {
		return nil, true
	}
	buf, err := io.ReadAll(io.LimitReader(q.Body, MaxScanBytes+1))
	rest := q.Body
	if len(buf) > MaxScanBytes {
		// too large: do not scan a prefix and call it clean; forward everything as it came
		q.Body = readCloser{io.MultiReader(bytes.NewReader(buf), rest), rest}
		return nil, true
	}
	q.Body = io.NopCloser(bytes.NewReader(buf))
	q.ContentLength = int64(len(buf))
	if err != nil {
		return nil, false
	}
	return dlp.Scan(buf), false
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }

func ruleUsesDLP(p *policy.Policy, id string) bool {
	for _, r := range p.Rules {
		if r.ID == id {
			return len(r.Match.DLP) > 0
		}
	}
	return false
}

func dlpBlockPage(w http.ResponseWriter, host string, types []string, ref string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><title>Blocked</title><h1>Upload blocked</h1>
<p>What you sent to %s appears to contain sensitive data (%s) and your organisation does not allow that.</p>
<p>If this is a mistake, contact your IT administrator and quote reference <b>%s</b>.</p>`,
		html.EscapeString(host), html.EscapeString(strings.Join(types, ", ")), ref)
}
