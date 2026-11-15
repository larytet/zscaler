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
	"github.com/larytet/zscaler/internal/filetype"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
	"github.com/larytet/zscaler/internal/tenancy"
)

// Inspector is an optional State extension: whether a tenant's web traffic is
// decrypted, which domains are exempt, and the per-tenant CA that signs the
// certificates shown to its devices (ZIA-040, ARCH-021).
type Inspector interface {
	Inspection(tenant string) (enabled bool, exempt []string, ca *pki.CA)
}

// SecretSource is an optional State extension: stored credentials to inject (AGS-001).
type SecretSource interface {
	Secret(tenant, name string) (store.Secret, bool)
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
		rec.Action, rec.Reason, rec.Ref = "deny", "host-mismatch", refID()
		p.Log(rec)
		errorPage(w, http.StatusMisdirectedRequest, "Request refused", reasonText("host-mismatch", nil), rec.Ref)
		return
	}
	pol := p.State.Policy(id.Tenant, policy.Web)
	d := policy.Decision{Action: policy.Deny, Reason: "no-policy"}
	cats := p.Classifier.Categories(host)
	cat := p.catalog(id.Tenant)
	var hits, files []string
	if pol != nil {
		if (pol.UsesDLP() || pol.UsesUploadFileTypes()) && q.Body != nil && q.Body != http.NoBody && (q.Method == "POST" || q.Method == "PUT" || q.Method == "PATCH") {
			var skipped bool
			hits, files, skipped = scanBody(q, p.edmSets(id.Tenant), pol.UsesDLP(), pol.UsesUploadFileTypes())
			if skipped {
				note := rec // visible in the log: the rule could not see this body
				note.Action, note.Reason = "info", "dlp-skipped-too-large"
				p.Log(note)
			}
		}
		d = pol.Evaluate(policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(),
			Device: policy.Device{ID: id.Device}, Workspace: id.Role == pki.RoleWorkspace, Inspected: true, Path: q.URL.Path, Method: q.Method, DLPHits: hits, UploadFiles: files,
			CloudApps: cat.AppsFor(host), CloudActions: cat.ActionsFor(host, q.Method, q.URL.Path)})
		rec.Version = pol.Version
		rec.DLP = hits
		if d.Action == policy.Deny && len(files) > 0 && ruleUsesUploadFileTypes(pol, d.RuleID) {
			rec.FileTypes = files
		}
	}
	rec.Rule, rec.Reason = d.RuleID, d.Reason
	ref := refID()
	// ZIA-022b: a rule that asks for capture keeps the exchange. Take the request body prefix now,
	// handing the body back whole so forwarding is unchanged.
	var reqBody []byte
	var reqTrunc bool
	if d.Capture {
		reqBody, q.Body, reqTrunc = takePrefix(q.Body, CaptureMaxBody)
	}
	switch d.Action {
	case policy.Deny:
		rec.Action, rec.Ref = "deny", ref
		p.Log(rec)
		if d.Capture {
			p.Log(captureRecord(rec, d.RuleID, "deny", q, reqBody, http.StatusForbidden, nil, nil, reqTrunc))
		}
		if len(rec.FileTypes) > 0 {
			fileBlockPage(w, host, "upload", rec.FileTypes, ref, reasonText(d.Reason, nil))
			return
		}
		if len(hits) > 0 && d.RuleID != "" && ruleUsesDLP(pol, d.RuleID) {
			dlpBlockPage(w, host, hits, ref, reasonText(d.Reason, nil))
			return
		}
		blockPage(w, host, cats, ref, reasonText(d.Reason, cats))
		return
	case policy.Warn:
		q.URL.Scheme, q.URL.Host = "https", q.Host // so the continue link stays on HTTPS
		if !p.warnPassed(q, id, host) {
			rec.Action, rec.Ref = "warn", ref
			p.Log(rec)
			if d.Capture {
				p.Log(captureRecord(rec, d.RuleID, "warn", q, reqBody, http.StatusOK, nil, nil, reqTrunc))
			}
			p.warnPage(w, q, id, host, cats, ref, warnReason(d.Reason, cats))
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
	if ts, ok := p.State.(TenancySource); ok {
		if vendor, hs := ts.TenancyHeaders(id.Tenant, host); len(hs) > 0 {
			for _, h := range hs {
				out.Header.Set(h.Name, h.Value) // replaces any value the client sent: a person cannot lift the restriction
			}
			note := rec
			note.Action, note.Reason = "info", "tenancy-restriction:"+vendor
			p.Log(note)
		}
	}
	var injected string // the secret value, kept only to scrub it from anything recorded or returned
	if d.Inject != "" {
		ss, _ := p.State.(SecretSource)
		var sc store.Secret
		ok := false
		if ss != nil {
			sc, ok = ss.Secret(id.Tenant, d.Inject)
		}
		h := strings.ToLower(host)
		sh := strings.ToLower(sc.Host)
		if !ok || !(h == sh || strings.HasSuffix(h, "."+sh)) {
			// missing secret or a host it is not bound to: refuse rather than send the request without it
			fail := rec
			fail.Action, fail.Reason, fail.Ref = "deny", "secret-unavailable", ref
			p.Log(fail)
			errorPage(w, http.StatusBadGateway, "Service unavailable", reasonText("secret-unavailable", nil), ref)
			return
		}
		out.Header.Set(sc.Header, sc.Value) // replaces whatever the agent sent
		out.Header.Del("Accept-Encoding")   // the transport then decompresses, so the response can be scrubbed
		injected = sc.Value
		note := rec
		note.Action, note.Reason = "info", "injected:"+d.Inject
		p.Log(note)
	}
	scanResp := pol != nil && pol.UsesResponseDLP()
	if scanResp {
		out.Header.Del("Accept-Encoding") // lets the transport ask for gzip itself and decompress, so the scan sees plain text
	}
	resp, err := p.tlsTransp.RoundTrip(out)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if pol != nil && pol.UsesDownloadFileTypes() {
		if p.checkDownload(w, resp, pol, id, user, host, q, cats, rec) {
			if d.Capture {
				p.Log(captureRecord(rec, d.RuleID, "deny", q, reqBody, http.StatusForbidden, nil, nil, reqTrunc))
			}
			return
		}
	}
	if scanResp && textual(resp.Header.Get("Content-Type")) {
		if blocked := p.scanResponse(w, resp, pol, id, user, host, cats, rec); blocked {
			if d.Capture {
				p.Log(captureRecord(rec, d.RuleID, "deny", q, reqBody, http.StatusForbidden, nil, nil, reqTrunc))
			}
			return
		}
	}
	if injected != "" {
		// an API that echoes its request headers would hand the credential back to the agent: scrub it
		if !scrubInjected(resp, injected) {
			errorPage(w, http.StatusBadGateway, "Service unavailable", "The answer was too large to check for a credential that the platform added to the request, so it was not passed on.", ref)
			return
		}
	}
	if d.Capture {
		var respBody []byte
		var respTrunc bool
		respBody, resp.Body, respTrunc = takePrefix(resp.Body, CaptureMaxBody)
		p.Log(captureRecord(rec, d.RuleID, "allow", q, reqBody, resp.StatusCode, resp.Header, respBody, reqTrunc || respTrunc))
	}
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
// TenancySource is an optional State extension: the sign-in restriction headers for a host (DATA-002a).
type TenancySource interface {
	TenancyHeaders(tenant, host string) (string, []tenancy.Header)
}

// EDMSource is an optional State extension: a tenant's exact-data-match sets (DATA-006).
type EDMSource interface {
	EDM(tenant string) map[string]*dlp.EDM
}

func (p *Proxy) edmSets(tenant string) map[string]*dlp.EDM {
	if es, ok := p.State.(EDMSource); ok {
		return es.EDM(tenant)
	}
	return nil
}

func scanBody(q *http.Request, sets map[string]*dlp.EDM, wantDLP, wantFiles bool) (hits, files []string, skipped bool) {
	if q.ContentLength > MaxScanBytes {
		return nil, nil, true
	}
	buf, err := io.ReadAll(io.LimitReader(q.Body, MaxScanBytes+1))
	rest := q.Body
	if len(buf) > MaxScanBytes {
		// too large: do not scan a prefix and call it clean; forward everything as it came
		q.Body = readCloser{io.MultiReader(bytes.NewReader(buf), rest), rest}
		return nil, nil, true
	}
	q.Body = io.NopCloser(bytes.NewReader(buf))
	q.ContentLength = int64(len(buf))
	if err != nil {
		return nil, nil, false
	}
	if wantDLP {
		hits = dlp.ScanWith(buf, sets)
	}
	if wantFiles {
		files = filetype.Upload(q.Header.Get("Content-Type"), q.URL.Path, buf)
	}
	return hits, files, false
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

func dlpBlockPage(w http.ResponseWriter, host string, types []string, ref, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><title>Blocked</title><h1>Upload blocked</h1>
<p>What you sent to %s appears to contain sensitive data (%s) and your organisation does not allow that.</p>
%s`, html.EscapeString(host), html.EscapeString(strings.Join(types, ", ")), pageTail(why, ref))
}

// textual reports whether a content type is something a scan can read as text.
func textual(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return strings.HasPrefix(ct, "text/") || strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml") ||
		ct == "application/json" || ct == "application/xml" || ct == "application/x-www-form-urlencoded" ||
		ct == "application/javascript" || ct == "application/x-ndjson" || ct == "text/event-stream"
}

// scanResponse reads at most MaxScanBytes of the response, evaluates the response rules, and
// either writes a block page (returning true) or leaves resp.Body ready to be copied to the
// user. A response too large to scan is forwarded whole and the gap is logged.
func (p *Proxy) scanResponse(w http.ResponseWriter, resp *http.Response, pol *policy.Policy, id pki.Identity, user policy.User,
	host string, cats []string, base broker.Record) bool {
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, MaxScanBytes+1))
	if len(buf) > MaxScanBytes {
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
		note := base
		note.Action, note.Reason, note.TS = "info", "dlp-response-skipped-too-large", time.Now().UTC()
		p.Log(note)
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	resp.ContentLength = int64(len(buf))
	resp.Header.Del("Content-Length")
	hits := dlp.ScanWith(buf, p.edmSets(id.Tenant))
	if len(hits) == 0 {
		return false
	}
	d := pol.EvaluateResponse(policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(),
		Device: policy.Device{ID: id.Device}, Workspace: id.Role == pki.RoleWorkspace, Inspected: true, ResponseDLPHits: hits})
	if d.Action != policy.Deny {
		return false
	}
	rec := base
	rec.TS, rec.Action, rec.Rule, rec.Reason, rec.DLP, rec.Inspected = time.Now().UTC(), "deny", d.RuleID, "dlp-response", hits, true
	rec.Ref = refID()
	p.Log(rec)
	responseBlockPage(w, host, hits, rec.Ref, reasonText("dlp-response", nil))
	return true
}

func responseBlockPage(w http.ResponseWriter, host string, types []string, ref, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><title>Blocked</title><h1>Response blocked</h1>
<p>What %s sent back appears to contain sensitive data (%s) and your organisation does not allow that to reach you.</p>
%s`, html.EscapeString(host), html.EscapeString(strings.Join(types, ", ")), pageTail(why, ref))
}

// MaxInjectedResponse bounds a response that must be scrubbed of an injected credential.
const MaxInjectedResponse = 8 << 20

// scrubInjected replaces the secret in the response headers and body. It reports false when the
// body is too large to check, in which case nothing may be forwarded.
func scrubInjected(resp *http.Response, secret string) bool {
	const mask = "[redacted]"
	for k, vs := range resp.Header {
		for i, v := range vs {
			if strings.Contains(v, secret) {
				vs[i] = strings.ReplaceAll(v, secret, mask)
			}
		}
		resp.Header[k] = vs
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxInjectedResponse+1))
	resp.Body.Close()
	if err != nil || len(b) > MaxInjectedResponse {
		return false
	}
	b = bytes.ReplaceAll(b, []byte(secret), []byte(mask))
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding") // Transport only decompresses what it asked for; an encoded body cannot be scanned
	return true
}

func ruleUsesUploadFileTypes(p *policy.Policy, id string) bool {
	for _, r := range p.Rules {
		if r.ID == id {
			return len(r.Match.UploadFileTypes) > 0
		}
	}
	return false
}

// checkDownload looks at the start of a response for its kind of file and refuses it if a rule says
// so (ZIA-013). Only the first few KiB are read; the rest streams on unchanged, so a large download is
// not held in memory. It reports whether it wrote a block page.
func (p *Proxy) checkDownload(w http.ResponseWriter, resp *http.Response, pol *policy.Policy, id pki.Identity, user policy.User,
	host string, q *http.Request, cats []string, base broker.Record) bool {
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body = readCloser{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	files := filetype.Download(resp.Header.Get("Content-Disposition"), q.URL.Path, resp.Header.Get("Content-Type"), head)
	if len(files) == 0 {
		return false
	}
	d := pol.EvaluateResponse(policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(),
		Device: policy.Device{ID: id.Device}, Workspace: id.Role == pki.RoleWorkspace, Inspected: true, DownloadFiles: files})
	if d.Action != policy.Deny {
		return false
	}
	rec := base
	rec.TS, rec.Action, rec.Rule, rec.Reason, rec.FileTypes, rec.Inspected = time.Now().UTC(), "deny", d.RuleID, "file-type-download", files, true
	rec.Ref = refID()
	p.Log(rec)
	resp.Body.Close()
	fileBlockPage(w, host, "download", files, rec.Ref, reasonText("file-type-download", nil))
	return true
}

func fileBlockPage(w http.ResponseWriter, host, direction string, types []string, ref, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><title>Blocked</title><h1>File blocked</h1>
<p>A file you tried to %s with %s looks like a kind your organisation does not allow (%s).</p>
%s`, direction, html.EscapeString(host), html.EscapeString(strings.Join(types, ", ")), pageTail(why, ref))
}
