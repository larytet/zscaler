// Package webproxy is the forward proxy and host classifier (DESIGN.md D3.5).
// RB1 does not decrypt TLS: policy sees the host name only.
package webproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/larytet/zscaler/internal/cloudapps"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

// Classifier maps domains to categories by walking suffixes.
type Classifier struct{ m map[string][]string }

func NewClassifier(lists map[string][]string) *Classifier {
	c := &Classifier{m: map[string][]string{}}
	for cat, domains := range lists {
		for _, d := range domains {
			d = policy.NormalizeHost(d)
			c.m[d] = append(c.m[d], cat)
		}
	}
	return c
}

// Categories returns every category of host or any parent domain.
func (c *Classifier) Categories(host string) []string {
	host = policy.NormalizeHost(host)
	var out []string
	for {
		out = append(out, c.m[host]...)
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return out
		}
		host = host[i+1:]
	}
}

type Proxy struct {
	CA         *pki.CA
	Rev        *pki.Revocations
	State      broker.State
	Classifier *Classifier
	Log        func(broker.Record)
	Name       string
	// SinkHealthy, when set, says whether the decision log can be written; a tenant chooses what happens to
	// new requests when it cannot (NFR-012).
	SinkHealthy func() bool
	// Exempt allows specific dial targets that would otherwise be refused as
	// private. nil in production; tests use it for a loopback origin.
	Exempt func(netip.AddrPort) bool

	secret    [32]byte
	once      sync.Once
	mu        sync.Mutex
	usedWarn  map[string]time.Time
	transport *http.Transport
	idCache   sync.Map
	// UpstreamRoots are extra trusted roots for verifying origin servers of inspected
	// connections (lab use; nil means the system roots only).
	UpstreamRoots *x509.CertPool

	leafKey   *ecdsa.PrivateKey
	leafMu    sync.Mutex
	leaves    sync.Map // tenant|host -> *tls.Certificate
	tlsTransp *http.Transport
}

func (p *Proxy) init() {
	p.once.Do(func() {
		rand.Read(p.secret[:])
		p.usedWarn = map[string]time.Time{}
		if p.Log == nil {
			p.Log = func(broker.Record) {}
		}
		p.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p.tlsTransp = &http.Transport{DialContext: p.safeDialer().DialContext, TLSClientConfig: &tls.Config{RootCAs: p.UpstreamRoots, MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
		p.transport = &http.Transport{DialContext: p.safeDialer().DialContext,
			MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	})
}

// Server returns an http.Server wired for mTLS with the header limits from the design.
func (p *Proxy) Server(cert tls.Certificate) *http.Server {
	p.init()
	return &http.Server{Handler: p, MaxHeaderBytes: 16 << 10, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: p.CA.Pool(),
			ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}}
}

// blocked reports addresses the proxy must never connect to.
func blocked(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("169.254.169.254") ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("fc00::/7").Contains(a)
}

// safeDialer checks the address after DNS resolution, at connect time, which
// defeats rebinding (WEB-009).
func (p *Proxy) safeDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("bad address")
		}
		if blocked(ap.Addr()) && (p.Exempt == nil || !p.Exempt(ap)) {
			return fmt.Errorf("destination not allowed")
		}
		return nil
	}}
}

type cachedID struct {
	id  pki.Identity
	exp time.Time
}

// verifyCached checks the certificate chain at most once a minute per
// certificate. Revocation is NOT cached: callers check it on every request.
func (p *Proxy) verifyCached(c *x509.Certificate) (pki.Identity, error) {
	key := sha256.Sum256(c.Raw)
	if v, ok := p.idCache.Load(key); ok {
		if ci := v.(cachedID); time.Now().Before(ci.exp) {
			return ci.id, nil
		}
	}
	id, err := p.CA.Verify(c, nil)
	if err != nil {
		return id, err
	}
	p.idCache.Store(key, cachedID{id, time.Now().Add(time.Minute)})
	return id, nil
}

func (p *Proxy) identify(r *http.Request) (pki.Identity, policy.User, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return pki.Identity{}, policy.User{}, false
	}
	id, err := p.verifyCached(r.TLS.PeerCertificates[0])
	if err != nil || (id.Role != pki.RoleDevice && id.Role != pki.RoleWorkspace) || broker.Revoked(p.State, p.Rev, id) {
		return id, policy.User{}, false
	}
	u, ok := p.State.User(id.Tenant, id.Subject)
	return id, u, ok
}

func refID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// CloudAppSource is an optional State extension: the apps a tenant sees for cloud app control (ZIA-011).
type CloudAppSource interface {
	CloudCatalog(tenant string) *cloudapps.Catalog
}

var builtinCatalog = cloudapps.NewCatalog(nil)

func (p *Proxy) catalog(tenant string) *cloudapps.Catalog {
	if cs, ok := p.State.(CloudAppSource); ok {
		return cs.CloudCatalog(tenant)
	}
	return builtinCatalog
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	id, user, ok := p.identify(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusProxyAuthRequired)
		return
	}
	host, port := splitHostPort(r)
	if host == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ref := refID()
	ws := id.Role == pki.RoleWorkspace
	rec := broker.Record{Workspace: ws, TS: time.Now().UTC(), Tenant: id.Tenant, Kind: "web", User: id.Subject, Device: id.Device,
		Target: net.JoinHostPort(host, strconv.Itoa(port)), EN: p.Name, Event: "open"}
	if refuse, note := broker.FailureGate(p.State, id.Tenant, p.SinkHealthy); refuse != "" {
		rec.Action, rec.Reason, rec.Ref = "deny", refuse, ref
		p.Log(rec)
		errorPage(w, http.StatusServiceUnavailable, "Temporarily unavailable", reasonText(refuse, nil), ref)
		return
	} else if note != "" { // going on although something is wrong: say so in the log
		nr := rec
		nr.Action, nr.Reason = "info", note
		p.Log(nr)
	}
	cats := p.Classifier.Categories(host)
	pol := p.State.Policy(id.Tenant, policy.Web)
	var d policy.Decision
	if pol == nil {
		d = policy.Decision{Action: policy.Deny, Reason: "no-policy"}
	} else {
		cat := p.catalog(id.Tenant)
		req := policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(), Workspace: ws,
			Device: policy.Device{ID: id.Device}, CloudApps: cat.AppsFor(host)}
		if r.Method != http.MethodConnect && r.URL != nil { // a plain request: its method and path are in the clear
			req.CloudActions = cat.ActionsFor(host, r.Method, r.URL.Path)
			req.Method, req.Path = r.Method, r.URL.Path
		}
		d = pol.Evaluate(req)
		rec.Version = pol.Version
	}
	rec.Rule, rec.Reason = d.RuleID, d.Reason
	connect := r.Method == http.MethodConnect
	if d.Inject != "" && d.Action == policy.Allow && (!connect || p.interceptCA(id.Tenant, host) == nil) {
		// a credential is only added to traffic the proxy decrypts; anything else (plain HTTP, an
		// exempt domain, inspection off) is refused rather than sent without it or tunnelled untouched
		d = policy.Decision{Action: policy.Deny, RuleID: d.RuleID, Reason: "inspection-required"}
		rec.Reason = d.Reason
	}

	switch d.Action {
	case policy.Deny:
		rec.Action, rec.Ref = "deny", ref
		p.Log(rec)
		blockPage(w, host, cats, ref, reasonText(d.Reason, cats))
		return
	case policy.Warn:
		if connect {
			rec.Reason = "warn-not-displayable"
		} else if !p.warnPassed(r, id, host) {
			rec.Action, rec.Ref = "warn", ref
			p.Log(rec)
			p.warnPage(w, r, id, host, cats, ref, warnReason(d.Reason, cats))
			return
		}
	}
	rec.Action = "allow"
	p.Log(rec)
	if connect {
		if ca := p.interceptCA(id.Tenant, host); ca != nil {
			p.inspect(w, r, id, user, host, port, rec, ca)
			return
		}
		p.tunnel(w, r, rec)
	} else {
		p.forward(w, r, rec)
	}
}

func splitHostPort(r *http.Request) (string, int) {
	h := r.Host
	def := 80
	if r.Method == http.MethodConnect {
		def = 443
	} else if r.URL != nil && r.URL.Host != "" {
		h = r.URL.Host
		if r.URL.Scheme == "https" {
			def = 443
		}
	}
	host, ps, err := net.SplitHostPort(h)
	if err != nil {
		host, ps = strings.Trim(h, "[]"), ""
	}
	port := def
	if ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0
		}
		port = n
	}
	return policy.NormalizeHost(host), port
}

// reasonTexts turns the reason codes the proxy and the policy engine give into a sentence a person can
// act on (ZIA-014). A reason that is not a code is the text an admin wrote on the rule, and is shown as it is.
var reasonTexts = map[string]string{
	"default":              "Your organisation's web policy has no rule that allows this site.",
	"no-policy":            "Your organisation has not set up a web policy yet, so nothing is allowed.",
	"user-disabled":        "Your account has been disabled.",
	"device-revoked":       "This device has been removed from your organisation's access.",
	"evaluation-error":     "The policy could not be checked, so access was refused to be safe.",
	"inspection-required":  "This site would need its traffic to be checked, and that is not possible for it, so it is refused.",
	"secret-unavailable":   "A credential that this service needs from your organisation is not available.",
	"host-mismatch":        "The request named a different site from the one the connection was made to.",
	"workspace-required":   "This site can only be opened in your organisation's protected workspace browser.",
	"file-type-download":   "Your organisation does not allow this kind of file to be downloaded.",
	"dlp-response":         "What the site sent back appears to contain sensitive data.",
	"approval-required":    "This needs an approval from your administrator first.",
	"state-stale":          "Your organisation's security service has not been reachable for a while, so new connections are refused to be safe.",
	"log-sink-unavailable": "The security log cannot be written right now, so new connections are refused to be safe.",
}

// reasonText returns the sentence for a decision. code is the decision's reason (a code or an admin's
// text); cats are the site's categories.
func reasonText(code string, cats []string) string {
	if t, ok := reasonTexts[code]; ok {
		return t
	}
	if code != "" {
		return code
	}
	if len(cats) > 0 {
		return "The site is in a category your organisation blocks (" + strings.Join(cats, ", ") + ")."
	}
	return "A rule in your organisation's web policy does not allow this."
}

// pageTail is what every block page ends with: the reason and the reference to quote.
// The pages a person sees when the proxy stops them are one shape (GAP-REQ-09): a language, a title, one
// heading inside a main region, a viewport so they read on a phone, text that follows the reader's font
// size, and colours that keep their contrast in a light or a dark setting (a test computes it).
const pageStyle = `body{font:1rem/1.5 system-ui,sans-serif;margin:0;padding:1rem;color:#1b1f24;background:#fff}` +
	`main{max-width:40rem;margin:2rem auto}h1{font-size:1.5rem;line-height:1.25}a{color:#0a4fd6}` +
	`@media (prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}a{color:#79b0ff}}`

func pageOpen(title, heading string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>` +
		html.EscapeString(title) + `</title><style>` + pageStyle + `</style></head><body><main><h1>` + html.EscapeString(heading) + `</h1>`
}

const pageClose = `</main></body></html>`

func pageTail(why, ref string) string {
	return fmt.Sprintf(`<p><b>Why:</b> %s</p>
<p>If you need access, contact your IT administrator and quote reference <b>%s</b>. They can find it in the decision log.</p>`,
		html.EscapeString(why), html.EscapeString(ref))
}

func blockPage(w http.ResponseWriter, host string, cats []string, ref, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, pageOpen("Blocked", "This site is blocked"))
	fmt.Fprintf(w, `<p>%s was blocked by your organisation's security policy%s.</p>
%s`, html.EscapeString(host), categoryNote(cats), pageTail(why, ref))
	fmt.Fprint(w, pageClose)
}

// categoryNote says which categories the site is in, when it has any: users and admins both want to see it.
func categoryNote(cats []string) string {
	if len(cats) == 0 {
		return ""
	}
	return " (category: " + html.EscapeString(strings.Join(cats, ", ")) + ")"
}

// errorPage answers a request the proxy cannot serve for a reason of its own (not a policy block),
// with the reason and a reference in the log, instead of a bare status line.
func errorPage(w http.ResponseWriter, status int, title, why, ref string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, pageOpen(title, title))
	fmt.Fprint(w, pageTail(why, ref))
	fmt.Fprint(w, pageClose)
}

const warnTTL = 5 * time.Minute

func (p *Proxy) warnToken(id pki.Identity, host string, exp int64) string {
	m := hmac.New(sha256.New, p.secret[:])
	fmt.Fprintf(m, "%s|%s|%s|%d", id.Tenant, id.Subject, host, exp)
	return strconv.FormatInt(exp, 10) + "." + hex.EncodeToString(m.Sum(nil))
}

// warnPassed validates and consumes a single-use continue token, then strips it from the URL.
func (p *Proxy) warnPassed(r *http.Request, id pki.Identity, host string) bool {
	q := r.URL.Query()
	tok := q.Get("ztx_continue")
	if tok == "" {
		return false
	}
	q.Del("ztx_continue")
	r.URL.RawQuery = q.Encode()
	exp, err := strconv.ParseInt(strings.SplitN(tok, ".", 2)[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	if !hmac.Equal([]byte(tok), []byte(p.warnToken(id, host, exp))) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, used := p.usedWarn[tok]; used {
		return false
	}
	p.usedWarn[tok] = time.Now()
	for k, t := range p.usedWarn { // prune
		if time.Since(t) > 2*warnTTL {
			delete(p.usedWarn, k)
		}
	}
	return true
}

// warnReason is the sentence on a warning page: the admin's text on the rule if there is one, else the
// category, else a plain statement.
func warnReason(code string, cats []string) string {
	switch {
	case code != "" && reasonTexts[code] == "":
		return code
	case len(cats) > 0:
		return "The site is in a category your organisation flags (" + strings.Join(cats, ", ") + ")."
	}
	return "A rule in your organisation's web policy asks for care with this site."
}

func (p *Proxy) warnPage(w http.ResponseWriter, r *http.Request, id pki.Identity, host string, cats []string, ref, why string) {
	u := *r.URL
	if !u.IsAbs() {
		u.Scheme, u.Host = "http", r.Host
		if r.TLS != nil { // inside an inspected tunnel
			u.Scheme = "https"
		}
	}
	q := u.Query()
	q.Set("ztx_continue", p.warnToken(id, host, time.Now().Add(warnTTL).Unix()))
	u.RawQuery = q.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, pageOpen("Warning", "Proceed with care"))
	defer fmt.Fprint(w, pageClose)
	fmt.Fprintf(w, `<p>Your organisation asks you to take care with %s. Your visit is logged.</p>
<p><b>Why:</b> %s</p>
<p><a href="%s">Continue anyway</a></p>
<p>If you need to ask about this, quote reference <b>%s</b>. Your IT administrator can find it in the decision log.</p>`,
		html.EscapeString(host), html.EscapeString(why), html.EscapeString(u.String()), html.EscapeString(ref))
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, rec broker.Record) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		rec.Event, rec.Reason = "close", "connect-failed"
		p.Log(rec)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	rec.Event, rec.BytesDwn = "close", n
	p.Log(rec)
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, rec broker.Record) {
	up, err := p.safeDialer().DialContext(r.Context(), "tcp", rec.Target)
	if err != nil {
		rec.Event, rec.Reason = "close", "connect-failed"
		p.Log(rec)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "unsupported", http.StatusInternalServerError)
		return
	}
	c, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	done := make(chan int64, 2)
	go func() { n, _ := io.Copy(up, buf); up.(*net.TCPConn).CloseWrite(); done <- n }()
	go func() { n, _ := io.Copy(c, up); closeWrite(c); done <- n }()
	rec.BytesUp = <-done
	rec.BytesDwn = <-done
	up.Close()
	c.Close()
	rec.Event = "close"
	p.Log(rec)
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func x509ParseCertificate(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }

func copyBody(w http.ResponseWriter, r io.Reader) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
