// Package webproxy is the forward proxy and host classifier (DESIGN.md D3.5).
// RB1 does not decrypt TLS: policy sees the host name only.
package webproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
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
	// Exempt allows specific dial targets that would otherwise be refused as
	// private. nil in production; tests use it for a loopback origin.
	Exempt func(netip.AddrPort) bool

	secret    [32]byte
	once      sync.Once
	mu        sync.Mutex
	usedWarn  map[string]time.Time
	transport *http.Transport
}

func (p *Proxy) init() {
	p.once.Do(func() {
		rand.Read(p.secret[:])
		p.usedWarn = map[string]time.Time{}
		if p.Log == nil {
			p.Log = func(broker.Record) {}
		}
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

func (p *Proxy) identify(r *http.Request) (pki.Identity, policy.User, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return pki.Identity{}, policy.User{}, false
	}
	id, err := p.CA.Verify(r.TLS.PeerCertificates[0], p.Rev)
	if err != nil || id.Role != pki.RoleDevice || broker.Revoked(p.State, nil, id) {
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
	rec := broker.Record{TS: time.Now().UTC(), Tenant: id.Tenant, Kind: "web", User: id.Subject, Device: id.Device,
		Target: net.JoinHostPort(host, strconv.Itoa(port)), EN: p.Name, Event: "open"}
	cats := p.Classifier.Categories(host)
	pol := p.State.Policy(id.Tenant, policy.Web)
	var d policy.Decision
	if pol == nil {
		d = policy.Decision{Action: policy.Deny, Reason: "no-policy"}
	} else {
		d = pol.Evaluate(policy.Request{Kind: policy.Web, User: user, Host: host, Categories: cats, Now: time.Now(),
			Device: policy.Device{ID: id.Device}})
		rec.Version = pol.Version
	}
	rec.Rule, rec.Reason = d.RuleID, d.Reason
	connect := r.Method == http.MethodConnect

	switch d.Action {
	case policy.Deny:
		rec.Action = "deny"
		p.Log(rec)
		blockPage(w, host, cats, ref)
		return
	case policy.Warn:
		if connect {
			rec.Reason = "warn-not-displayable"
		} else if !p.warnPassed(r, id, host) {
			rec.Action = "warn"
			p.Log(rec)
			p.warnPage(w, r, id, host, cats, ref)
			return
		}
	}
	rec.Action = "allow"
	p.Log(rec)
	if connect {
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

func blockPage(w http.ResponseWriter, host string, cats []string, ref string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><title>Blocked</title><h1>This site is blocked</h1>
<p>%s was blocked by your organisation's security policy (category: %s).</p>
<p>If you need access, contact your IT administrator and quote reference <b>%s</b>.</p>`,
		html.EscapeString(host), html.EscapeString(strings.Join(cats, ", ")), ref)
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

func (p *Proxy) warnPage(w http.ResponseWriter, r *http.Request, id pki.Identity, host string, cats []string, ref string) {
	u := *r.URL
	if !u.IsAbs() {
		u.Scheme, u.Host = "http", r.Host
	}
	q := u.Query()
	q.Set("ztx_continue", p.warnToken(id, host, time.Now().Add(warnTTL).Unix()))
	u.RawQuery = q.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><title>Warning</title><h1>Proceed with care</h1>
<p>%s is in a category your organisation flags (%s). Your visit is logged.</p>
<p><a href="%s">Continue anyway</a></p><p>Reference %s</p>`,
		html.EscapeString(host), html.EscapeString(strings.Join(cats, ", ")), html.EscapeString(u.String()), ref)
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
