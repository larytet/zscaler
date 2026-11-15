// Package broker implements the enforcement node's private-access path:
// mTLS listener, connector registry, policy decision and stream stitching
// (DESIGN.md D3.2 to D3.4), plus the connector and agent-side clients.
package broker

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/mux"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/posture"
)

type Target struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

type Segment struct {
	ID      string   `json:"id"`
	Group   string   `json:"group"` // connector group
	Targets []Target `json:"targets"`
}

// State is the EN's cached view of tenant configuration.
type State interface {
	Policy(tenant string, k policy.Kind) *policy.Policy
	Segment(tenant, id string) (Segment, bool)
	User(tenant, subject string) (policy.User, bool)
}

// Record is one decision log entry (DESIGN.md D2.5).
type Record struct {
	TS       time.Time `json:"ts"`
	Tenant   string    `json:"tenant"`
	Kind     string    `json:"kind"`
	User     string    `json:"user,omitempty"`
	Device   string    `json:"device,omitempty"`
	App      string    `json:"app,omitempty"`
	Target   string    `json:"target,omitempty"`
	Action   string    `json:"action"`
	Rule     string    `json:"rule,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Version  int       `json:"policy_version"`
	EN       string    `json:"en,omitempty"`
	BytesUp  int64     `json:"bytes_up,omitempty"`
	BytesDwn int64     `json:"bytes_down,omitempty"`
	Event    string    `json:"event,omitempty"` // "open" or "close"
}

type openReq struct {
	T    string `json:"t"` // "open" | "posture"
	App  string `json:"app,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	Tok  string `json:"token,omitempty"`
}

type EN struct {
	Name           string
	CA             *pki.CA
	Rev            *pki.Revocations
	State          State
	Log            func(Record)
	Cert           tls.Certificate
	ReevalEvery    time.Duration // default 5 min
	ConnectTimeout time.Duration // default 5 s
	Logger         *slog.Logger

	mu         sync.Mutex
	connectors map[string][]*connector // tenant/group
	rr         atomic.Uint64
	sessions   map[*session]struct{}
	live       map[*mux.Session]struct{}
	closed     bool
}

type connector struct {
	id   string
	sess *mux.Session
}

type session struct {
	tenant, device, user string
	a, b                 io.Closer
	req                  func() policy.Request
	pol                  func() *policy.Policy
}

func (e *EN) init() {
	if e.connectors == nil {
		e.connectors = map[string][]*connector{}
		e.sessions = map[*session]struct{}{}
		e.live = map[*mux.Session]struct{}{}
	}
	if e.ReevalEvery == 0 {
		e.ReevalEvery = 5 * time.Minute
	}
	if e.ConnectTimeout == 0 {
		e.ConnectTimeout = 5 * time.Second
	}
	if e.Log == nil {
		e.Log = func(Record) {}
	}
	if e.Logger == nil {
		e.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

func (e *EN) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{e.Cert},
		ClientCAs:    e.CA.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// Serve accepts connections until the listener closes.
func (e *EN) Serve(ln net.Listener) error {
	e.mu.Lock()
	e.init()
	e.mu.Unlock()
	go e.reevalLoop()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go e.handle(c)
	}
}

func (e *EN) Close() {
	e.mu.Lock()
	e.closed = true
	live := e.live
	e.live = map[*mux.Session]struct{}{}
	e.mu.Unlock()
	for s := range live {
		s.Close()
	}
}

func (e *EN) handle(raw net.Conn) {
	tc := tls.Server(raw, e.TLSConfig())
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return
	}
	raw.SetDeadline(time.Time{})
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		raw.Close()
		return
	}
	id, err := e.CA.Verify(certs[0], e.Rev)
	if err != nil {
		e.Logger.Info("client cert rejected", "err", err)
		raw.Close()
		return
	}
	sess := mux.New(tc, mux.Config{Server: true})
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		sess.Close()
		return
	}
	e.live[sess] = struct{}{}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.live, sess)
		e.mu.Unlock()
		sess.Close()
	}()
	switch id.Role {
	case pki.RoleConnector:
		e.serveConnector(id, sess)
	case pki.RoleDevice:
		e.serveDevice(id, certs[0], sess)
	default:
		e.Logger.Info("unexpected role", "role", id.Role)
	}
}

func (e *EN) serveConnector(id pki.Identity, sess *mux.Session) {
	key := id.Tenant + "/" + id.Subject // subject carries the connector group
	c := &connector{id: id.Device, sess: sess}
	e.mu.Lock()
	e.connectors[key] = append(e.connectors[key], c)
	e.mu.Unlock()
	<-sess.Done()
	e.mu.Lock()
	list := e.connectors[key]
	for i, x := range list {
		if x == c {
			e.connectors[key] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	e.mu.Unlock()
}

func (e *EN) pick(tenant, group string, skip map[*connector]bool) *connector {
	e.mu.Lock()
	defer e.mu.Unlock()
	var alive []*connector
	for _, c := range e.connectors[tenant+"/"+group] {
		if !skip[c] {
			select {
			case <-c.sess.Done():
			default:
				alive = append(alive, c)
			}
		}
	}
	if len(alive) == 0 {
		return nil
	}
	return alive[int(e.rr.Add(1))%len(alive)]
}

type deviceState struct {
	mu      sync.Mutex
	posture *policy.Posture
}

func (d *deviceState) get() *policy.Posture {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.posture
}

func (e *EN) serveDevice(id pki.Identity, cert *x509.Certificate, sess *mux.Session) {
	ds := &deviceState{}
	replay := posture.NewReplay()
	for {
		st, meta, err := sess.Accept()
		if err != nil {
			return
		}
		var rq openReq
		if json.Unmarshal(meta, &rq) != nil {
			st.Reject("bad-request")
			continue
		}
		switch rq.T {
		case "posture":
			e.onPosture(id, cert, ds, replay, st, rq)
		case "open":
			go e.open(id, ds, st, rq)
		default:
			st.Reject("bad-request")
		}
	}
}

func (e *EN) onPosture(id pki.Identity, cert *x509.Certificate, ds *deviceState, rp *posture.Replay, st *mux.Stream, rq openReq) {
	ec, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		st.Reject("bad-key")
		return
	}
	r, err := posture.Verify(ec, rq.Tok)
	if err != nil || r.DeviceID != id.Device {
		st.Reject("bad-posture")
		return
	}
	if err := rp.Check(r); err != nil {
		st.Reject("replay")
		return
	}
	ds.mu.Lock()
	ds.posture = r.ToPolicy()
	ds.mu.Unlock()
	st.Accept()
	st.Close()
}

func (e *EN) logRec(r Record) {
	r.TS = time.Now().UTC()
	r.EN = e.Name
	e.Log(r)
}

func (e *EN) open(id pki.Identity, ds *deviceState, st *mux.Stream, rq openReq) {
	rec := Record{Tenant: id.Tenant, Kind: "private", User: id.Subject, Device: id.Device, App: rq.App, Event: "open"}
	deny := func(code, reason string) {
		rec.Action, rec.Reason = "deny", reason
		e.logRec(rec)
		st.Reject(code)
	}
	if _, ok := e.State.User(id.Tenant, id.Subject); !ok {
		deny("policy", "unknown-user")
		return
	}
	seg, ok := e.State.Segment(id.Tenant, rq.App)
	if !ok {
		deny("unknown-app", "unknown-app")
		return
	}
	host, ok := resolveTarget(seg, rq.Host, rq.Port)
	if !ok {
		deny("bad-target", "target-not-in-segment")
		return
	}
	rec.Target = net.JoinHostPort(host, itoa(rq.Port))
	pol := e.State.Policy(id.Tenant, policy.Private)
	if pol == nil {
		deny("policy", "no-policy")
		return
	}
	mk := func() policy.Request {
		u, ok := e.State.User(id.Tenant, id.Subject)
		if !ok {
			u = policy.User{Disabled: true}
		}
		return policy.Request{Kind: policy.Private, User: u, App: rq.App, Now: time.Now(),
			Device: policy.Device{ID: id.Device, Revoked: e.Rev.IsRevoked(id.Serial), Posture: ds.get()}}
	}
	d := pol.Evaluate(mk())
	rec.Version, rec.Rule, rec.Reason = pol.Version, d.RuleID, d.Reason
	if d.Action != policy.Allow {
		deny("policy", d.Reason)
		return
	}
	// pick a connector and open, with one retry on another connector
	meta, _ := json.Marshal(openReq{Host: host, Port: rq.Port, App: rq.App})
	tried := map[*connector]bool{}
	var up *mux.Stream
	for i := 0; i < 2 && up == nil; i++ {
		c := e.pick(id.Tenant, seg.Group, tried)
		if c == nil {
			break
		}
		tried[c] = true
		if s, err := c.sess.Open(meta, e.ConnectTimeout); err == nil {
			up = s
		}
	}
	if up == nil {
		deny("unavailable", "no-connector")
		return
	}
	rec.Action = "allow"
	e.logRec(rec)
	st.Accept()
	s := &session{tenant: id.Tenant, device: id.Device, user: id.Subject, a: st, b: up,
		req: mk, pol: func() *policy.Policy { return e.State.Policy(id.Tenant, policy.Private) }}
	e.mu.Lock()
	e.sessions[s] = struct{}{}
	e.mu.Unlock()
	upN, dnN := stitch(st, up)
	e.mu.Lock()
	delete(e.sessions, s)
	e.mu.Unlock()
	rec.Event, rec.BytesUp, rec.BytesDwn = "close", upN, dnN
	e.logRec(rec)
}

func resolveTarget(seg Segment, host string, port int) (string, bool) {
	if host == "" && len(seg.Targets) == 1 {
		host = seg.Targets[0].Host
	}
	for _, t := range seg.Targets {
		if !strings.EqualFold(t.Host, host) {
			continue
		}
		for _, p := range t.Ports {
			if p == port {
				return t.Host, true
			}
		}
	}
	return "", false
}

type halfCloser interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// stitch copies both ways until both directions end. Returns bytes
// client-to-upstream and upstream-to-client.
func stitch(a, b halfCloser) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src halfCloser, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		dst.CloseWrite()
	}
	go cp(b, a, &ab)
	go cp(a, b, &ba)
	wg.Wait()
	a.Close()
	b.Close()
	return
}

// RevokeDevice marks the device's certificate revoked and closes its live
// sessions immediately (DESIGN.md D4.4).
func (e *EN) RevokeDevice(serial, tenant, device string, expires time.Time) {
	e.Rev.Revoke(serial, expires)
	e.closeWhere(func(s *session) bool { return s.tenant == tenant && s.device == device })
}

// DisableUser closes live sessions of a user. The caller must also mark the
// user disabled in State so new sessions are denied.
func (e *EN) DisableUser(tenant, user string) {
	e.closeWhere(func(s *session) bool { return s.tenant == tenant && s.user == user })
}

func (e *EN) closeWhere(f func(*session) bool) {
	e.mu.Lock()
	var kill []*session
	for s := range e.sessions {
		if f(s) {
			kill = append(kill, s)
		}
	}
	e.mu.Unlock()
	for _, s := range kill {
		s.a.Close()
		s.b.Close()
	}
}

func (e *EN) reevalLoop() {
	t := time.NewTicker(e.ReevalEvery)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		e.ReevalNow()
	}
}

// ReevalNow re-evaluates every live session and closes those now denied.
func (e *EN) ReevalNow() int {
	e.mu.Lock()
	all := make([]*session, 0, len(e.sessions))
	for s := range e.sessions {
		all = append(all, s)
	}
	e.mu.Unlock()
	n := 0
	for _, s := range all {
		p := s.pol()
		if p == nil || p.Evaluate(s.req()).Action != policy.Allow {
			s.a.Close()
			s.b.Close()
			n++
		}
	}
	return n
}

func (e *EN) ActiveSessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}

func (e *EN) ConnectorCount(tenant, group string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.connectors[tenant+"/"+group])
}

var ErrNoConn = errors.New("broker: not connected")

func itoa(n int) string { return strconv.Itoa(n) }
