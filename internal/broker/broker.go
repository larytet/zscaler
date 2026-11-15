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
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/devhealth"
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
	Group   string   `json:"group"`           // connector group
	Class   string   `json:"class,omitempty"` // "standard" or "admin", used by the safe-defaults pack
	Targets []Target `json:"targets"`
}

// State is the EN's cached view of tenant configuration.
type State interface {
	Policy(tenant string, k policy.Kind) *policy.Policy
	Segment(tenant, id string) (Segment, bool)
	User(tenant, subject string) (policy.User, bool)
}

// Revoker is an optional State extension: devices revoked by an admin.
type Revoker interface {
	DeviceRevoked(tenant, device string) bool
}

// Failure modes a tenant can choose (NFR-012). What they decide is exactly this: whether NEW sessions and
// requests go on when the node has not heard from the control plane for the staleness window (using the
// last policy it has: "cached"), or are refused ("deny"); and whether they go on when the decision log
// cannot be written ("allow") or are refused ("deny"). Sessions already open are not cut by either.
const (
	FailDeny   = "deny"
	FailCached = "cached"
	FailAllow  = "allow"
)

// FailureModer is an optional State extension: a tenant's failure modes. Without it, both are "deny".
type FailureModer interface {
	FailureMode(tenant string) (onStale, onLogFailure string)
}

// FailureGate decides whether a new session or request may start given the node's health. It returns
// a reason code to refuse with, or "" to go on; and when it goes on although something is wrong, a note
// to record ("state-stale-cached", "log-sink-down-allowed") so the degraded decision is visible.
func FailureGate(st State, tenant string, sinkHealthy func() bool) (refuse, note string) {
	onStale, onLog := FailDeny, FailDeny
	if fm, ok := st.(FailureModer); ok {
		onStale, onLog = fm.FailureMode(tenant)
	}
	if sinkHealthy != nil && !sinkHealthy() {
		if onLog != FailAllow {
			return "log-sink-unavailable", ""
		}
		note = "log-sink-down-allowed"
	}
	if s, ok := st.(Staler); ok && s.Stale() {
		if onStale != FailCached {
			return "state-stale", ""
		}
		if note == "" {
			note = "state-stale-cached"
		} else {
			note += ",state-stale-cached"
		}
	}
	return "", note
}

// Staler is an optional State extension: true when the EN has not heard from
// the control plane recently enough to trust its cache (DESIGN.md D3.6).
type Staler interface {
	Stale() bool
}

// Granter is an optional State extension: just-in-time grants approved by an admin.
type Granter interface {
	Granted(tenant, user, app string, now time.Time) bool
}

// resolve turns a require_approval decision into allow (a grant exists) or deny.
func resolve(st State, tenant, user, app string, d policy.Decision, now time.Time) policy.Decision {
	if d.Action != policy.Approve {
		return d
	}
	if g, ok := st.(Granter); ok && g.Granted(tenant, user, app, now) {
		return policy.Decision{Action: policy.Allow, RuleID: d.RuleID, Reason: "approved"}
	}
	return policy.Decision{Action: policy.Deny, RuleID: d.RuleID, Reason: "approval-required"}
}

// operatorCap enforces AGS-004: an AI agent can reach nothing its operator cannot. It returns a
// denial reason, or "" when the agent may go on. Devices are not compared: only who may reach what.
func operatorCap(st State, pol *policy.Policy, tenant, user, app string, now time.Time) string {
	u, ok := st.User(tenant, user)
	if !ok || u.Operator == "" {
		return ""
	}
	op, ok := st.User(tenant, u.Operator)
	if !ok || op.Disabled {
		return "operator-disabled"
	}
	d := resolve(st, tenant, op.Subject, app, pol.Evaluate(policy.Request{Kind: policy.Private, User: op, App: app, Now: now, AssumeDevice: true}), now)
	if d.Action != policy.Allow {
		return "operator-lacks-access"
	}
	return ""
}

// Revoked reports whether a presented certificate must be refused.
func Revoked(st State, rev *pki.Revocations, id pki.Identity) bool {
	if rev != nil && rev.IsRevoked(id.Serial) {
		return true
	}
	if r, ok := st.(Revoker); ok && id.Role == pki.RoleDevice && r.DeviceRevoked(id.Tenant, id.Device) {
		return true
	}
	return false
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
	// Inspected is set when the web request was decrypted and checked per URL.
	Inspected bool `json:"inspected,omitempty"`
	// Workspace is true when the request came from the workspace browser.
	Workspace bool `json:"workspace,omitempty"`
	// DLP lists the data types found in a blocked or logged request body. Never the data.
	DLP []string `json:"dlp,omitempty"`
	// Ref is the reference a user was shown on a block or warning page, so an administrator who is
	// given it can find the decision (ZIA-014).
	Ref string `json:"ref,omitempty"`
	// FileTypes are the kinds of file a blocked upload or download carried (ZIA-013), never the file.
	FileTypes []string `json:"file_types,omitempty"`
	// Health is set on records of Kind "health": the latest device health numbers.
	Health *devhealth.Snapshot `json:"health,omitempty"`
	// Capture is set on records of Kind "capture": a kept exchange (ZIA-022b). Never persisted to the node's log file.
	Capture *Capture `json:"capture,omitempty"`
	// Src is the address the client connected from, as this node saw it (after any NAT). It is used to
	// evaluate a rule's network condition and is deliberately not written to the log: an address is personal data.
	Src netip.Addr `json:"-"`
	// Inputs to the decision, so that a draft policy can be replayed against history.
	Groups  []string     `json:"groups,omitempty"`
	Posture *PostureSnap `json:"posture,omitempty"`
}

// Capture is a decrypted exchange kept for forensics. Credentials are redacted before it is
// built; bodies are cut at a size cap (Truncated says so) and held as base64.
type Capture struct {
	Rule        string            `json:"rule"`
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Verdict     string            `json:"verdict"` // allow, deny or warn
	Status      int               `json:"status"`  // the status the user received
	ReqHeaders  map[string]string `json:"req_headers,omitempty"`
	ReqBody     string            `json:"req_body,omitempty"` // base64
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	RespBody    string            `json:"resp_body,omitempty"` // base64
	Truncated   bool              `json:"truncated,omitempty"`
}

// Durable reports whether a record may be written to the node's log file. Captures hold
// content and only travel to the control plane, where they expire quickly.
func (r Record) Durable() bool { return r.Kind != "capture" }

// PostureSnap is the posture that was in force for a decision.
type PostureSnap struct {
	OS             string    `json:"os,omitempty"`
	OSVersion      string    `json:"os_version,omitempty"`
	DiskEncrypted  *bool     `json:"disk_encrypted,omitempty"`
	FirewallOn     *bool     `json:"firewall_on,omitempty"`
	ScreenLock     *bool     `json:"screen_lock,omitempty"`
	RemovableMedia *bool     `json:"removable_media,omitempty"`
	ReportedAt     time.Time `json:"reported_at"`
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
	// MaxConnsPerIdentity caps simultaneous connections per certificate identity (default 20).
	MaxConnsPerIdentity int
	// SinkHealthy, when set, is consulted before opening a session: if the decision
	// log cannot be written, new sessions are refused so nothing happens unrecorded.
	SinkHealthy func() bool

	mu         sync.Mutex
	connectors map[string][]*connector // tenant/group
	rr         atomic.Uint64
	sessions   map[*session]struct{}
	live       map[*mux.Session]struct{}
	closed     bool
	perID      map[string]int
}

type connector struct {
	id   string
	sess *mux.Session
}

type session struct {
	app                  string
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
		e.perID = map[string]int{}
	}
	if e.MaxConnsPerIdentity == 0 {
		e.MaxConnsPerIdentity = 20
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
	if err != nil || Revoked(e.State, nil, id) {
		e.Logger.Info("client cert rejected", "err", err)
		raw.Close()
		return
	}
	idKey := id.Tenant + "/" + id.Role + "/" + id.Subject + "/" + id.Device
	e.mu.Lock()
	if e.perID[idKey] >= e.MaxConnsPerIdentity {
		e.mu.Unlock()
		e.Logger.Info("connection limit reached", "identity", idKey)
		raw.Close()
		return
	}
	e.perID[idKey]++
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.perID[idKey]--; e.mu.Unlock() }()
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
	case pki.RoleDevice, pki.RoleWorkspace:
		e.serveDevice(id, certs[0], sess, SourceOf(raw.RemoteAddr()))
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
	e.logRec(Record{Tenant: id.Tenant, Kind: "connector", Event: "connected", App: id.Subject, Device: id.Device, Action: "info"})
	<-sess.Done()
	e.logRec(Record{Tenant: id.Tenant, Kind: "connector", Event: "disconnected", App: id.Subject, Device: id.Device, Action: "info"})
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
	src     netip.Addr // where the device connected from, for network conditions (zero when unknown)
}

func (d *deviceState) get() *policy.Posture {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.posture
}

func (e *EN) serveDevice(id pki.Identity, cert *x509.Certificate, sess *mux.Session, src netip.Addr) {
	ds := &deviceState{src: src}
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
	// record first, acknowledge after: when the agent hears "accepted" the events already exist
	ok, failing := posture.Baseline(r)
	rec := Record{Tenant: id.Tenant, Kind: "posture", User: id.Subject, Device: id.Device, Action: "pass"}
	if !ok {
		rec.Action, rec.Reason = "fail", strings.Join(failing, " and ")
	}
	e.logRec(rec)
	if r.Health != nil {
		e.logRec(Record{Tenant: id.Tenant, Kind: "health", User: id.Subject, Device: id.Device, Action: "info", Health: r.Health})
	}
	st.Accept()
	st.Close()
}

func (e *EN) logRec(r Record) {
	r.TS = time.Now().UTC()
	r.EN = e.Name
	e.Log(r)
}

func (e *EN) open(id pki.Identity, ds *deviceState, st *mux.Stream, rq openReq) {
	rec := Record{Tenant: id.Tenant, Kind: "private", User: id.Subject, Device: id.Device, App: rq.App, Event: "open", Workspace: id.Role == pki.RoleWorkspace}
	deny := func(code, reason string) {
		rec.Action, rec.Reason = "deny", reason
		e.logRec(rec)
		st.Reject(code)
	}
	e.mu.Lock()
	sink := e.SinkHealthy
	e.mu.Unlock()
	refuse, note := FailureGate(e.State, id.Tenant, sink)
	if refuse != "" {
		deny("unavailable", refuse)
		return
	}
	if note != "" { // going on although something is wrong: say so in the log
		nr := rec
		nr.Action, nr.Reason = "info", note
		e.logRec(nr)
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
	if u, ok := e.State.User(id.Tenant, id.Subject); ok {
		rec.Groups = u.Groups
	}
	if p := ds.get(); p != nil {
		rec.Posture = &PostureSnap{OS: p.OS, OSVersion: p.OSVersion, DiskEncrypted: p.DiskEncrypted, FirewallOn: p.FirewallOn, ScreenLock: p.ScreenLock, RemovableMedia: p.RemovableMedia, ReportedAt: p.ReportedAt}
	}
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
		return policy.Request{Kind: policy.Private, User: u, App: rq.App, Now: time.Now(), Workspace: id.Role == pki.RoleWorkspace, SrcIP: ds.src,
			Device: policy.Device{ID: id.Device, Revoked: Revoked(e.State, e.Rev, id), Posture: ds.get()}}
	}
	d := resolve(e.State, id.Tenant, id.Subject, rq.App, pol.Evaluate(mk()), time.Now())
	rec.Version, rec.Rule, rec.Reason = pol.Version, d.RuleID, d.Reason
	if d.Action == policy.Allow {
		if why := operatorCap(e.State, pol, id.Tenant, id.Subject, rq.App, time.Now()); why != "" {
			d = policy.Decision{Action: policy.Deny, RuleID: d.RuleID, Reason: why}
			rec.Reason = why
		}
	}
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
	s := &session{app: rq.App, tenant: id.Tenant, device: id.Device, user: id.Subject, a: st, b: up,
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

// CloseDevice closes live sessions of a device (used when the control plane reports a revocation).
func (e *EN) CloseDevice(tenant, device string) {
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
		if p == nil || resolve(e.State, s.tenant, s.user, s.app, p.Evaluate(s.req()), time.Now()).Action != policy.Allow ||
			operatorCap(e.State, p, s.tenant, s.user, s.app, time.Now()) != "" {
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

// SourceOf turns a connection's remote address into an address a rule can be matched against. IPv6, and
// IPv4 seen through a dual-stack socket (::ffff:a.b.c.d), come out the same way as plain IPv4. An address
// that cannot be read gives the zero Addr, which matches no network condition.
func SourceOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}
