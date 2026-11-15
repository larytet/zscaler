package cp

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/idp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/signed"
	"github.com/larytet/zscaler/internal/store"
)

// Enrol serves the device and connector endpoints. Run it on its own
// listener, separate from the admin API (DESIGN.md D5.1). The listener should
// request, but not require, a client certificate (renew and targets need one).
type Enrol struct {
	API  *API
	CA   *pki.CA
	Rev  *pki.Revocations
	HTTP *http.Client // for IdP calls (tests)
	// MinAgentVersion is announced to agents with every certificate; older agents refuse to start sessions.
	MinAgentVersion string
	// PolicyKey signs every state snapshot served to enforcement nodes.
	PolicyKey *ecdsa.PrivateKey
	seq       atomic.Int64

	mu        sync.Mutex
	verifiers map[string]*idp.Verifier
}

func (e *Enrol) verifier(tenant string) (*idp.Verifier, error) {
	cfg, err := e.API.Store.GetIDP(tenant)
	if err != nil {
		return nil, err
	}
	if cfg.Issuer == "" {
		return nil, fail(409, "idp_not_configured", "the tenant has no identity provider configured")
	}
	key := tenant + "|" + cfg.Issuer + "|" + cfg.ClientID + "|" + cfg.GroupClaim
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.verifiers == nil {
		e.verifiers = map[string]*idp.Verifier{}
	}
	v, ok := e.verifiers[key]
	if !ok {
		v = &idp.Verifier{Issuer: cfg.Issuer, ClientID: cfg.ClientID, GroupClaim: cfg.GroupClaim, HTTP: e.HTTP}
		e.verifiers[key] = v
	}
	return v, nil
}

func (e *Enrol) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /enrol/device", e.device)
	m.HandleFunc("POST /enrol/renew", e.renew)
	m.HandleFunc("POST /enrol/connector", e.connector)
	m.HandleFunc("GET /enrol/targets", e.targets)
	m.HandleFunc("GET /enrol/inspection", e.inspection)
	m.HandleFunc("POST /enrol/en", e.enrolEN)
	m.HandleFunc("POST /enrol/service", e.enrolService)
	m.HandleFunc("GET /sync/state", e.syncState)
	m.HandleFunc("POST /ingest/records", e.ingest)
	return m
}

// WorkspaceTTL is the lifetime of a workspace credential: short, because it runs on devices we do not manage.
const WorkspaceTTL = 4 * time.Hour

// InfraTTL is the lifetime of connector and enforcement-node certificates.
// RB1 has no renewal for them: restart with a fresh token before expiry.
const InfraTTL = 7 * 24 * time.Hour

// EnrolResult is the exported name of the certificate response (used by tests and tools).
type EnrolResult = certOut

type certOut struct {
	DeviceID string    `json:"device_id,omitempty"`
	Cert     string    `json:"cert"` // base64 DER
	CA       string    `json:"ca"`   // PEM
	Expires  time.Time `json:"expires"`
	MinAgent string    `json:"min_agent_version,omitempty"`
	// PolicyPub is the control plane's signing key (PEM), pinned by enforcement nodes at enrolment.
	PolicyPub string `json:"policy_pub,omitempty"`
}

func (e *Enrol) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.CA.Cert.Raw}))
}

func parsePub(b64s string) (any, error) {
	der, err := base64.StdEncoding.DecodeString(b64s)
	if err != nil {
		return nil, fail(400, "invalid", "public_key must be base64 PKIX DER")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fail(400, "invalid", "public_key is not a valid PKIX key")
	}
	return pub, nil
}

func deviceID(pubDER string) string {
	h := sha256.Sum256([]byte(pubDER))
	return "d-" + hex.EncodeToString(h[:6])
}

func (e *Enrol) issue(pub any, id pki.Identity, ttl time.Duration, names ...string) (certOut, *x509.Certificate, error) {
	der, err := e.CA.Sign(pub, id, ttl, names...)
	if err != nil {
		return certOut{}, nil, err
	}
	c, _ := x509.ParseCertificate(der)
	return certOut{Cert: base64.StdEncoding.EncodeToString(der), CA: e.caPEM(), Expires: c.NotAfter, MinAgent: e.MinAgentVersion}, c, nil
}

// device: OIDC login result in, short-lived device certificate out.
func (e *Enrol) device(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var in struct {
		Tenant    string `json:"tenant"`
		IDToken   string `json:"id_token"`
		Nonce     string `json:"nonce"`
		PublicKey string `json:"public_key"`
		Workspace bool   `json:"workspace"` // enrol the workspace browser instead of an agent
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	v, err := e.verifier(in.Tenant)
	if err != nil {
		// do not reveal whether the tenant exists
		writeErr(w, fail(401, "unauthenticated", "enrolment failed"))
		return
	}
	cl, err := v.Verify(in.IDToken, in.Nonce)
	if err != nil {
		e.API.log(ctxInfo{tenant: in.Tenant, actor: "anonymous"}, "enrol.device.failed", "", nil, nil)
		writeErr(w, fail(401, "unauthenticated", "enrolment failed"))
		return
	}
	pub, err := parsePub(in.PublicKey)
	if err != nil {
		writeErr(w, err)
		return
	}
	if u, ok := e.API.Store.User(in.Tenant, cl.Subject); ok && u.Disabled {
		writeErr(w, fail(403, "user_disabled", "this account is disabled"))
		return
	}
	if err := e.API.Store.UpsertUser(in.Tenant, policy.User{Subject: cl.Subject, Email: cl.Email, Groups: cl.Groups}); err != nil {
		writeErr(w, err)
		return
	}
	did := deviceID(in.PublicKey)
	devs, _ := e.API.Store.Devices(in.Tenant)
	for _, d := range devs {
		if d.ID == did && d.Revoked {
			writeErr(w, fail(403, "device_revoked", "this device was revoked"))
			return
		}
	}
	role, ttl := pki.RoleDevice, pki.DeviceTTL
	if in.Workspace {
		role, ttl = pki.RoleWorkspace, WorkspaceTTL
	}
	out, cert, err := e.issue(pub, pki.Identity{Tenant: in.Tenant, Subject: cl.Subject, Device: did, Role: role}, ttl)
	if err != nil {
		writeErr(w, err)
		return
	}
	e.API.Store.PutDevice(in.Tenant, store.Device{ID: did, User: cl.Subject, Serial: cert.SerialNumber.String()})
	e.API.log(ctxInfo{tenant: in.Tenant, actor: cl.Subject}, "enrol.device", did, nil, nil)
	out.DeviceID = did
	writeJSON(w, 200, out)
}

func (e *Enrol) peer(r *http.Request) (pki.Identity, *x509.Certificate, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return pki.Identity{}, nil, false
	}
	c := r.TLS.PeerCertificates[0]
	id, err := e.CA.Verify(c, e.Rev)
	return id, c, err == nil
}

// renew: a valid, unrevoked device certificate gets a fresh one, as long as
// the user is still enabled. (Deviation from DESIGN.md D4.2, which uses an
// IdP refresh token; tracked in STATUS.md.)
func (e *Enrol) renew(w http.ResponseWriter, r *http.Request) {
	id, _, ok := e.peer(r)
	if !ok || (id.Role != pki.RoleDevice && id.Role != pki.RoleWorkspace) {
		writeErr(w, fail(401, "unauthenticated", "a valid device certificate is required"))
		return
	}
	var in struct {
		PublicKey string `json:"public_key"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	if deviceID(in.PublicKey) != id.Device {
		writeErr(w, fail(403, "key_mismatch", "renewal must use the enrolled key"))
		return
	}
	u, ok := e.API.Store.User(id.Tenant, id.Subject)
	if !ok || u.Disabled {
		writeErr(w, fail(403, "user_disabled", "this account is disabled"))
		return
	}
	if devs, _ := e.API.Store.Devices(id.Tenant); true {
		for _, d := range devs {
			if d.ID == id.Device && d.Revoked {
				writeErr(w, fail(403, "device_revoked", "this device was revoked"))
				return
			}
		}
	}
	pub, err := parsePub(in.PublicKey)
	if err != nil {
		writeErr(w, err)
		return
	}
	ttl := pki.DeviceTTL
	if id.Role == pki.RoleWorkspace {
		ttl = WorkspaceTTL // a workspace never gets a longer credential by renewing
	}
	out, cert, err := e.issue(pub, id, ttl)
	if err != nil {
		writeErr(w, err)
		return
	}
	e.API.Store.PutDevice(id.Tenant, store.Device{ID: id.Device, User: id.Subject, Serial: cert.SerialNumber.String()})
	out.DeviceID = id.Device
	writeJSON(w, 200, out)
}

// connector: one-time token in, connector certificate out. The tenant and
// group come from the token, never from the request.
func (e *Enrol) connector(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var in struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	pub, err := parsePub(in.PublicKey)
	if err != nil {
		writeErr(w, err)
		return
	}
	// only a tenant connector token: not an enforcement-node or AI-agent token
	tenant, group, err := e.API.Tokens.RedeemIf(in.Token, func(t, g string) bool {
		return t != "" && !strings.HasPrefix(g, ENTokenPrefix) && !strings.HasPrefix(g, ServiceTokenPrefix)
	})
	if err != nil {
		writeErr(w, fail(401, "unauthenticated", "invalid, used or expired token"))
		return
	}
	if in.Name == "" {
		in.Name = deviceID(in.PublicKey)
	}
	out, _, err := e.issue(pub, pki.Identity{Tenant: tenant, Subject: group, Device: in.Name, Role: pki.RoleConnector}, InfraTTL)
	if err != nil {
		writeErr(w, err)
		return
	}
	e.API.log(ctxInfo{tenant: tenant, actor: "connector:" + in.Name}, "enrol.connector", group, nil, nil)
	writeJSON(w, 200, out)
}

// targets returns the allow-list for the calling connector's group only.
func (e *Enrol) targets(w http.ResponseWriter, r *http.Request) {
	id, _, ok := e.peer(r)
	if !ok || id.Role != pki.RoleConnector {
		writeErr(w, fail(401, "unauthenticated", "a valid connector certificate is required"))
		return
	}
	segs, err := e.API.Store.Segments(id.Tenant)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := []broker.Target{}
	for _, s := range segs {
		if s.Group == id.Subject {
			out = append(out, s.Targets...)
		}
	}
	writeJSON(w, 200, out)
}

// ENTokenPrefix marks a token as an enforcement-node enrolment token. The
// "group" field carries the comma-separated DNS names or IPs for its certificate.
const ENTokenPrefix = "en:"

func (e *Enrol) enrolEN(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var in struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	pub, err := parsePub(in.PublicKey)
	if err != nil {
		writeErr(w, err)
		return
	}
	_, group, err := e.API.Tokens.RedeemIf(in.Token, func(t, g string) bool { return t == "" && strings.HasPrefix(g, ENTokenPrefix) })
	if err != nil {
		writeErr(w, fail(401, "unauthenticated", "invalid, used or expired token"))
		return
	}
	names := strings.Split(strings.TrimPrefix(group, ENTokenPrefix), ",")
	var pubPEM string
	if e.PolicyKey != nil {
		pubPEM = string(pki.PublicPEM(&e.PolicyKey.PublicKey))
	}
	if in.Name == "" {
		in.Name = names[0]
	}
	out, _, err := e.issue(pub, pki.Identity{Tenant: "platform", Subject: "en", Device: in.Name, Role: pki.RoleEN}, InfraTTL, names...)
	if err != nil {
		writeErr(w, err)
		return
	}
	out.PolicyPub = pubPEM
	writeJSON(w, 200, out)
}

// syncState gives an enforcement node the full cached state (DESIGN.md D2.6;
// RB1 polls this instead of holding a push stream).
func (e *Enrol) syncState(w http.ResponseWriter, r *http.Request) {
	id, _, ok := e.peer(r)
	if !ok || id.Role != pki.RoleEN {
		writeErr(w, fail(401, "unauthenticated", "an enforcement-node certificate is required"))
		return
	}
	if e.PolicyKey == nil {
		writeErr(w, fail(500, "no_signing_key", "the control plane has no policy-signing key"))
		return
	}
	payload, err := json.Marshal(e.API.Store.Snapshot())
	if err != nil {
		writeErr(w, err)
		return
	}
	// strictly increasing even across restarts: time-based, bumped past the previous value
	now := time.Now()
	seq := now.UnixNano()
	for {
		old := e.seq.Load()
		if seq <= old {
			seq = old + 1
		}
		if e.seq.CompareAndSwap(old, seq) {
			break
		}
	}
	env, err := signed.Sign(e.PolicyKey, seq, now, payload)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, env)
}

// ingest receives batches of decision and event records from an enforcement node.
func (e *Enrol) ingest(w http.ResponseWriter, r *http.Request) {
	id, _, ok := e.peer(r)
	if !ok || id.Role != pki.RoleEN {
		writeErr(w, fail(401, "unauthenticated", "an enforcement-node certificate is required"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var recs []broker.Record
	if err := json.NewDecoder(r.Body).Decode(&recs); err != nil || len(recs) > 5000 {
		writeErr(w, fail(400, "invalid", "expected a JSON array of at most 5000 records"))
		return
	}
	for _, rec := range recs {
		if e.API.Alerts != nil {
			e.API.Alerts.Ingest(rec)
		}
		if e.API.Decisions != nil {
			e.API.Decisions.Add(rec)
		}
		if e.API.Health != nil && rec.Kind == "health" && rec.Health != nil {
			e.API.Health.Put(devhealth.Entry{Tenant: rec.Tenant, User: rec.User, Device: rec.Device, At: time.Now(), Snapshot: *rec.Health})
		}
		if e.API.Approvals != nil && rec.Kind == "private" && rec.Action == "deny" && rec.Reason == "approval-required" && rec.Event == "open" {
			if req, created := e.API.Approvals.Add(rec.Tenant, rec.User, rec.App, rec.Rule, time.Now()); created && e.API.OnApprovalRequest != nil {
				go e.API.OnApprovalRequest(req)
			}
		}
	}
	writeJSON(w, 200, map[string]int{"accepted": len(recs)})
}

// ServiceTokenPrefix marks a token for an AI agent or other non-interactive identity.
const ServiceTokenPrefix = "svc:"

// enrolService redeems a one-time service token for a device certificate whose subject is
// the agent identity ("agent:<name>"). The identity, its operator and its app grants were
// set up by an admin (see POST /v1/ai-agents); nothing here widens them.
func (e *Enrol) enrolService(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var in struct {
		Token     string `json:"token"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	pub, err := parsePub(in.PublicKey)
	if err != nil {
		writeErr(w, err)
		return
	}
	tenant, group, err := e.API.Tokens.RedeemIf(in.Token, func(t, g string) bool { return t != "" && strings.HasPrefix(g, ServiceTokenPrefix) })
	if err != nil {
		writeErr(w, fail(401, "unauthenticated", "invalid, used or expired token"))
		return
	}
	subject := strings.TrimPrefix(group, ServiceTokenPrefix)
	u, ok := e.API.Store.User(tenant, subject)
	if !ok || u.Disabled {
		writeErr(w, fail(403, "agent_disabled", "this agent identity is disabled or was removed"))
		return
	}
	did := deviceID(in.PublicKey)
	out, cert, err := e.issue(pub, pki.Identity{Tenant: tenant, Subject: subject, Device: did, Role: pki.RoleDevice}, pki.DeviceTTL)
	if err != nil {
		writeErr(w, err)
		return
	}
	e.API.Store.PutDevice(tenant, store.Device{ID: did, User: subject, Serial: cert.SerialNumber.String()})
	e.API.log(ctxInfo{tenant: tenant, actor: subject}, "enrol.service", did, nil, nil)
	out.DeviceID = did
	writeJSON(w, 200, out)
}

// inspection tells a device or workspace whether its tenant's web traffic is decrypted and,
// if so, the hash of the key that signs the certificates, which the workspace browser pins
// (and which no other browser trusts).
func (e *Enrol) inspection(w http.ResponseWriter, r *http.Request) {
	id, _, ok := e.peer(r)
	if !ok || (id.Role != pki.RoleDevice && id.Role != pki.RoleWorkspace) {
		writeErr(w, fail(401, "unauthenticated", "a valid device certificate is required"))
		return
	}
	spki, on := e.API.Store.InterceptSPKI(id.Tenant)
	writeJSON(w, 200, map[string]any{"enabled": on, "spki_sha256": spki})
}
