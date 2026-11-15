// Package store holds control-plane state, scoped by tenant on every call
// (DESIGN.md D2.1, ARCH-020). RB1 persists to one JSON file.
package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/dlp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("version conflict")
	ErrExists   = errors.New("already exists")
)

type Role string

const (
	Admin  Role = "admin"
	Viewer Role = "viewer"
)

type IDP struct {
	Issuer     string `json:"issuer"`
	ClientID   string `json:"client_id"`
	GroupClaim string `json:"group_claim"`
}

type Device struct {
	ID      string `json:"id"`
	User    string `json:"user"`
	Serial  string `json:"serial,omitempty"`
	Revoked bool   `json:"revoked"`
}

type PolicyDoc struct {
	Version int            `json:"version"`
	Policy  *policy.Policy `json:"policy"`
}

// AgentTimes are the registry facts for one AI agent identity (AGS-005).
type AgentTimes struct {
	Created time.Time `json:"created"`
	LastUse time.Time `json:"last_use,omitempty"`
}

// NoteAgentCreated records when an agent identity was made (or re-made).
func (s *Store) NoteAgentCreated(tenant, subject string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if t.AgentTimes == nil {
		t.AgentTimes = map[string]AgentTimes{}
	}
	t.AgentTimes[subject] = AgentTimes{Created: at}
	return s.save()
}

// NoteAgentUse records that an agent was allowed through. It is called for every allowed decision,
// so it writes the store at most once every five minutes per agent.
func (s *Store) NoteAgentUse(tenant, subject string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return
	}
	cur, ok := t.AgentTimes[subject]
	if !ok || at.Sub(cur.LastUse) < 5*time.Minute && !cur.LastUse.IsZero() {
		return // unknown identity (not an agent of ours) or recorded recently
	}
	cur.LastUse = at
	t.AgentTimes[subject] = cur
	s.save()
}

// AgentTimes returns the registry facts for a tenant's agents.
func (s *Store) AgentTimes(tenant string) map[string]AgentTimes {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil
	}
	out := make(map[string]AgentTimes, len(t.AgentTimes))
	for k, v := range t.AgentTimes {
		out[k] = v
	}
	return out
}

type Tenant struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	IDP         IDP                        `json:"idp"`
	AlertEmails []string                   `json:"alert_emails,omitempty"`
	Segments    map[string]broker.Segment  `json:"segments"`
	Policies    map[policy.Kind]*PolicyDoc `json:"policies"`
	Users       map[string]policy.User     `json:"users"`
	Restricted  map[string]string          `json:"restricted,omitempty"` // subject -> reason
	risk        map[string]int             `json:"-"`                    // computed, in memory only
	Grants      []Grant                    `json:"grants,omitempty"`
	AgentTimes  map[string]AgentTimes      `json:"agent_times,omitempty"` // AI agent registry: created and last used
	Inspect     InspectCfg                 `json:"inspect,omitempty"`
	Secrets     map[string]Secret          `json:"secrets,omitempty"`
	EDM         map[string]EDMSet          `json:"edm,omitempty"`
	Devices     map[string]Device          `json:"devices"`
}

type adminRec struct {
	Tenant string `json:"tenant"`
	Role   Role   `json:"role"`
	Name   string `json:"name"`
}

type file struct {
	Tenants map[string]*Tenant  `json:"tenants"`
	Admins  map[string]adminRec `json:"admins"` // sha256(token) -> record
}

type Store struct {
	mu   sync.RWMutex
	path string
	d    file
}

// Open loads path if it exists. An empty path keeps the store in memory.
func Open(path string) (*Store, error) {
	s := &Store{path: path, d: file{Tenants: map[string]*Tenant{}, Admins: map[string]adminRec{}}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, fmt.Errorf("store %s: %w", path, err)
	}
	for _, t := range s.d.Tenants {
		for k, pd := range t.Policies {
			if err := pd.Policy.Compile(nil); err != nil {
				return nil, fmt.Errorf("tenant %s policy %s: %w", t.ID, k, err)
			}
		}
	}
	return s, nil
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(&s.d, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hash(tok string) string { h := sha256.Sum256([]byte(tok)); return hex.EncodeToString(h[:]) }

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) tenant(id string) (*Tenant, error) {
	t, ok := s.d.Tenants[id]
	if !ok {
		return nil, ErrNotFound
	}
	return t, nil
}

// CreateTenant also creates the first admin and returns its token (shown once).
func (s *Store) CreateTenant(id, name string) (adminToken string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.Tenants[id]; ok {
		return "", ErrExists
	}
	s.d.Tenants[id] = &Tenant{ID: id, Name: name, Segments: map[string]broker.Segment{},
		Policies: map[policy.Kind]*PolicyDoc{}, Users: map[string]policy.User{}, Devices: map[string]Device{}}
	tok := newToken()
	s.d.Admins[hash(tok)] = adminRec{Tenant: id, Role: Admin, Name: "owner"}
	return tok, s.save()
}

func (s *Store) AddAdmin(tenant, name string, role Role) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.tenant(tenant); err != nil {
		return "", err
	}
	tok := newToken()
	s.d.Admins[hash(tok)] = adminRec{Tenant: tenant, Role: role, Name: name}
	return tok, s.save()
}

// Auth maps a bearer token to its tenant and role. The tenant always comes
// from here, never from the request.
func (s *Store) Auth(tok string) (tenant string, role Role, name string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.d.Admins[hash(tok)]
	return a.Tenant, a.Role, a.Name, ok
}

// AdminHashes is for tests that check tokens are not stored in clear.
func (s *Store) AdminHashes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for h := range s.d.Admins {
		out = append(out, h)
	}
	return out
}

func (s *Store) SetIDP(tenant string, i IDP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	t.IDP = i
	return s.save()
}

func (s *Store) GetIDP(tenant string) (IDP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return IDP{}, err
	}
	return t.IDP, nil
}

func (s *Store) Segments(tenant string) ([]broker.Segment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]broker.Segment, 0, len(t.Segments))
	for _, g := range t.Segments {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) PutSegment(tenant string, g broker.Segment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	t.Segments[g.ID] = g
	return s.save()
}

func (s *Store) DeleteSegment(tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if _, ok := t.Segments[id]; !ok {
		return ErrNotFound
	}
	delete(t.Segments, id)
	return s.save()
}

func (s *Store) SegmentIDs(tenant string) map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := map[string]bool{}
	if t, err := s.tenant(tenant); err == nil {
		for id := range t.Segments {
			m[id] = true
		}
	}
	return m
}

// GetPolicy returns the stored document, or ErrNotFound if none was saved.
func (s *Store) GetPolicy(tenant string, k policy.Kind) (*PolicyDoc, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	d, ok := t.Policies[k]
	if !ok {
		return nil, ErrNotFound
	}
	return d, nil
}

// PutPolicy compiles and stores p. ifMatch is the version the caller read
// (0 when none exists). Returns the new version.
func (s *Store) PutPolicy(tenant string, k policy.Kind, p *policy.Policy, ifMatch int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return 0, err
	}
	cur := 0
	if d, ok := t.Policies[k]; ok {
		cur = d.Version
	}
	if ifMatch != cur {
		return cur, ErrConflict
	}
	p.Kind = k
	p.Version = cur + 1
	known := map[string]bool{}
	for id := range t.Segments {
		known[id] = true
	}
	if err := p.Compile(known); err != nil {
		return cur, err
	}
	if err := t.checkEDM(p); err != nil {
		return cur, err
	}
	if err := t.checkInjects(p); err != nil {
		return cur, err
	}
	t.Policies[k] = &PolicyDoc{Version: p.Version, Policy: p}
	return p.Version, s.save()
}

func (s *Store) UpsertUser(tenant string, u policy.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if old, ok := t.Users[u.Subject]; ok {
		u.Disabled = old.Disabled // a login never re-enables a disabled user
	}
	t.Users[u.Subject] = u
	return s.save()
}

func (s *Store) SetUserDisabled(tenant, subject string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	u, ok := t.Users[subject]
	if !ok {
		return ErrNotFound
	}
	u.Disabled = disabled
	t.Users[subject] = u
	return s.save()
}

// effective adds product-side groups to what the identity provider said.
func (t *Tenant) effective(u policy.User) policy.User {
	u.Risk = t.risk[u.Subject]
	if _, ok := t.Restricted[u.Subject]; ok {
		g := make([]string, 0, len(u.Groups)+1)
		for _, x := range u.Groups {
			if x != policy.RestrictedGroup {
				g = append(g, x)
			}
		}
		u.Groups = append(g, policy.RestrictedGroup)
	}
	return u
}

// SetRestricted puts a user in, or takes them out of, the product-side
// restricted group. It survives IdP group refreshes at login.
func (s *Store) SetRestricted(tenant, subject string, restricted bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if _, ok := t.Users[subject]; !ok {
		return ErrNotFound
	}
	if restricted {
		if t.Restricted == nil {
			t.Restricted = map[string]string{}
		}
		t.Restricted[subject] = reason
	} else {
		delete(t.Restricted, subject)
	}
	return s.save()
}

func (s *Store) Users(tenant string) ([]policy.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]policy.User, 0, len(t.Users))
	for _, u := range t.Users {
		out = append(out, t.effective(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

func (s *Store) PutDevice(tenant string, d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	t.Devices[d.ID] = d
	return s.save()
}

func (s *Store) Devices(tenant string) ([]Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(t.Devices))
	for _, d := range t.Devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// RevokeDevice marks the device revoked and returns it (for the serial).
func (s *Store) RevokeDevice(tenant, id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return Device{}, err
	}
	d, ok := t.Devices[id]
	if !ok {
		return Device{}, ErrNotFound
	}
	d.Revoked = true
	t.Devices[id] = d
	return d, s.save()
}

// --- broker.State implementation (read-only view used by enforcement nodes) ---

func (s *Store) Policy(tenant string, k policy.Kind) *policy.Policy {
	if d, err := s.GetPolicy(tenant, k); err == nil {
		return d.Policy
	}
	return nil
}

func (s *Store) Segment(tenant, id string) (broker.Segment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return broker.Segment{}, false
	}
	g, ok := t.Segments[id]
	return g, ok
}

func (s *Store) User(tenant, subject string) (policy.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return policy.User{}, false
	}
	u, ok := t.Users[subject]
	return t.effective(u), ok
}

var _ broker.State = (*Store)(nil)

// Snapshot is the full state an enforcement node needs, per tenant.
type TenantSnap struct {
	Segments       []broker.Segment
	Users          []policy.User
	Policies       map[policy.Kind]*policy.Policy
	RevokedDevices []string
	Grants         []Grant // only unexpired ones
	Inspect        *InspectSnap
	Secrets        []Secret
	EDM            []EDMSet // exact-data-match sets: salted hashes only
}

// Grant is an admin-approved, time-limited access (just-in-time).
type Grant struct {
	User    string    `json:"user"`
	App     string    `json:"app"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by"`
}

// Secret is a credential the platform holds so that an AI agent does not have to (AGS-001).
// The value is returned by no API. It is stored in clear in the store file and sent to
// enforcement nodes in the signed snapshot, like the inspection CA key.
type Secret struct {
	Name   string `json:"name"`
	Host   string `json:"host"`   // the only host it may be sent to (a domain also covers its subdomains)
	Header string `json:"header"` // the request header it is placed in
	Value  string `json:"value"`
}

// InspectCfg is a tenant's TLS inspection setting. The intercept CA is per tenant
// (ARCH-021): it is created when inspection is first enabled and never shared.
type InspectCfg struct {
	Enabled bool     `json:"enabled"`
	Exempt  []string `json:"exempt,omitempty"` // domains (and their subdomains) that are never decrypted
	CACert  string   `json:"ca_cert,omitempty"`
	CAKey   string   `json:"ca_key,omitempty"`
	// LeafKey is the one key every inspection certificate of this tenant is minted with, so its
	// public-key hash is stable and the workspace browser can trust it (and only it).
	LeafKey string `json:"leaf_key,omitempty"`
}

type InspectSnap struct {
	Enabled bool
	Exempt  []string
	CACert  string
	CAKey   string
	LeafKey string
}

type Snapshot struct {
	Tenants map[string]*TenantSnap
}

func (s *Store) Snapshot() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := &Snapshot{Tenants: map[string]*TenantSnap{}}
	for id, t := range s.d.Tenants {
		ts := &TenantSnap{Policies: map[policy.Kind]*policy.Policy{}}
		for _, g := range t.Segments {
			ts.Segments = append(ts.Segments, g)
		}
		for _, u := range t.Users {
			ts.Users = append(ts.Users, t.effective(u))
		}
		for k, d := range t.Policies {
			ts.Policies[k] = d.Policy
		}
		for _, d := range t.Devices {
			if d.Revoked {
				ts.RevokedDevices = append(ts.RevokedDevices, d.ID)
			}
		}
		if t.Inspect.Enabled && t.Inspect.CAKey != "" {
			ts.Inspect = &InspectSnap{Enabled: true, Exempt: append([]string(nil), t.Inspect.Exempt...), CACert: t.Inspect.CACert, CAKey: t.Inspect.CAKey, LeafKey: t.Inspect.LeafKey}
		}
		for _, e := range t.EDM {
			ts.EDM = append(ts.EDM, e)
		}
		for _, sc := range t.Secrets {
			ts.Secrets = append(ts.Secrets, sc)
		}
		now := time.Now()
		for _, g := range t.Grants {
			if g.Expires.After(now) {
				ts.Grants = append(ts.Grants, g)
			}
		}
		out.Tenants[id] = ts
	}
	return out
}

func (s *Store) SetAlertEmails(tenant string, emails []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	t.AlertEmails = emails
	return s.save()
}

func (s *Store) AlertEmails(tenant string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, err := s.tenant(tenant); err == nil {
		return append([]string(nil), t.AlertEmails...)
	}
	return nil
}

// Tenants lists tenant IDs.
func (s *Store) Tenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.d.Tenants))
	for id := range s.d.Tenants {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// AdminCounts returns how many admin and read-only tokens a tenant has.
func (s *Store) AdminCounts(tenant string) (admins, viewers int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.d.Admins {
		if a.Tenant == tenant {
			if a.Role == Admin {
				admins++
			} else {
				viewers++
			}
		}
	}
	return
}

// SetRisk replaces a tenant's computed risk scores (not persisted).
func (s *Store) SetRisk(tenant string, scores map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, err := s.tenant(tenant); err == nil {
		t.risk = scores
	}
}

// PutGrant records a just-in-time grant, replacing an earlier one for the same user and app.
// Expired grants are dropped as a side effect.
func (s *Store) PutGrant(tenant string, g Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	now := time.Now()
	kept := t.Grants[:0]
	for _, x := range t.Grants {
		if x.Expires.After(now) && !(x.User == g.User && x.App == g.App) {
			kept = append(kept, x)
		}
	}
	t.Grants = append(kept, g)
	return s.save()
}

// RevokeGrant ends a grant early.
func (s *Store) RevokeGrant(tenant, user, app string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	kept := t.Grants[:0]
	for _, x := range t.Grants {
		if !(x.User == user && x.App == app) {
			kept = append(kept, x)
		}
	}
	t.Grants = kept
	return s.save()
}

// Granted reports whether an unexpired grant exists (also makes Store a broker.Granter).
func (s *Store) Granted(tenant, user, app string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return false
	}
	for _, g := range t.Grants {
		if g.User == user && g.App == app && g.Expires.After(now) {
			return true
		}
	}
	return false
}

// SetInspection turns TLS inspection on or off and sets the exemption list. The
// tenant's intercept CA is created the first time it is enabled.
func (s *Store) SetInspection(tenant string, enabled bool, exempt []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if enabled && t.Inspect.CAKey == "" {
		ca, err := pki.NewCA(tenant+" TLS inspection CA", nil)
		if err != nil {
			return err
		}
		t.Inspect.CACert, t.Inspect.CAKey = string(ca.PEM()), string(ca.KeyPEM())
	}
	if enabled && t.Inspect.LeafKey == "" {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, _ := x509.MarshalECPrivateKey(k)
		t.Inspect.LeafKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	t.Inspect.Enabled = enabled
	t.Inspect.Exempt = exempt
	return s.save()
}

// Inspection returns the setting without the private key.
func (s *Store) Inspection(tenant string) (InspectCfg, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return InspectCfg{}, err
	}
	c := t.Inspect
	c.CAKey, c.LeafKey = "", "" // private keys never leave the store through this call
	return c, nil
}

// InterceptSPKI returns the base64 SHA-256 of the public key that signs every inspection
// certificate of the tenant (the form browsers use for SPKI pins), if inspection is on.
func (s *Store) InterceptSPKI(tenant string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil || !t.Inspect.Enabled || t.Inspect.LeafKey == "" {
		return "", false
	}
	blk, _ := pem.Decode([]byte(t.Inspect.LeafKey))
	if blk == nil {
		return "", false
	}
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return "", false
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	h := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(h[:]), true
}

// PutSecret stores or replaces a secret. Callers validate the fields.
func (s *Store) PutSecret(tenant string, sc Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if t.Secrets == nil {
		t.Secrets = map[string]Secret{}
	}
	t.Secrets[sc.Name] = sc
	return s.save()
}

// Secrets lists names, hosts and headers. The values are never returned.
func (s *Store) Secrets(tenant string) ([]Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(t.Secrets))
	for _, sc := range t.Secrets {
		sc.Value = ""
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteSecret(tenant, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if _, ok := t.Secrets[name]; !ok {
		return ErrNotFound
	}
	// a policy that still injects this secret would silently stop working: refuse
	for k, d := range t.Policies {
		for _, r := range d.Policy.Rules {
			if r.Inject == name {
				return fmt.Errorf("secret %q is still used by rule %q of the %s policy", name, r.ID, k)
			}
		}
	}
	delete(t.Secrets, name)
	return s.save()
}

// secretsCover checks that every inject rule names an existing secret and covers its host.
// checkEDM refuses a policy that names a data set that does not exist.
func (t *Tenant) checkEDM(p *policy.Policy) error {
	for _, r := range p.Rules {
		for _, list := range [][]string{r.Match.DLP, r.Match.DLPResponse} {
			for _, d := range list {
				if strings.HasPrefix(d, dlp.EDMPrefix) {
					if _, ok := t.EDM[strings.TrimPrefix(d, dlp.EDMPrefix)]; !ok {
						return fmt.Errorf("rule %q uses the unknown data set %q", r.ID, d)
					}
				}
			}
		}
	}
	return nil
}

func (t *Tenant) checkInjects(p *policy.Policy) error {
	for _, r := range p.Rules {
		if r.Inject == "" {
			continue
		}
		sc, ok := t.Secrets[r.Inject]
		if !ok {
			return fmt.Errorf("rule %q injects the unknown secret %q", r.ID, r.Inject)
		}
		covered := false
		for _, d := range r.Match.Domains {
			d = strings.ToLower(d)
			if sc.Host == d || strings.HasSuffix(sc.Host, "."+d) {
				covered = true
			}
		}
		if !covered {
			return fmt.Errorf("rule %q injects secret %q, which is bound to %s, but the rule does not name that host or a parent domain", r.ID, r.Inject, sc.Host)
		}
	}
	return nil
}

// Secret implements the proxy's lookup for the in-process store (tests); nodes use the snapshot.
func (s *Store) Secret(tenant, name string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return Secret{}, false
	}
	sc, ok := t.Secrets[name]
	return sc, ok
}

// EDMSet is one exact-data-match list. Only salted hashes are kept; the values are not.
type EDMSet struct {
	Name    string    `json:"name"`
	Salt    string    `json:"salt,omitempty"`   // hex; never shown by the API
	Hashes  []string  `json:"hashes,omitempty"` // never shown by the API
	Count   int       `json:"count"`
	Skipped int       `json:"skipped,omitempty"` // values that could not be matched (too short, too long, spaces)
	Updated time.Time `json:"updated"`
}

// PutEDM replaces a data set with the given values. It returns how many were kept and how many
// were skipped as unmatchable. The values are hashed here and then forgotten.
func (s *Store) PutEDM(tenant, name string, values []string) (kept, skipped int, err error) {
	if !dlp.ValidEDMName(name) {
		return 0, 0, fmt.Errorf("invalid data set name")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return 0, 0, err
	}
	seen := map[string]bool{}
	var hashes []string
	for _, v := range values {
		h, ok := dlp.Hash(salt, v)
		if !ok {
			skipped++
			continue
		}
		if !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	if len(hashes) == 0 {
		return 0, skipped, fmt.Errorf("no usable values: each must be one token of 4 to 64 letters, digits or . _ @ + -")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return 0, 0, err
	}
	if _, exists := t.EDM[name]; !exists && len(t.EDM) >= 5 {
		return 0, 0, fmt.Errorf("at most 5 data sets")
	}
	if t.EDM == nil {
		t.EDM = map[string]EDMSet{}
	}
	t.EDM[name] = EDMSet{Name: name, Salt: hex.EncodeToString(salt), Hashes: hashes, Count: len(hashes), Skipped: skipped, Updated: time.Now().UTC()}
	return len(hashes), skipped, s.save()
}

// EDMSets lists a tenant's data sets without the salt or hashes.
func (s *Store) EDMSets(tenant string) ([]EDMSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]EDMSet, 0, len(t.EDM))
	for _, e := range t.EDM {
		e.Salt, e.Hashes = "", nil
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteEDM removes a data set unless a policy still uses it.
func (s *Store) DeleteEDM(tenant, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if _, ok := t.EDM[name]; !ok {
		return ErrNotFound
	}
	for k, d := range t.Policies {
		for _, r := range d.Policy.Rules {
			for _, list := range [][]string{r.Match.DLP, r.Match.DLPResponse} {
				for _, x := range list {
					if x == dlp.EDMPrefix+name {
						return fmt.Errorf("data set %q is still used by rule %q of the %s policy", name, r.ID, k)
					}
				}
			}
		}
	}
	delete(t.EDM, name)
	return s.save()
}
