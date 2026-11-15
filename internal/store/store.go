// Package store holds control-plane state, scoped by tenant on every call
// (DESIGN.md D2.1, ARCH-020). RB1 persists to one JSON file.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/larytet/zscaler/internal/broker"
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

type Tenant struct {
	ID       string                     `json:"id"`
	Name     string                     `json:"name"`
	IDP      IDP                        `json:"idp"`
	Segments map[string]broker.Segment  `json:"segments"`
	Policies map[policy.Kind]*PolicyDoc `json:"policies"`
	Users    map[string]policy.User     `json:"users"`
	Devices  map[string]Device          `json:"devices"`
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

func (s *Store) Users(tenant string) ([]policy.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]policy.User, 0, len(t.Users))
	for _, u := range t.Users {
		out = append(out, u)
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
	return u, ok
}

var _ broker.State = (*Store)(nil)
