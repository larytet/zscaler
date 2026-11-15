// Package en holds the enforcement node's view of control-plane state.
package en

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/signed"
	"github.com/larytet/zscaler/internal/store"
)

// DefaultSyncEvery is the default poll interval. With 5 s the worst case for a
// change to reach a node is about 5 s plus transfer, which does not meet the
// 5 s target of PERF-006, so the default is 2 s.
const DefaultSyncEvery = 2 * time.Second

type tenantView struct {
	segs    map[string]broker.Segment
	users   map[string]policy.User
	pols    map[policy.Kind]*policy.Policy
	revoked map[string]bool
	grants  map[string]time.Time // user|app -> expiry
	inspect bool
	exempt  []string
	ca      *pki.CA
}

type view struct{ tenants map[string]*tenantView }

// SyncState implements broker.State (plus Revoker and Staler) from snapshots.
type SyncState struct {
	cur        atomic.Pointer[view]
	lastOK     atomic.Int64 // unix nanos
	StaleAfter time.Duration
	Now        func() time.Time

	mu       sync.Mutex
	OnChange func(old, new *store.Snapshot)
	prev     *store.Snapshot
}

func NewSyncState() *SyncState {
	s := &SyncState{StaleAfter: 15 * time.Minute}
	s.cur.Store(&view{tenants: map[string]*tenantView{}})
	return s
}

func (s *SyncState) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Apply installs a snapshot. Policies that fail to compile are skipped and
// the previous version of that policy is kept (DESIGN.md D3.6).
func (s *SyncState) Apply(snap *store.Snapshot) []error {
	var errs []error
	old := s.cur.Load()
	nv := &view{tenants: map[string]*tenantView{}}
	for id, t := range snap.Tenants {
		tv := &tenantView{segs: map[string]broker.Segment{}, users: map[string]policy.User{},
			pols: map[policy.Kind]*policy.Policy{}, revoked: map[string]bool{}, grants: map[string]time.Time{}}
		for _, g := range t.Segments {
			tv.segs[g.ID] = g
		}
		for _, u := range t.Users {
			tv.users[u.Subject] = u
		}
		for _, d := range t.RevokedDevices {
			tv.revoked[d] = true
		}
		for _, g := range t.Grants {
			tv.grants[g.User+"|"+g.App] = g.Expires
		}
		if t.Inspect != nil && t.Inspect.Enabled {
			if ca, err := pki.CAFromPEM([]byte(t.Inspect.CACert), []byte(t.Inspect.CAKey), nil); err == nil {
				tv.inspect, tv.exempt, tv.ca = true, t.Inspect.Exempt, ca
			} else {
				errs = append(errs, fmt.Errorf("tenant %s: intercept CA unusable, inspection stays off: %w", id, err))
			}
		}
		for k, p := range t.Policies {
			if ot := old.tenants[id]; ot != nil && ot.pols[k] != nil && p.Version < ot.pols[k].Version {
				errs = append(errs, fmt.Errorf("tenant %s policy %s: refusing rollback from version %d to %d", id, k, ot.pols[k].Version, p.Version))
				tv.pols[k] = ot.pols[k]
				continue
			}
			if err := p.Compile(nil); err != nil {
				errs = append(errs, err)
				if ot := old.tenants[id]; ot != nil && ot.pols[k] != nil {
					tv.pols[k] = ot.pols[k]
				}
				continue
			}
			tv.pols[k] = p
		}
		nv.tenants[id] = tv
	}
	s.cur.Store(nv)
	s.lastOK.Store(s.now().UnixNano())
	s.mu.Lock()
	prev := s.prev
	s.prev = snap
	cb := s.OnChange
	s.mu.Unlock()
	if cb != nil {
		cb(prev, snap)
	}
	return errs
}

func (s *SyncState) Stale() bool {
	last := s.lastOK.Load()
	return last == 0 || s.now().Sub(time.Unix(0, last)) > s.StaleAfter
}

func (s *SyncState) t(tenant string) *tenantView { return s.cur.Load().tenants[tenant] }

func (s *SyncState) Policy(tenant string, k policy.Kind) *policy.Policy {
	if t := s.t(tenant); t != nil {
		return t.pols[k]
	}
	return nil
}

func (s *SyncState) Segment(tenant, id string) (broker.Segment, bool) {
	if t := s.t(tenant); t != nil {
		g, ok := t.segs[id]
		return g, ok
	}
	return broker.Segment{}, false
}

func (s *SyncState) User(tenant, sub string) (policy.User, bool) {
	if t := s.t(tenant); t != nil {
		u, ok := t.users[sub]
		return u, ok
	}
	return policy.User{}, false
}

func (s *SyncState) DeviceRevoked(tenant, device string) bool {
	if t := s.t(tenant); t != nil {
		return t.revoked[device]
	}
	return false
}

// Inspection reports whether a tenant's web traffic is decrypted, which domains are
// exempt, and the CA used to mint certificates.
func (s *SyncState) Inspection(tenant string) (bool, []string, *pki.CA) {
	if t := s.t(tenant); t != nil && t.inspect {
		return true, t.exempt, t.ca
	}
	return false, nil, nil
}

// Granted implements broker.Granter from the signed snapshot.
func (s *SyncState) Granted(tenant, user, app string, now time.Time) bool {
	if t := s.t(tenant); t != nil {
		if exp, ok := t.grants[user+"|"+app]; ok {
			return exp.After(now)
		}
	}
	return false
}

var (
	_ broker.State   = (*SyncState)(nil)
	_ broker.Revoker = (*SyncState)(nil)
	_ broker.Staler  = (*SyncState)(nil)
)

// Diff finds what became disabled or revoked between two snapshots, so the
// EN can close live sessions at once.
func Diff(old, cur *store.Snapshot) (revokedDevices [][2]string, disabledUsers [][2]string) {
	if old == nil {
		old = &store.Snapshot{Tenants: map[string]*store.TenantSnap{}}
	}
	for id, t := range cur.Tenants {
		ot := old.Tenants[id]
		wasRev, wasDis := map[string]bool{}, map[string]bool{}
		if ot != nil {
			for _, d := range ot.RevokedDevices {
				wasRev[d] = true
			}
			for _, u := range ot.Users {
				if u.Disabled {
					wasDis[u.Subject] = true
				}
			}
		}
		for _, d := range t.RevokedDevices {
			if !wasRev[d] {
				revokedDevices = append(revokedDevices, [2]string{id, d})
			}
		}
		for _, u := range t.Users {
			if u.Disabled && !wasDis[u.Subject] {
				disabledUsers = append(disabledUsers, [2]string{id, u.Subject})
			}
		}
	}
	return
}

// Poller fetches snapshots from the control plane.
type Poller struct {
	URL   string // base URL of the enrolment listener
	TLS   *tls.Config
	State *SyncState
	HTTP  *http.Client
	// PolicyPub is the pinned control-plane signing key. A Poller without it
	// refuses to apply any state: unsigned state is never trusted.
	PolicyPub *ecdsa.PublicKey
	MaxAge    time.Duration // how old a signature may be (default 15 minutes)

	lastSeq int64
}

func (p *Poller) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: p.TLS}}
}

func (p *Poller) Once() error {
	resp, err := p.client().Get(p.URL + "/sync/state")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("sync: control plane returned " + resp.Status)
	}
	if p.PolicyPub == nil {
		return errors.New("sync: no pinned policy-signing key; refusing unsigned state")
	}
	var env signed.Envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&env); err != nil {
		return err
	}
	max := p.MaxAge
	if max == 0 {
		max = 15 * time.Minute
	}
	if err := env.Verify(p.PolicyPub, p.lastSeq, time.Now(), max); err != nil {
		return err
	}
	var snap store.Snapshot
	if err := json.Unmarshal(env.Payload, &snap); err != nil {
		return err
	}
	p.lastSeq = env.Seq
	p.State.Apply(&snap)
	return nil
}

// Run polls until stop closes.
func (p *Poller) Run(every time.Duration, stop <-chan struct{}, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := p.Once(); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}
