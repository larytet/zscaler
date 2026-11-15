package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

// SCIM provisioning (INT-002): an identity provider creates users and groups, and the platform uses
// them. A user is matched to a sign-in by e-mail address. When SCIM is on for a tenant, a provisioned
// user's groups are the SCIM groups they are a member of (not the groups in the sign-in token), and a
// user who is inactive in SCIM, or removed, cannot use the platform.

// Limits keep one tenant from filling the store.
const (
	SCIMMaxUsers   = 5000
	SCIMMaxGroups  = 500
	SCIMMaxMembers = 2000
)

var (
	ErrSCIMConflict = errors.New("a resource with that name exists")
	ErrSCIMLimit    = errors.New("too many resources")
)

// SCIMConfig is a tenant's provisioning setting.
type SCIMConfig struct {
	Enabled bool `json:"enabled"`
	// RequireProvisioned refuses anyone the identity provider has not provisioned (people only; AI agents are not people).
	RequireProvisioned bool `json:"require_provisioned"`
	HasToken           bool `json:"has_token"`
}

// SCIMUser is a user as the identity provider describes them.
type SCIMUser struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"external_id,omitempty"`
	UserName    string    `json:"user_name"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Active      bool      `json:"active"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}

// SCIMGroup is a group as the identity provider describes it; DisplayName is the group name policies use.
type SCIMGroup struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"external_id,omitempty"`
	DisplayName string    `json:"display_name"`
	Members     []string  `json:"members,omitempty"` // user ids
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}

func newSCIMID() string {
	b := make([]byte, 16)
	rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func lc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// scimOverlay applies SCIM to a user read from the store.
func (t *Tenant) scimOverlay(u policy.User) policy.User {
	if t.SCIM == nil || !t.SCIM.Enabled || strings.HasPrefix(u.Subject, "agent:") {
		return u
	}
	su, ok := t.scimUserFor(u.Subject, u.Email)
	if !ok {
		if t.SCIM.RequireProvisioned || t.SCIMGone[u.Subject] {
			u.Disabled = true
		}
		return u
	}
	if !su.Active {
		u.Disabled = true
	}
	u.Groups = t.scimGroupsOf(su.ID)
	return u
}

func (t *Tenant) scimUserFor(subject, email string) (SCIMUser, bool) {
	for _, su := range t.SCIMUsers {
		if (email != "" && lc(su.Email) == lc(email)) || (subject != "" && (lc(su.UserName) == lc(subject) || lc(su.Email) == lc(subject))) {
			return su, true
		}
	}
	return SCIMUser{}, false
}

func (t *Tenant) scimGroupsOf(userID string) []string {
	var out []string
	for _, g := range t.SCIMGroups {
		for _, m := range g.Members {
			if m == userID {
				out = append(out, g.DisplayName)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// SCIMBlocks says whether a sign-in must be refused because of provisioning: SCIM is on with
// require-provisioned and the person is not provisioned, or is provisioned as inactive.
func (s *Store) SCIMBlocks(tenant, subject, email string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil || t.SCIM == nil || !t.SCIM.Enabled {
		return false, ""
	}
	su, ok := t.scimUserFor(subject, email)
	switch {
	case ok && !su.Active:
		return true, "this account is deactivated"
	case !ok && t.SCIM.RequireProvisioned:
		return true, "this account has not been provisioned by your identity provider"
	}
	return false, ""
}

// SCIMConfigOf returns the setting and the counts.
func (s *Store) SCIMConfigOf(tenant string) (SCIMConfig, int, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil || t.SCIM == nil {
		return SCIMConfig{}, 0, 0
	}
	return *t.SCIM, len(t.SCIMUsers), len(t.SCIMGroups)
}

// SetSCIM changes the setting. Turning it on makes no token: ask for one with NewSCIMToken.
func (s *Store) SetSCIM(tenant string, enabled, requireProvisioned bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if t.SCIM == nil {
		t.SCIM = &SCIMConfig{}
	}
	t.SCIM.Enabled, t.SCIM.RequireProvisioned = enabled, requireProvisioned
	return s.save()
}

// NewSCIMToken makes the tenant's token (replacing any earlier one) and returns it once.
func (s *Store) NewSCIMToken(tenant string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return "", err
	}
	if s.d.SCIMTokens == nil {
		s.d.SCIMTokens = map[string]string{}
	}
	for h, tn := range s.d.SCIMTokens {
		if tn == tenant {
			delete(s.d.SCIMTokens, h)
		}
	}
	tok := "scim-" + newToken()
	s.d.SCIMTokens[hash(tok)] = tenant
	if t.SCIM == nil {
		t.SCIM = &SCIMConfig{}
	}
	t.SCIM.HasToken = true
	return tok, s.save()
}

// SCIMTenant maps a token to its tenant, only while SCIM is enabled for it.
func (s *Store) SCIMTenant(tok string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tn, ok := s.d.SCIMTokens[hash(tok)]
	if !ok {
		return "", false
	}
	t, err := s.tenant(tn)
	if err != nil || t.SCIM == nil || !t.SCIM.Enabled {
		return "", false
	}
	return tn, true
}

// SCIMUserIn describes a user to create or replace.
type SCIMUserIn struct {
	ExternalID, UserName, Email, DisplayName string
	Active                                   bool
}

func (t *Tenant) dupUser(id, userName, email string) bool {
	for _, su := range t.SCIMUsers {
		if su.ID != id && (lc(su.UserName) == lc(userName) || lc(su.Email) == lc(email)) {
			return true
		}
	}
	return false
}

// SCIMPutUser creates a user (id empty) or replaces one. It returns the user and the policy subjects
// whose access just ended, so the caller can close their sessions.
func (s *Store) SCIMPutUser(tenant, id string, in SCIMUserIn) (SCIMUser, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return SCIMUser{}, nil, err
	}
	if in.UserName == "" || in.Email == "" {
		return SCIMUser{}, nil, errors.New("userName is required")
	}
	if t.dupUser(id, in.UserName, in.Email) {
		return SCIMUser{}, nil, ErrSCIMConflict
	}
	now := time.Now().UTC()
	var su SCIMUser
	if id == "" {
		if len(t.SCIMUsers) >= SCIMMaxUsers {
			return SCIMUser{}, nil, ErrSCIMLimit
		}
		su = SCIMUser{ID: newSCIMID(), Created: now}
	} else {
		var ok bool
		if su, ok = t.SCIMUsers[id]; !ok {
			return SCIMUser{}, nil, ErrNotFound
		}
	}
	was := su.Active
	su.ExternalID, su.UserName, su.Email, su.DisplayName, su.Active, su.Updated = in.ExternalID, in.UserName, lc(in.Email), in.DisplayName, in.Active, now
	if t.SCIMUsers == nil {
		t.SCIMUsers = map[string]SCIMUser{}
	}
	t.SCIMUsers[su.ID] = su
	var ended []string
	if id != "" && was && !su.Active {
		ended = t.subjectsOf(su)
	}
	for _, sub := range t.subjectsOf(su) { // provisioned again: lose the mark a removal left
		delete(t.SCIMGone, sub)
	}
	return su, ended, s.save()
}

// subjectsOf lists the policy users that this SCIM user stands for.
func (t *Tenant) subjectsOf(su SCIMUser) []string {
	var out []string
	for sub, u := range t.Users {
		if lc(u.Email) == lc(su.Email) || lc(sub) == lc(su.UserName) {
			out = append(out, sub)
		}
	}
	sort.Strings(out)
	return out
}

// SCIMDeleteUser removes a user and their group memberships. It returns the policy subjects whose
// access just ended.
func (s *Store) SCIMDeleteUser(tenant, id string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil, err
	}
	su, ok := t.SCIMUsers[id]
	if !ok {
		return nil, ErrNotFound
	}
	delete(t.SCIMUsers, id)
	for gid, g := range t.SCIMGroups {
		var keep []string
		for _, m := range g.Members {
			if m != id {
				keep = append(keep, m)
			}
		}
		g.Members = keep
		t.SCIMGroups[gid] = g
	}
	gone := t.subjectsOf(su)
	if t.SCIMGone == nil {
		t.SCIMGone = map[string]bool{}
	}
	for _, sub := range gone {
		t.SCIMGone[sub] = true // removed in the identity provider: no access until provisioned again
	}
	return gone, s.save()
}

// SCIMUserList returns the tenant's users, ordered by creation then id.
func (s *Store) SCIMUserList(tenant string) []SCIMUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil
	}
	out := make([]SCIMUser, 0, len(t.SCIMUsers))
	for _, u := range t.SCIMUsers {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// SCIMUserGet returns one user and the names of the groups they belong to.
func (s *Store) SCIMUserGet(tenant, id string) (SCIMUser, []SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return SCIMUser{}, nil, false
	}
	su, ok := t.SCIMUsers[id]
	if !ok {
		return SCIMUser{}, nil, false
	}
	var gs []SCIMGroup
	for _, g := range t.SCIMGroups {
		for _, m := range g.Members {
			if m == id {
				gs = append(gs, g)
				break
			}
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].DisplayName < gs[j].DisplayName })
	return su, gs, true
}

// SCIMPutGroup creates a group (id empty) or replaces one. Members are user ids; unknown ids are refused.
func (s *Store) SCIMPutGroup(tenant, id, externalID, displayName string, members []string) (SCIMGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return SCIMGroup{}, err
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 128 || strings.ContainsAny(displayName, "\r\n\x00") {
		return SCIMGroup{}, errors.New("displayName is required, one line, at most 128 characters")
	}
	for _, g := range t.SCIMGroups {
		if g.ID != id && lc(g.DisplayName) == lc(displayName) {
			return SCIMGroup{}, ErrSCIMConflict
		}
	}
	if len(members) > SCIMMaxMembers {
		return SCIMGroup{}, ErrSCIMLimit
	}
	seen := map[string]bool{}
	var clean []string
	for _, m := range members {
		if _, ok := t.SCIMUsers[m]; !ok {
			return SCIMGroup{}, errors.New("member " + m + " is not a provisioned user")
		}
		if !seen[m] {
			seen[m] = true
			clean = append(clean, m)
		}
	}
	now := time.Now().UTC()
	var g SCIMGroup
	if id == "" {
		if len(t.SCIMGroups) >= SCIMMaxGroups {
			return SCIMGroup{}, ErrSCIMLimit
		}
		g = SCIMGroup{ID: newSCIMID(), Created: now}
	} else {
		var ok bool
		if g, ok = t.SCIMGroups[id]; !ok {
			return SCIMGroup{}, ErrNotFound
		}
	}
	g.ExternalID, g.DisplayName, g.Members, g.Updated = externalID, displayName, clean, now
	if t.SCIMGroups == nil {
		t.SCIMGroups = map[string]SCIMGroup{}
	}
	t.SCIMGroups[g.ID] = g
	return g, s.save()
}

// SCIMDeleteGroup removes a group.
func (s *Store) SCIMDeleteGroup(tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return err
	}
	if _, ok := t.SCIMGroups[id]; !ok {
		return ErrNotFound
	}
	delete(t.SCIMGroups, id)
	return s.save()
}

// SCIMGroupList returns the groups ordered by name.
func (s *Store) SCIMGroupList(tenant string) []SCIMGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return nil
	}
	out := make([]SCIMGroup, 0, len(t.SCIMGroups))
	for _, g := range t.SCIMGroups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out
}

// SCIMGroupGet returns one group.
func (s *Store) SCIMGroupGet(tenant, id string) (SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return SCIMGroup{}, false
	}
	g, ok := t.SCIMGroups[id]
	return g, ok
}
