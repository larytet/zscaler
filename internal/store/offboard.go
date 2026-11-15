package store

import (
	"sort"
	"strings"
)

// OffboardReport says what one "person left" action ended.
type OffboardReport struct {
	Subject       string   // the policy subject that was disabled
	Identifiers   []string // everything the person was known by (subject, e-mail, SCIM user name)
	WasDisabled   bool     // the account was already disabled before this call
	Devices       []Device // devices revoked by this call (not those already revoked)
	Grants        int      // access grants ended
	SCIMDeactived bool     // a SCIM user was marked inactive
}

// Offboard ends everything the store holds that gives a person access, in one step under one lock, so
// there is no moment when half of it is done (GAP-REQ-07): the account is disabled, each of their devices
// is revoked (and kept, so its certificate stays dead), their access grants end, and a provisioned user
// is marked inactive. It is safe to call twice: the second call finds nothing left to end.
func (s *Store) Offboard(tenant, subject string) (OffboardReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return OffboardReport{}, err
	}
	u, ok := t.Users[subject]
	if !ok {
		return OffboardReport{}, ErrNotFound
	}
	set := t.expand([]string{subject})
	rep := OffboardReport{Subject: subject, WasDisabled: u.Disabled}
	for k := range set {
		rep.Identifiers = append(rep.Identifiers, k)
	}
	sort.Strings(rep.Identifiers)
	u.Disabled = true
	t.Users[subject] = u
	for id, d := range t.Devices {
		if set[strings.ToLower(d.User)] && !d.Revoked {
			d.Revoked = true
			t.Devices[id] = d
			rep.Devices = append(rep.Devices, d)
		}
	}
	sort.Slice(rep.Devices, func(i, j int) bool { return rep.Devices[i].ID < rep.Devices[j].ID })
	kept := t.Grants[:0]
	for _, g := range t.Grants {
		if set[strings.ToLower(g.User)] {
			rep.Grants++
			continue
		}
		kept = append(kept, g)
	}
	t.Grants = kept
	for id, su := range t.SCIMUsers {
		if (set[strings.ToLower(su.Email)] || set[strings.ToLower(su.UserName)]) && su.Active {
			su.Active = false
			su.Updated = s.Time()
			t.SCIMUsers[id] = su
			rep.SCIMDeactived = true
		}
	}
	return rep, s.save()
}
