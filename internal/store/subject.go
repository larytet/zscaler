package store

import (
	"sort"
	"strings"

	"github.com/larytet/zscaler/internal/policy"
)

// Data about one person (NFR-030): what the store holds, and removing it.

func idSet(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			m[id] = true
		}
	}
	return m
}

// subjectsOf expands names into every identifier of the people they match: a person is known by their
// subject, their e-mail address and their SCIM user name.
func (t *Tenant) expand(ids []string) map[string]bool {
	set := idSet(ids)
	out := map[string]bool{}
	for k := range set {
		out[k] = true
	}
	for sub, u := range t.Users {
		if set[strings.ToLower(sub)] || (u.Email != "" && set[strings.ToLower(u.Email)]) {
			out[strings.ToLower(sub)] = true
			if u.Email != "" {
				out[strings.ToLower(u.Email)] = true
			}
		}
	}
	for _, su := range t.SCIMUsers {
		if set[strings.ToLower(su.Email)] || set[strings.ToLower(su.UserName)] {
			out[strings.ToLower(su.Email)] = true
			out[strings.ToLower(su.UserName)] = true
		}
	}
	return out
}

// SubjectData is what the store holds about a person.
type SubjectData struct {
	Identifiers []string          `json:"identifiers"`
	Users       []policy.User     `json:"users"`
	SCIMUsers   []SCIMUser        `json:"scim_users"`
	Devices     []Device          `json:"devices"`
	Grants      []Grant           `json:"access_grants"`
	Restricted  map[string]string `json:"restricted,omitempty"`
}

// Subject returns what the store holds about the person the names match.
func (s *Store) Subject(tenant string, ids []string) (SubjectData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return SubjectData{}, err
	}
	set := t.expand(ids)
	d := SubjectData{Users: []policy.User{}, SCIMUsers: []SCIMUser{}, Devices: []Device{}, Grants: []Grant{}}
	for k := range set {
		d.Identifiers = append(d.Identifiers, k)
	}
	sort.Strings(d.Identifiers)
	for sub, u := range t.Users {
		if set[strings.ToLower(sub)] {
			d.Users = append(d.Users, t.effective(u))
			if r, ok := t.Restricted[sub]; ok {
				if d.Restricted == nil {
					d.Restricted = map[string]string{}
				}
				d.Restricted[sub] = r
			}
		}
	}
	for _, su := range t.SCIMUsers {
		if set[strings.ToLower(su.Email)] || set[strings.ToLower(su.UserName)] {
			d.SCIMUsers = append(d.SCIMUsers, su)
		}
	}
	for _, dev := range t.Devices {
		if set[strings.ToLower(dev.User)] {
			d.Devices = append(d.Devices, dev)
		}
	}
	for _, g := range t.Grants {
		if set[strings.ToLower(g.User)] {
			d.Grants = append(d.Grants, g)
		}
	}
	sort.Slice(d.Devices, func(i, j int) bool { return d.Devices[i].ID < d.Devices[j].ID })
	return d, nil
}

// EraseReport says what EraseSubject removed.
type EraseReport struct {
	Identifiers []string // what the person was known by, so other stores can be cleaned too
	Users       int
	SCIMUsers   int
	Devices     int
	Grants      int
	Revoked     []Device // the devices that were revoked and kept without their owner, so their certificates stay dead
}

// EraseSubject removes the person from the store: the user record, the SCIM user and its group
// memberships, the access grants and the restriction. Their devices are revoked and kept as bare
// revoked entries with no owner: deleting a revoked device would make its certificate valid again.
func (s *Store) EraseSubject(tenant string, ids []string) (EraseReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return EraseReport{}, err
	}
	set := t.expand(ids)
	var rep EraseReport
	for k := range set {
		rep.Identifiers = append(rep.Identifiers, k)
	}
	sort.Strings(rep.Identifiers)
	for sub := range t.Users {
		if set[strings.ToLower(sub)] {
			delete(t.Users, sub)
			delete(t.Restricted, sub)
			delete(t.SCIMGone, sub)
			delete(t.risk, sub)
			rep.Users++
		}
	}
	for id, su := range t.SCIMUsers {
		if set[strings.ToLower(su.Email)] || set[strings.ToLower(su.UserName)] {
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
			rep.SCIMUsers++
		}
	}
	for id, dev := range t.Devices {
		if set[strings.ToLower(dev.User)] {
			rep.Revoked = append(rep.Revoked, dev)
			t.Devices[id] = Device{ID: dev.ID, Serial: dev.Serial, Revoked: true}
			rep.Devices++
		}
	}
	kept := t.Grants[:0]
	for _, g := range t.Grants {
		if set[strings.ToLower(g.User)] {
			rep.Grants++
			continue
		}
		kept = append(kept, g)
	}
	t.Grants = kept
	return rep, s.save()
}
