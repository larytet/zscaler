package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Validate returns all errors found (DESIGN.md D2.7). known may be nil.
func Validate(p *Policy, known map[string]bool) []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if p.Kind != Private && p.Kind != Web {
		add("unknown kind %q", p.Kind)
	}
	switch p.DefaultAction {
	case "", Allow, Deny, Warn:
	default:
		add("unknown default_action %q", p.DefaultAction)
	}
	if p.Kind == Private && p.DefaultAction != Deny {
		add("private policy default_action must be deny")
	}
	ids, prios := map[string]bool{}, map[int]bool{}
	for i, r := range p.Rules {
		w := fmt.Sprintf("rule[%d] %q", i, r.ID)
		if r.ID == "" {
			add("%s: empty id", w)
		}
		if ids[r.ID] {
			add("%s: duplicate id", w)
		}
		ids[r.ID] = true
		if prios[r.Priority] {
			add("%s: duplicate priority %d", w, r.Priority)
		}
		prios[r.Priority] = true
		switch r.Action {
		case Allow, Deny:
		case Warn:
			if p.Kind != Web {
				add("%s: warn is only valid for web policies", w)
			}
		default:
			add("%s: unknown action %q", w, r.Action)
		}
		m := r.Match
		if r.Action == Allow && len(m.Users)+len(m.Groups)+len(m.Apps)+len(m.Domains)+len(m.Categories) == 0 && m.Posture == nil {
			add("%s: allow rule matches everything", w)
		}
		for _, a := range m.Apps {
			if known != nil && !known[a] {
				add("%s: unknown segment %q", w, a)
			}
		}
		for _, d := range m.Domains {
			if strings.ContainsAny(d, "/:@ ") || d == "" {
				add("%s: bad domain %q (no scheme, path or port)", w, d)
			}
		}
		if n := m.Network; n != nil {
			for _, c := range n.SrcCIDRs {
				if _, err := netip.ParsePrefix(c); err != nil {
					add("%s: bad CIDR %q", w, c)
				}
			}
		}
		if t := m.Time; t != nil {
			if t.TZ != "" {
				if _, err := time.LoadLocation(t.TZ); err != nil {
					add("%s: bad time zone %q", w, t.TZ)
				}
			}
			if (t.From == "") != (t.To == "") {
				add("%s: time needs both from and to", w)
			}
			for _, s := range []string{t.From, t.To} {
				if s != "" {
					if _, err := parseHM(s); err != nil {
						add("%s: bad time %q", w, s)
					}
				}
			}
			for _, d := range t.Days {
				if _, ok := dayNames[strings.ToLower(d)]; !ok {
					add("%s: bad day %q", w, d)
				}
			}
		}
	}
	return errs
}
