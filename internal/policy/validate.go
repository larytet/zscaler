package policy

import (
	"fmt"

	"github.com/larytet/zscaler/internal/dlp"
	"net/netip"
	"reflect"
	"sort"
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
		case Isolate:
			if len(r.Match.Apps)+len(r.Match.Domains)+len(r.Match.Categories) == 0 {
				add("%s: isolate must name apps, domains or categories, or it would send everything to the workspace", w)
			}
		case Approve:
			if p.Kind != Private {
				add("%s: require_approval is only valid for private policies", w)
			}
			if len(r.Match.Apps) == 0 {
				add("%s: require_approval must name the apps it covers", w)
			}
		case Warn:
			if p.Kind != Web {
				add("%s: warn is only valid for web policies", w)
			}
		default:
			add("%s: unknown action %q", w, r.Action)
		}
		m := r.Match
		if r.Action == Allow && len(m.Users)+len(m.Groups)+len(m.Apps)+len(m.Domains)+len(m.Categories)+len(m.Paths)+len(m.Methods)+len(m.DLP) == 0 && m.Workspace == nil && m.Posture == nil && m.MaxRisk == nil && m.MinRisk == nil {
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
		if len(m.Paths)+len(m.Methods) > 0 && p.Kind != Web {
			add("%s: paths and methods are only valid in web policies", w)
		}
		if len(m.DLP) > 0 && p.Kind != Web {
			add("%s: dlp is only valid in web policies", w)
		}
		for _, dn := range m.DLP {
			if !dlp.Known(dn) {
				add("%s: unknown dlp type %q (known: %s)", w, dn, strings.Join(dlp.Names(), ", "))
			}
		}
		for _, pth := range m.Paths {
			if !strings.HasPrefix(pth, "/") || strings.ContainsAny(pth, " \r\n") {
				add("%s: path %q must start with / and contain no spaces", w, pth)
			}
		}
		for _, mt := range m.Methods {
			switch strings.ToUpper(mt) {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			default:
				add("%s: unknown method %q", w, mt)
			}
		}
		for name, v := range map[string]*int{"max_risk": m.MaxRisk, "min_risk": m.MinRisk} {
			if v != nil && (*v < 0 || *v > 100) {
				add("%s: %s must be between 0 and 100", w, name)
			}
		}
		if m.MinRisk != nil && m.MaxRisk != nil && *m.MinRisk > *m.MaxRisk {
			add("%s: min_risk is above max_risk, the rule can never match", w)
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

// Warnings reports problems that are not errors. Today: a rule that can never
// match because an earlier rule has an identical match, or matches everything
// (VAL-009). It does not attempt full subset analysis.
func Warnings(p *Policy) []string {
	rules := append([]Rule(nil), p.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	var out []string
	for i, r := range rules {
		for _, e := range rules[:i] {
			if reflect.DeepEqual(e.Match, r.Match) || reflect.DeepEqual(e.Match, Match{}) {
				out = append(out, fmt.Sprintf("rule %q can never match: rule %q (priority %d) always matches first", r.ID, e.ID, e.Priority))
				break
			}
		}
	}
	return out
}
