package cp

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/versions"
)

// A list of who runs which version, built from what the components say about themselves when they call
// the control plane (GAP-REQ-08). It is kept in memory: after a restart it fills again within a minute for
// nodes and connectors and within the certificate renewal period for agents.

type seenVersion struct {
	role, tenant, name, user, version string
	seen                              time.Time
}

type fleet struct {
	mu sync.Mutex
	m  map[string]seenVersion
}

const maxFleet = 20000

// noteVersion records the version a certificate-holding component announced in its request.
func (a *API) noteVersion(r *http.Request, id pki.Identity) {
	v := strings.TrimSpace(r.Header.Get(versions.Header))
	if v == "" || len(v) > 64 {
		return
	}
	for _, c := range v { // a version is letters, digits and . + - _ ; anything else is ignored, not stored
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '-' || c == '_') {
			return
		}
	}
	k := id.Role + "|" + id.Tenant + "|" + id.Device
	a.fleet.mu.Lock()
	defer a.fleet.mu.Unlock()
	if a.fleet.m == nil {
		a.fleet.m = map[string]seenVersion{}
	}
	if _, known := a.fleet.m[k]; !known && len(a.fleet.m) >= maxFleet {
		return
	}
	a.fleet.m[k] = seenVersion{role: id.Role, tenant: id.Tenant, name: id.Device, user: id.Subject, version: v, seen: time.Now()}
}

type component struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	User     string `json:"user,omitempty"`
	Version  string `json:"version"`
	LastSeen string `json:"last_seen"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
}

// versionStatus lists what runs which version for the tenant: its connectors and devices, and the
// enforcement nodes, which serve every tenant and so are listed to all.
func (a *API) versionStatus(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	a.fleet.mu.Lock()
	var seen []seenVersion
	for _, s := range a.fleet.m {
		if s.tenant == c.tenant || s.role == pki.RoleEN {
			seen = append(seen, s)
		}
	}
	a.fleet.mu.Unlock()
	sort.Slice(seen, func(i, j int) bool {
		if seen[i].role != seen[j].role {
			return seen[i].role < seen[j].role
		}
		return seen[i].name < seen[j].name
	})
	out := []component{}
	counts := map[string]int{}
	var warn []string
	for _, s := range seen {
		st, msg := versions.Classify(a.Version, s.version)
		counts[st]++
		out = append(out, component{Role: s.role, Name: s.name, User: s.user, Version: s.version, LastSeen: s.seen.UTC().Format(time.RFC3339), Status: st, Message: msg})
		if st == versions.TooOld || st == versions.Newer {
			warn = append(warn, s.role+" "+s.name+" "+msg)
		}
		if a.MinAgentVersion != "" && (s.role == pki.RoleDevice || s.role == pki.RoleWorkspace) {
			if cv, ok := versions.Parse(s.version); ok {
				if mv, ok2 := versions.Parse(a.MinAgentVersion); ok2 && (cv.Major < mv.Major || cv.Major == mv.Major && (cv.Minor < mv.Minor || cv.Minor == mv.Minor && cv.Patch < mv.Patch)) {
					warn = append(warn, s.role+" "+s.name+" is below the minimum agent version ("+a.MinAgentVersion+"), so it refuses to start sessions")
				}
			}
		}
	}
	if warn == nil {
		warn = []string{}
	}
	return map[string]any{
		"control_plane":         a.Version,
		"supported":             "A component may be at most one minor version older than the control plane, and never newer.",
		"upgrade_order":         "control plane, then enforcement nodes, then connectors, then agents. You can stop between steps.",
		"minimum_agent_version": a.MinAgentVersion,
		"counts":                counts,
		"components":            out,
		"warnings":              warn,
		"not_listed":            "A component appears after it next calls the control plane (nodes and connectors within a minute, agents when they renew their certificate). Components older than this feature do not announce a version and are not listed.",
	}, nil
}
