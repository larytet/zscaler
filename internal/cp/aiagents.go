package cp

import (
	"github.com/larytet/zscaler/internal/agentpack"
	"github.com/larytet/zscaler/internal/ruleoftwo"
	"github.com/larytet/zscaler/internal/shadowai"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

// AI agents (AI-001, AI-002, basic). An agent is a named, non-interactive identity
// ("agent:<name>") run by a human operator. It can reach only the apps an admin lists,
// only until the grant expires, through the same broker and policy as people, and every
// session is logged under the agent's own name. It belongs to the group "ai-agent", so
// no rule that serves people serves it by accident: access needs a require_approval rule
// for that group (the grant is the approval).
const AIAgentGroup = "ai-agent"

var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type aiAgentIn struct {
	Name     string   `json:"name"`
	Operator string   `json:"operator"` // subject of an existing, enabled user
	Apps     []string `json:"apps"`
	Minutes  int      `json:"minutes"` // 1 to 1440, default 480
}

func (a *API) createAIAgent(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in aiAgentIn
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !agentName.MatchString(in.Name) {
		return nil, fail(400, "invalid", "name must be 1 to 32 characters: lower-case letters, digits and dashes")
	}
	if len(in.Apps) == 0 || len(in.Apps) > 20 {
		return nil, fail(400, "invalid", "list between 1 and 20 apps")
	}
	if in.Minutes == 0 {
		in.Minutes = 480
	}
	if in.Minutes < 1 || in.Minutes > 1440 {
		return nil, fail(400, "invalid", "minutes must be between 1 and 1440")
	}
	op, ok := a.Store.User(c.tenant, in.Operator)
	if !ok || op.Disabled || strings.HasPrefix(op.Subject, "agent:") {
		return nil, fail(400, "invalid", "operator must be an existing, enabled person")
	}
	known := a.Store.SegmentIDs(c.tenant)
	for _, app := range in.Apps {
		if !known[app] {
			return nil, fail(400, "invalid", "unknown app "+app)
		}
	}
	subject := "agent:" + in.Name
	if err := a.Store.UpsertUser(c.tenant, policy.User{Subject: subject, Groups: []string{AIAgentGroup}, Operator: op.Subject,
		Email: "AI agent " + in.Name + " run by " + op.Subject}); err != nil {
		return nil, err
	}
	// a re-created agent must not stay disabled or restricted from an earlier life
	a.Store.SetUserDisabled(c.tenant, subject, false)
	a.Store.SetRestricted(c.tenant, subject, false, "")
	until := time.Now().Add(time.Duration(in.Minutes) * time.Minute)
	for _, app := range in.Apps {
		if err := a.Store.PutGrant(c.tenant, store.Grant{User: subject, App: app, Expires: until, By: c.actor + " for " + op.Subject}); err != nil {
			return nil, err
		}
	}
	tok := a.Tokens.Issue(c.tenant, ServiceTokenPrefix+subject)
	a.log(c, "ai-agent.create", subject, nil, map[string]any{"operator": op.Subject, "apps": in.Apps, "minutes": in.Minutes})
	return map[string]any{"agent": subject, "operator": op.Subject, "apps": in.Apps, "access_until": until, "enrolment_token": tok, "token_valid_minutes": 60}, nil
}

func (a *API) listAIAgents(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	users, _ := a.Store.Users(c.tenant)
	type row struct {
		Agent    string   `json:"agent"`
		Operator string   `json:"operator"`
		Disabled bool     `json:"disabled"`
		Apps     []string `json:"apps"`
	}
	out := []row{}
	snap := a.Store.Snapshot().Tenants[c.tenant]
	for _, u := range users {
		if !strings.HasPrefix(u.Subject, "agent:") {
			continue
		}
		rw := row{Agent: u.Subject, Operator: strings.TrimPrefix(u.Email, "AI agent "+strings.TrimPrefix(u.Subject, "agent:")+" run by "), Disabled: u.Disabled, Apps: []string{}}
		if snap != nil {
			for _, g := range snap.Grants {
				if g.User == u.Subject {
					rw.Apps = append(rw.Apps, g.App)
				}
			}
		}
		out = append(out, rw)
	}
	return out, nil
}

// removeAIAgent disables the identity and ends every grant at once.
func (a *API) removeAIAgent(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	subject := "agent:" + r.PathValue("name")
	if _, ok := a.Store.User(c.tenant, subject); !ok {
		return nil, fail(404, "not_found", "not found")
	}
	if err := a.Store.SetUserDisabled(c.tenant, subject, true); err != nil {
		return nil, err
	}
	if snap := a.Store.Snapshot().Tenants[c.tenant]; snap != nil {
		for _, g := range snap.Grants {
			if g.User == subject {
				a.Store.RevokeGrant(c.tenant, subject, g.App)
			}
		}
	}
	if a.OnDisableUser != nil {
		a.OnDisableUser(c.tenant, subject)
	}
	a.log(c, "ai-agent.remove", subject, nil, nil)
	return map[string]string{"removed": subject}, nil
}

// readonlyPack returns web rules that make one agent read-only with default-deny egress (AGS-002,
// AGS-003). It changes nothing: the admin puts the rules in front of the web policy and saves it.
// Query: domains=a.com,b.com (services it may read), model=api.example.com (provider, fully
// allowed), inject=<secret name> (optional).
func (a *API) readonlyPack(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	subject := "agent:" + r.PathValue("name")
	if u, ok := a.Store.User(c.tenant, subject); !ok || u.Disabled {
		return nil, fail(404, "not_found", "no such AI agent")
	}
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	q := r.URL.Query()
	inject := q.Get("inject")
	if inject != "" {
		found := false
		list, _ := a.Store.Secrets(c.tenant)
		for _, s := range list {
			found = found || s.Name == inject
		}
		if !found {
			return nil, fail(400, "invalid", "unknown secret "+inject)
		}
	}
	cfg, _ := a.Store.Inspection(c.tenant)
	p, err := agentpack.Build(agentpack.Options{Agent: subject, Domains: split(q.Get("domains")), Model: split(q.Get("model")), Inject: inject}, cfg.Enabled)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	return p, nil
}

// lintAIAgent runs the rule-of-two check for one agent (AGS-017). Advice only.
func (a *API) lintAIAgent(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	subject := "agent:" + r.PathValue("name")
	u, ok := a.Store.User(c.tenant, subject)
	if !ok {
		return nil, fail(404, "not_found", "no such AI agent")
	}
	var apps []string
	now := time.Now()
	if snap := a.Store.Snapshot().Tenants[c.tenant]; snap != nil {
		for _, g := range snap.Grants {
			if g.User == subject && g.Expires.After(now) {
				apps = append(apps, g.App)
			}
		}
	}
	var web *policy.Policy
	if d, err := a.Store.GetPolicy(c.tenant, policy.Web); err == nil {
		web = d.Policy
	}
	return ruleoftwo.Check(u, apps, web), nil
}

// shadowAI reports AI tool use per person from recent web decisions (AGS-016).
// Query: days (1 to 30, default 7), sanctioned=ChatGPT,Claude (tools the organisation approved).
func (a *API) shadowAI(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			return nil, fail(400, "invalid", "days must be 1 to 30")
		}
		days = n
	}
	var sanctioned []string
	if v := r.URL.Query().Get("sanctioned"); v != "" {
		sanctioned = strings.Split(v, ",")
	}
	if a.Decisions == nil {
		return shadowai.Build(nil, sanctioned, nil), nil
	}
	return shadowai.Build(a.Decisions.Since(c.tenant, time.Now().Add(-time.Duration(days)*24*time.Hour)), sanctioned, nil), nil
}
