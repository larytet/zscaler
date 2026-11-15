// Package agentpack builds the web rules that make an AI agent read-only with a default-deny
// egress list (AGS-002, AGS-003). It only produces rules; an admin reviews and saves them.
package agentpack

import (
	"errors"
	"strings"

	"github.com/larytet/zscaler/internal/policy"
)

// WriteMethods are the verbs the pack refuses. Methods are only visible on decrypted traffic.
var WriteMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// Options say what the agent may reach.
type Options struct {
	Agent    string   // "agent:<name>"
	Domains  []string // services it may read
	Model    []string // model provider domains, fully allowed (a model call is a POST)
	Inject   string   // optional stored secret to add on the read rule
	Priority int      // first priority number; the pack uses four consecutive numbers
}

// Pack is the result: rules to put in front of the tenant's other web rules, and plain-language
// warnings about what the rules cannot do in the tenant's current setup.
type Pack struct {
	Rules    []policy.Rule `json:"rules"`
	Warnings []string      `json:"warnings"`
}

func clean(in []string) ([]string, error) {
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "/:@ *") || strings.HasPrefix(d, ".") {
			return nil, errors.New("not a plain domain: " + d)
		}
		out = append(out, d)
	}
	return out, nil
}

// Build returns, in order: allow the model provider; refuse write methods on the listed services;
// allow the rest of the listed services (reads, and the tunnel itself); refuse everything else for
// this agent. Order matters because the first matching rule wins.
func Build(o Options, inspectionOn bool) (*Pack, error) {
	if !strings.HasPrefix(o.Agent, "agent:") || len(o.Agent) < 7 {
		return nil, errors.New("agent must be an agent identity")
	}
	doms, err := clean(o.Domains)
	if err != nil {
		return nil, err
	}
	model, err := clean(o.Model)
	if err != nil {
		return nil, err
	}
	if len(doms) == 0 && len(model) == 0 {
		return nil, errors.New("list at least one domain the agent may reach")
	}
	if o.Priority < 1 {
		o.Priority = 1
	}
	who := []string{o.Agent}
	slug := strings.TrimPrefix(o.Agent, "agent:")
	p := &Pack{Rules: []policy.Rule{}}
	prio := o.Priority
	add := func(r policy.Rule) { r.Priority = prio; prio++; p.Rules = append(p.Rules, r) }
	if len(model) > 0 {
		add(policy.Rule{ID: "agent-" + slug + "-model", Action: policy.Allow, Reason: "agent-model-provider", Match: policy.Match{Users: who, Domains: model}})
	}
	if len(doms) > 0 {
		add(policy.Rule{ID: "agent-" + slug + "-no-writes", Action: policy.Deny, Reason: "agent-read-only",
			Match: policy.Match{Users: who, Domains: doms, Methods: WriteMethods}})
		add(policy.Rule{ID: "agent-" + slug + "-read", Action: policy.Allow, Inject: o.Inject, Reason: "agent-read",
			Match: policy.Match{Users: who, Domains: doms}})
	}
	add(policy.Rule{ID: "agent-" + slug + "-egress-deny", Action: policy.Deny, Reason: "agent-egress",
		Match: policy.Match{Users: who}})
	if len(doms) > 0 && !inspectionOn {
		p.Warnings = append(p.Warnings, "TLS inspection is off: the read-only rule cannot see request methods, so writes to the listed services are NOT blocked. Turn inspection on before relying on this pack.")
	}
	if len(doms) > 0 {
		p.Warnings = append(p.Warnings,
			"Domains on the inspection exempt list are tunnelled unseen: writes to them are not blocked.",
			"Only the verbs "+strings.Join(WriteMethods, ", ")+" are refused. A read-only API that changes data on GET is not made safe by this.",
			"Web rules cannot send a write to approval (require_approval is for private apps): writes are denied.")
	}
	return p, nil
}
