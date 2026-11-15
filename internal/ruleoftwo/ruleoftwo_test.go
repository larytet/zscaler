package ruleoftwo

import (
	"testing"

	"github.com/larytet/zscaler/internal/agentpack"
	"github.com/larytet/zscaler/internal/policy"
)

func web(t *testing.T, def policy.Action, rules ...policy.Rule) *policy.Policy {
	p := &policy.Policy{Kind: policy.Web, DefaultAction: def, Rules: rules}
	if err := p.Compile(nil); err != nil {
		t.Fatal(err)
	}
	return p
}

var bot = policy.User{Subject: "agent:bot", Email: "agent:bot", Groups: []string{"ai-agent"}}

func TestAllThreeLegsWarn(t *testing.T) { // AGT-012
	r := Check(bot, []string{"erp"}, web(t, policy.Allow))
	if !r.Warning || !r.ReadsPrivateData || !r.TakesUntrustedInput || !r.CanSendOrChange || len(r.Why) != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestMissingALegGivesNoWarning(t *testing.T) {
	if r := Check(bot, nil, web(t, policy.Allow)); r.Warning { // no private data
		t.Fatalf("%+v", r)
	}
	if r := Check(bot, []string{"erp"}, web(t, policy.Deny)); r.Warning || r.TakesUntrustedInput { // no web
		t.Fatalf("%+v", r)
	}
	if r := Check(bot, []string{"erp"}, nil); r.Warning {
		t.Fatalf("%+v", r)
	}
}

func TestReadOnlyPackRemovesTheWayOut(t *testing.T) {
	pk, _ := agentpack.Build(agentpack.Options{Agent: "agent:bot", Domains: []string{"api.crm.example"}}, true)
	p := web(t, policy.Allow, pk.Rules...)
	if r := Check(bot, []string{"erp"}, p); r.Warning || r.TakesUntrustedInput || r.CanSendOrChange {
		t.Fatalf("the egress deny rule should close legs B and C: %+v", r)
	}
	// a read-only rule alone leaves B but closes C
	p2 := web(t, policy.Allow, policy.Rule{ID: "ro", Priority: 1, Action: policy.Deny, Match: policy.Match{Users: []string{"agent:bot"}, Methods: []string{"POST", "PUT", "PATCH", "DELETE"}}})
	if r := Check(bot, []string{"erp"}, p2); r.Warning || !r.TakesUntrustedInput || r.CanSendOrChange {
		t.Fatalf("%+v", r)
	}
}
