// Package ruleoftwo is a deterministic check of an AI agent's reach (AGS-017). An agent that can
// (A) read private data, (B) take in untrusted content and (C) send data out or change things is
// open to being steered by that content into leaking what it can read. Holding all three is the
// risky combination; this check tells an owner when an agent does. It gives advice only.
package ruleoftwo

import (
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

type Result struct {
	ReadsPrivateData    bool     `json:"reads_private_data"`
	TakesUntrustedInput bool     `json:"takes_untrusted_input"`
	CanSendOrChange     bool     `json:"can_send_or_change"`
	Warning             bool     `json:"warning"`
	Message             string   `json:"message"`
	Why                 []string `json:"why"`
	Advice              []string `json:"advice"`
}

// Check looks at what the agent can reach: private apps it holds access to, and what the web
// policy lets it do to a site nobody has vetted (probed with a made-up host name).
func Check(agent policy.User, privateApps []string, web *policy.Policy) Result {
	const probe = "untrusted-site.invalid"
	r := Result{Why: []string{}, Advice: []string{}}
	if len(privateApps) > 0 {
		r.ReadsPrivateData = true
		r.Why = append(r.Why, "A: it holds access to private apps")
	}
	allowed := func(method string) bool {
		if web == nil {
			return false
		}
		d := web.Evaluate(policy.Request{Kind: policy.Web, User: agent, Host: probe, Now: time.Now(), Inspected: true, Method: method, Path: "/"})
		return d.Action == policy.Allow || d.Action == policy.Warn
	}
	if allowed("GET") {
		r.TakesUntrustedInput = true
		r.Why = append(r.Why, "B: the web policy lets it read pages from sites nobody has vetted")
	}
	if allowed("POST") {
		r.CanSendOrChange = true
		r.Why = append(r.Why, "C: the web policy lets it send data to sites nobody has vetted")
	}
	r.Warning = r.ReadsPrivateData && r.TakesUntrustedInput && r.CanSendOrChange
	if r.Warning {
		r.Message = "This agent can read private data, take in untrusted content and send data out. Content it reads could steer it into leaking what it can read. Remove one of the three."
		r.Advice = append(r.Advice,
			"Limit its web access to the services it needs (the read-only pack does this and refuses everything else).",
			"Or remove its access to private apps if it must browse freely.",
			"Or refuse writes and uploads for it, so it can read but not send.")
	} else {
		r.Message = "This agent does not hold all three of: private data, untrusted input, and a way out."
	}
	r.Advice = append(r.Advice, "This check only follows the policy as saved; it cannot see what the agent's software does with what it reads.")
	return r
}
