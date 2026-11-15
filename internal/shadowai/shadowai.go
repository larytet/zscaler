// Package shadowai reports which AI tools people in the organisation actually use, from web
// decisions the platform already holds (AGS-016). It names domains and people; it never looks at
// content.
package shadowai

import (
	"net"
	"sort"
	"strings"

	"github.com/larytet/zscaler/internal/decisions"
)

// Tools is a built-in list of well-known AI services, matched by domain suffix. It is a starting
// point, not a complete catalogue, and goes stale: the report says so.
var Tools = map[string]string{
	"chatgpt.com": "ChatGPT", "openai.com": "OpenAI", "claude.ai": "Claude", "anthropic.com": "Anthropic",
	"gemini.google.com": "Gemini", "copilot.microsoft.com": "Copilot", "perplexity.ai": "Perplexity",
	"deepseek.com": "DeepSeek", "mistral.ai": "Mistral", "x.ai": "Grok", "grok.com": "Grok",
	"huggingface.co": "Hugging Face", "poe.com": "Poe", "character.ai": "Character.AI", "cursor.com": "Cursor",
	"githubcopilot.com": "GitHub Copilot", "midjourney.com": "Midjourney", "replicate.com": "Replicate",
}

// ToolFor returns the tool name for a host, or "".
func ToolFor(host string, extra map[string]string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, m := range []map[string]string{extra, Tools} {
		for d, n := range m {
			if host == d || strings.HasSuffix(host, "."+d) {
				return n
			}
		}
	}
	return ""
}

type Person struct {
	User     string `json:"user"`
	Requests int    `json:"requests"`
	Allowed  int    `json:"allowed"`
	Denied   int    `json:"denied"`
}

type Tool struct {
	Tool       string   `json:"tool"`
	Sanctioned bool     `json:"sanctioned"`
	Requests   int      `json:"requests"`
	People     []Person `json:"people"`
}

type Report struct {
	Tools []Tool   `json:"tools"`
	Notes []string `json:"notes"`
}

// Build counts web decisions by tool and person. sanctioned names tools the organisation has
// approved (matched case-insensitively against the tool name). AI agents ("agent:") are listed
// like people so their use is visible.
func Build(es []decisions.Entry, sanctioned []string, extra map[string]string) Report {
	ok := map[string]bool{}
	for _, s := range sanctioned {
		ok[strings.ToLower(strings.TrimSpace(s))] = true
	}
	type key struct{ tool, user string }
	per := map[key]*Person{}
	tot := map[string]int{}
	for _, e := range es {
		if e.Kind != "web" || e.User == "" || e.Event == "close" || e.Action == "info" {
			continue
		}
		host := e.Target
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		t := ToolFor(host, extra)
		if t == "" {
			continue
		}
		p := per[key{t, e.User}]
		if p == nil {
			p = &Person{User: e.User}
			per[key{t, e.User}] = p
		}
		p.Requests++
		tot[t]++
		switch e.Action {
		case "allow":
			p.Allowed++
		case "deny":
			p.Denied++
		}
	}
	r := Report{Tools: []Tool{}}
	for t, n := range tot {
		tl := Tool{Tool: t, Sanctioned: ok[strings.ToLower(t)], Requests: n}
		for k, p := range per {
			if k.tool == t {
				tl.People = append(tl.People, *p)
			}
		}
		sort.Slice(tl.People, func(i, j int) bool {
			if tl.People[i].Requests != tl.People[j].Requests {
				return tl.People[i].Requests > tl.People[j].Requests
			}
			return tl.People[i].User < tl.People[j].User
		})
		r.Tools = append(r.Tools, tl)
	}
	sort.Slice(r.Tools, func(i, j int) bool {
		if r.Tools[i].Sanctioned != r.Tools[j].Sanctioned {
			return !r.Tools[i].Sanctioned // unsanctioned first: that is what the owner wants to see
		}
		if r.Tools[i].Requests != r.Tools[j].Requests {
			return r.Tools[i].Requests > r.Tools[j].Requests
		}
		return r.Tools[i].Tool < r.Tools[j].Tool
	})
	r.Notes = []string{
		"Counts come from web decisions the platform holds in memory (the most recent ones only), so a long period may be partly missing.",
		"Only traffic that goes through the platform's web proxy is seen; a laptop without the agent, or a phone, is invisible.",
		"The tool list is built in and incomplete; an AI feature inside another site is not recognised.",
		"Requests are counted, not people's time or content.",
	}
	return r
}
