package shadowai

import (
	"testing"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
)

func e(user, target, action string) decisions.Entry {
	return decisions.Entry{Record: broker.Record{Kind: "web", User: user, Target: target, Action: action, Event: "open"}}
}

func TestReportCountsPerToolAndPerson(t *testing.T) { // AGT-011
	es := []decisions.Entry{
		e("alice", "chatgpt.com:443", "allow"), e("alice", "chatgpt.com:443", "allow"), e("bob", "chatgpt.com:443", "deny"),
		e("bob", "api.anthropic.com:443", "allow"), e("agent:bot", "claude.ai:443", "allow"),
		e("carol", "example.com:443", "allow"),                                          // not an AI tool
		{Record: broker.Record{Kind: "private", User: "dave", Target: "chatgpt.com:1"}}, // not web
		{Record: broker.Record{Kind: "web", User: "erin", Target: "chatgpt.com:443", Action: "allow", Event: "close"}},
	}
	r := Build(es, []string{"claude"}, nil)
	var gpt, claude *Tool
	for i := range r.Tools {
		switch r.Tools[i].Tool {
		case "ChatGPT":
			gpt = &r.Tools[i]
		case "Claude":
			claude = &r.Tools[i]
		}
	}
	if gpt == nil || gpt.Requests != 3 || gpt.Sanctioned || len(gpt.People) != 2 || gpt.People[0].User != "alice" || gpt.People[0].Allowed != 2 || gpt.People[1].Denied != 1 {
		t.Fatalf("%+v", gpt)
	}
	if claude == nil || !claude.Sanctioned {
		t.Fatalf("%+v", claude)
	}
	for _, tl := range r.Tools {
		for _, p := range tl.People {
			if p.User == "carol" || p.User == "dave" || p.User == "erin" {
				t.Fatalf("%s should not appear: %+v", p.User, tl)
			}
		}
	}
	if r.Tools[0].Sanctioned {
		t.Fatal("unsanctioned tools come first")
	}
	if len(r.Notes) == 0 {
		t.Fatal("limits must be stated")
	}
}

func TestToolMatchesSuffixOnly(t *testing.T) {
	if ToolFor("notchatgpt.com", nil) != "" || ToolFor("evilchatgpt.com.example.net", nil) != "" {
		t.Fatal("look-alike domains must not match")
	}
	if ToolFor("www.chatgpt.com", nil) != "ChatGPT" {
		t.Fatal("subdomain")
	}
}
