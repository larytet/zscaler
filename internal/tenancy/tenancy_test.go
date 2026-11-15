package tenancy

import (
	"strings"
	"testing"
)

func valid(t *testing.T) *Config {
	c, err := Validate(Config{
		Microsoft: &Microsoft{Allowed: []string{"Contoso.com", "72f988bf-86f1-41af-91ab-2d7cd011db47", "contoso.com"}, Context: "72f988bf-86f1-41af-91ab-2d7cd011db47"},
		Google:    &Google{Allowed: []string{"Contoso.com"}},
		Slack:     &Slack{Allowed: []string{"t01abcdef"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestHeadersPerVendor(t *testing.T) { // AGT-024 (DATA-002a)
	c := valid(t)
	cases := []struct {
		host, vendor string
		headers      map[string]string
	}{
		{"login.microsoftonline.com", "microsoft", map[string]string{"Restrict-Access-To-Tenants": "contoso.com,72f988bf-86f1-41af-91ab-2d7cd011db47", "Restrict-Access-Context": "72f988bf-86f1-41af-91ab-2d7cd011db47"}},
		{"LOGIN.WINDOWS.NET.", "microsoft", nil},
		{"accounts.google.com", "google", map[string]string{"X-GoogApps-Allowed-Domains": "contoso.com"}},
		{"acme.slack.com", "slack", map[string]string{"X-Slack-Allowed-Workspaces": "T01ABCDEF", "X-Slack-Allowed-Workspaces-Requester": "T01ABCDEF"}},
		{"slack.com", "slack", nil},
	}
	for _, tc := range cases {
		v, hs := c.HeadersFor(tc.host)
		if v != tc.vendor || len(hs) == 0 {
			t.Errorf("%s: %q %v", tc.host, v, hs)
		}
		for name, want := range tc.headers {
			found := false
			for _, h := range hs {
				if h.Name == name && h.Value == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: header %s=%s missing in %v", tc.host, name, want, hs)
			}
		}
	}
	// look-alike hosts and unrelated hosts get nothing: a header must never be sent to the wrong site
	for _, h := range []string{"login.microsoftonline.com.evil.example", "notlogin.microsoftonline.com", "evilslack.com", "slack.com.evil.example", "example.com", "", "accounts.google.com.attacker.net"} {
		if v, hs := c.HeadersFor(h); v != "" || hs != nil {
			t.Errorf("%q must get no restriction headers, got %q %v", h, v, hs)
		}
	}
	// only the vendors that are configured
	only := &Config{Slack: c.Slack}
	if v, _ := only.HeadersFor("login.microsoftonline.com"); v != "" {
		t.Error("an unconfigured vendor was restricted")
	}
	if (&Config{}).Empty() == false || (*Config)(nil).Empty() == false || c.Empty() {
		t.Error("Empty")
	}
}

func TestValidation(t *testing.T) { // AGT-024
	good := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	bad := map[string]Config{
		"ms no allowed":       {Microsoft: &Microsoft{Context: good}},
		"ms bad tenant":       {Microsoft: &Microsoft{Allowed: []string{"not a domain"}, Context: good}},
		"ms no context":       {Microsoft: &Microsoft{Allowed: []string{"contoso.com"}}},
		"ms context a name":   {Microsoft: &Microsoft{Allowed: []string{"contoso.com"}, Context: "contoso.com"}},
		"google bad domain":   {Google: &Google{Allowed: []string{"a,b.com"}}},
		"google header split": {Google: &Google{Allowed: []string{"a.com\r\nX-Evil: 1"}}},
		"slack bad id":        {Slack: &Slack{Allowed: []string{"workspace-name"}}},
		"slack empty":         {Slack: &Slack{}},
		"too many":            {Google: &Google{Allowed: many(51)}},
	}
	for name, c := range bad {
		if _, err := Validate(c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if c, err := Validate(Config{}); err != nil || !c.Empty() {
		t.Errorf("an empty config means none: %v", err)
	}
}

func many(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, strings.Repeat("a", i%20+1)+itoa(i)+".example.com")
	}
	return out
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		return "0"
	}
	return s
}
