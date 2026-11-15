// Package tenancy implements tenancy restriction (DATA-002a): on decrypted traffic to a SaaS vendor's
// sign-in hosts the platform adds the header that vendor documents for limiting sign-in to the
// organisation's own tenants, so a person cannot sign in to a personal or foreign account from a
// managed device. It adds headers only; the vendor enforces them.
//
// The hosts and header names below are the ones in each vendor's tenant-restriction documentation as
// the author knows them. They have not been checked against the live services in this repository's
// tests, and a vendor can change them: check them before relying on this.
package tenancy

import (
	"errors"
	"regexp"
	"strings"
)

// Config is a tenant's restrictions. A nil vendor is not restricted.
type Config struct {
	Microsoft *Microsoft `json:"microsoft,omitempty"`
	Google    *Google    `json:"google,omitempty"`
	Slack     *Slack     `json:"slack,omitempty"`
}

// Microsoft: Entra ID sign-in. Allowed are tenant domains or directory IDs; Context is the directory ID of the
// organisation that sets the restriction.
type Microsoft struct {
	Allowed []string `json:"allowed"`
	Context string   `json:"context"`
}

// Google: Workspace sign-in. Allowed are the organisation's Google Workspace domains.
type Google struct {
	Allowed []string `json:"allowed"`
}

// Slack: allowed are workspace IDs (T followed by letters and digits).
type Slack struct {
	Allowed []string `json:"allowed"`
}

// Header is one request header to add. It replaces a header of the same name the client sent, so a
// user cannot lift the restriction by sending their own.
type Header struct{ Name, Value string }

var (
	guid      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	domain    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	slackTeam = regexp.MustCompile(`^[TE][A-Z0-9]{6,14}$`)
)

// Hosts lists, per vendor, the sign-in hosts a restriction applies to (a host and its subdomains).
var Hosts = map[string][]string{
	"microsoft": {"login.microsoftonline.com", "login.microsoft.com", "login.windows.net"},
	"google":    {"accounts.google.com", "accounts.youtube.com"},
	"slack":     {"slack.com"},
}

func cleanList(in []string, ok func(string) bool, what string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !ok(v) {
			return nil, errors.New(what + ": " + v + " is not valid")
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New(what + ": list at least one")
	}
	if len(out) > 50 {
		return nil, errors.New(what + ": at most 50")
	}
	return out, nil
}

// Validate checks a config and returns it cleaned. An empty config (no vendor) is valid and means none.
func Validate(c Config) (Config, error) {
	var err error
	if m := c.Microsoft; m != nil {
		if m.Allowed, err = cleanList(lower(m.Allowed), func(s string) bool { return guid.MatchString(s) || domain.MatchString(s) }, "microsoft allowed tenants (domains or directory IDs)"); err != nil {
			return c, err
		}
		if !guid.MatchString(strings.TrimSpace(m.Context)) {
			return c, errors.New("microsoft context must be the directory (tenant) ID of your organisation, a GUID")
		}
		m.Context = strings.TrimSpace(m.Context)
	}
	if g := c.Google; g != nil {
		if g.Allowed, err = cleanList(lower(g.Allowed), domain.MatchString, "google allowed domains"); err != nil {
			return c, err
		}
	}
	if s := c.Slack; s != nil {
		if s.Allowed, err = cleanList(upper(s.Allowed), slackTeam.MatchString, "slack allowed workspace IDs"); err != nil {
			return c, err
		}
	}
	return c, nil
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

func upper(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(strings.TrimSpace(s))
	}
	return out
}

// Empty reports whether no vendor is restricted.
func (c *Config) Empty() bool {
	return c == nil || c.Microsoft == nil && c.Google == nil && c.Slack == nil
}

func matches(host string, suffixes []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range suffixes {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// HeadersFor returns the headers to add to a request to host, and which vendor asked for them
// ("" when none apply).
func (c *Config) HeadersFor(host string) (string, []Header) {
	if c.Empty() {
		return "", nil
	}
	switch {
	case c.Microsoft != nil && matches(host, Hosts["microsoft"]):
		return "microsoft", []Header{{"Restrict-Access-To-Tenants", strings.Join(c.Microsoft.Allowed, ",")}, {"Restrict-Access-Context", c.Microsoft.Context}}
	case c.Google != nil && matches(host, Hosts["google"]):
		return "google", []Header{{"X-GoogApps-Allowed-Domains", strings.Join(c.Google.Allowed, ",")}}
	case c.Slack != nil && matches(host, Hosts["slack"]):
		v := strings.Join(c.Slack.Allowed, ",")
		return "slack", []Header{{"X-Slack-Allowed-Workspaces-Requester", v}, {"X-Slack-Allowed-Workspaces", v}}
	}
	return "", nil
}

// AllHosts returns every sign-in host of the vendors that are restricted, for warnings.
func (c *Config) AllHosts() []string {
	var out []string
	if c.Empty() {
		return nil
	}
	if c.Microsoft != nil {
		out = append(out, Hosts["microsoft"]...)
	}
	if c.Google != nil {
		out = append(out, Hosts["google"]...)
	}
	if c.Slack != nil {
		out = append(out, Hosts["slack"]...)
	}
	return out
}
