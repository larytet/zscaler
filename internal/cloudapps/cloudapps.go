// Package cloudapps is the catalogue behind cloud app control (ZIA-011): which web services are "apps",
// and what requests to them count as an action such as upload, post or share. A rule can then say "refuse
// uploads to Dropbox" instead of listing every address and path.
//
// The built-in entries are hand-made from what the author knows of each service's public interface. They
// have NOT been checked against the live services, vendors change their endpoints, and a request this
// catalogue does not recognise as an action is simply not matched. Every organisation can add apps of
// its own, and replace a built-in one, to correct this.
package cloudapps

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

// Actions a rule can name.
var Actions = []string{"upload", "download", "post", "share", "delete", "login"}

// Rule recognises one kind of request. All the conditions given must hold.
type Rule struct {
	Hosts    []string `json:"hosts,omitempty"`    // the request host is one of these (or a subdomain); empty means any of the app's domains
	Methods  []string `json:"methods,omitempty"`  // empty means any method
	Paths    []string `json:"paths,omitempty"`    // the path starts with one of these; empty means any path
	Contains []string `json:"contains,omitempty"` // the path contains one of these
}

// App is one service.
type App struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Domains []string          `json:"domains"`           // the service and its subdomains
	Actions map[string][]Rule `json:"actions,omitempty"` // action name to the rules that recognise it
	Builtin bool              `json:"builtin,omitempty"`
}

var (
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	methodRe = regexp.MustCompile(`^[A-Z]{3,10}$`)
)

// IsAction reports whether name is an action a rule can use.
func IsAction(name string) bool {
	for _, a := range Actions {
		if a == name {
			return true
		}
	}
	return false
}

// ValidID reports whether id can name an app.
func ValidID(id string) bool { return idRe.MatchString(id) }

// Validate checks an app (and returns it cleaned) before it is stored.
func Validate(a App) (App, error) {
	a.ID = strings.ToLower(strings.TrimSpace(a.ID))
	if !idRe.MatchString(a.ID) {
		return a, errors.New("id: 1 to 40 characters, lower-case letters, digits and dash")
	}
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" {
		a.Name = a.ID
	}
	if len(a.Name) > 80 || strings.ContainsAny(a.Name, "\r\n\x00") {
		return a, errors.New("name: one line, at most 80 characters")
	}
	if len(a.Domains) == 0 || len(a.Domains) > 20 {
		return a, errors.New("domains: list 1 to 20")
	}
	for i, d := range a.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if !domainRe.MatchString(d) {
			return a, errors.New("domain " + d + " is not a plain domain (no scheme, path or wildcard; subdomains are included)")
		}
		a.Domains[i] = d
	}
	if len(a.Actions) > len(Actions) {
		return a, errors.New("too many actions")
	}
	for name, rules := range a.Actions {
		if !IsAction(name) {
			return a, errors.New("unknown action " + name + " (known: " + strings.Join(Actions, ", ") + ")")
		}
		if len(rules) == 0 || len(rules) > 20 {
			return a, errors.New("action " + name + ": list 1 to 20 rules")
		}
		for ri := range rules {
			r := &rules[ri]
			for i, h := range r.Hosts {
				h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
				if !domainRe.MatchString(h) || !withinDomains(h, a.Domains) {
					return a, errors.New("rule host " + h + " must be one of the app's domains or a subdomain of one")
				}
				r.Hosts[i] = h
			}
			for i, m := range r.Methods {
				m = strings.ToUpper(strings.TrimSpace(m))
				if !methodRe.MatchString(m) {
					return a, errors.New("method " + m + " is not valid")
				}
				r.Methods[i] = m
			}
			for _, p := range r.Paths {
				if !strings.HasPrefix(p, "/") || len(p) > 200 || strings.ContainsAny(p, " \r\n?#") {
					return a, errors.New("path " + p + " must start with / and have no space, ? or #")
				}
			}
			for _, c := range r.Contains {
				if c == "" || len(c) > 100 || strings.ContainsAny(c, " \r\n?#") {
					return a, errors.New("contains " + c + " must be one short piece of path")
				}
			}
		}
	}
	a.Builtin = false
	return a, nil
}

func withinDomains(h string, domains []string) bool {
	for _, d := range domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// Builtin returns the built-in apps. See the note at the top of the package: not verified.
func Builtin() []App {
	post := []string{"POST"}
	apps := []App{
		{ID: "dropbox", Name: "Dropbox", Domains: []string{"dropbox.com", "dropboxapi.com", "dropboxusercontent.com"}, Actions: map[string][]Rule{
			"upload":   {{Hosts: []string{"content.dropboxapi.com"}, Methods: post, Paths: []string{"/2/files/upload"}}, {Methods: []string{"POST", "PUT"}, Paths: []string{"/ajax_upload", "/upload"}}},
			"download": {{Hosts: []string{"content.dropboxapi.com"}, Methods: post, Paths: []string{"/2/files/download"}}},
			"share":    {{Hosts: []string{"api.dropboxapi.com"}, Methods: post, Paths: []string{"/2/sharing/"}}},
			"delete":   {{Hosts: []string{"api.dropboxapi.com"}, Methods: post, Paths: []string{"/2/files/delete"}}}}},
		{ID: "google-drive", Name: "Google Drive", Domains: []string{"drive.google.com", "docs.google.com", "drive.usercontent.google.com"}, Actions: map[string][]Rule{
			"upload":   {{Methods: []string{"POST", "PUT"}, Paths: []string{"/upload/"}}, {Methods: []string{"POST", "PUT"}, Contains: []string{"/upload"}}},
			"download": {{Paths: []string{"/uc", "/download"}}},
			"share":    {{Methods: post, Contains: []string{"/permissions", "/share"}}}}},
		{ID: "box", Name: "Box", Domains: []string{"box.com", "boxcloud.com"}, Actions: map[string][]Rule{
			"upload":   {{Hosts: []string{"upload.box.com"}, Methods: post}},
			"download": {{Methods: []string{"GET"}, Contains: []string{"/download"}}}}},
		{ID: "wetransfer", Name: "WeTransfer", Domains: []string{"wetransfer.com", "we.tl"}, Actions: map[string][]Rule{
			"upload": {{Methods: []string{"POST", "PUT"}, Contains: []string{"/transfers", "/upload"}}}}},
		{ID: "slack", Name: "Slack", Domains: []string{"slack.com"}, Actions: map[string][]Rule{
			"post":   {{Methods: post, Paths: []string{"/api/chat.postMessage", "/api/chat.update", "/api/chat.postEphemeral"}}},
			"upload": {{Methods: post, Paths: []string{"/api/files."}}, {Hosts: []string{"files.slack.com"}, Methods: []string{"POST", "PUT"}}}}},
		{ID: "pastebin", Name: "Pastebin", Domains: []string{"pastebin.com"}, Actions: map[string][]Rule{
			"post": {{Methods: post}}}},
		{ID: "github-gist", Name: "GitHub Gist", Domains: []string{"gist.github.com"}, Actions: map[string][]Rule{
			"post": {{Methods: post}}}},
		{ID: "chatgpt", Name: "ChatGPT", Domains: []string{"chatgpt.com", "chat.openai.com"}, Actions: map[string][]Rule{
			"post":   {{Methods: post, Paths: []string{"/backend-api/conversation"}}},
			"upload": {{Methods: post, Paths: []string{"/backend-api/files"}}}}},
	}
	for i := range apps {
		apps[i].Builtin = true
	}
	return apps
}

// Catalog is the apps one tenant sees: the built-in ones, with its own added or replacing.
type Catalog struct{ apps map[string]App }

// NewCatalog merges a tenant's own apps over the built-in ones.
func NewCatalog(custom []App) *Catalog {
	c := &Catalog{apps: map[string]App{}}
	for _, a := range Builtin() {
		c.apps[a.ID] = a
	}
	for _, a := range custom {
		c.apps[a.ID] = a
	}
	return c
}

// Has reports whether an app of this id exists.
func (c *Catalog) Has(id string) bool { _, ok := c.apps[id]; return ok }

// List returns every app, ordered by id.
func (c *Catalog) List() []App {
	out := make([]App, 0, len(c.apps))
	for _, a := range c.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func hostIn(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return withinDomains(host, domains)
}

// AppsFor returns the ids of the apps a host belongs to.
func (c *Catalog) AppsFor(host string) []string {
	if c == nil {
		return nil
	}
	var out []string
	for id, a := range c.apps {
		if hostIn(host, a.Domains) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (r Rule) matches(host, method, path string) bool {
	if len(r.Hosts) > 0 && !hostIn(host, r.Hosts) {
		return false
	}
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			ok = ok || strings.EqualFold(m, method)
		}
		if !ok {
			return false
		}
	}
	if len(r.Paths) > 0 {
		ok := false
		for _, p := range r.Paths {
			ok = ok || strings.HasPrefix(path, p)
		}
		if !ok {
			return false
		}
	}
	if len(r.Contains) > 0 {
		ok := false
		for _, s := range r.Contains {
			ok = ok || strings.Contains(path, s)
		}
		if !ok {
			return false
		}
	}
	return true
}

// ActionsFor returns the "app:action" pairs a request to host is recognised as.
func (c *Catalog) ActionsFor(host, method, path string) []string {
	if c == nil {
		return nil
	}
	var out []string
	for id, a := range c.apps {
		if !hostIn(host, a.Domains) {
			continue
		}
		for action, rules := range a.Actions {
			for _, r := range rules {
				if r.matches(host, method, path) {
					out = append(out, id+":"+action)
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
