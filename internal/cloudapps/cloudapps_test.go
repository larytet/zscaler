package cloudapps

import (
	"strings"
	"testing"
)

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestBuiltinAppsAreValidAndRecogniseActions(t *testing.T) { // AGT-031 (ZIA-011)
	for _, a := range Builtin() {
		if !a.Builtin {
			t.Errorf("%s is not marked built-in", a.ID)
		}
		v, err := Validate(a)
		if err != nil {
			t.Errorf("built-in app %s does not pass its own validation: %v", a.ID, err)
		}
		if v.Builtin {
			t.Errorf("a validated app must not claim to be built-in")
		}
	}
	c := NewCatalog(nil)
	cases := []struct {
		host, method, path string
		want               []string
		not                []string
	}{
		{"content.dropboxapi.com", "POST", "/2/files/upload", []string{"dropbox:upload"}, []string{"dropbox:download", "dropbox:share"}},
		{"content.dropboxapi.com", "POST", "/2/files/download", []string{"dropbox:download"}, []string{"dropbox:upload"}},
		{"api.dropboxapi.com", "POST", "/2/sharing/create_shared_link_with_settings", []string{"dropbox:share"}, []string{"dropbox:upload"}},
		{"api.dropboxapi.com", "POST", "/2/files/upload", nil, []string{"dropbox:upload"}}, // the rule names the content host
		{"slack.com", "POST", "/api/chat.postMessage", []string{"slack:post"}, []string{"slack:upload"}},
		{"acme.slack.com", "POST", "/api/files.upload", []string{"slack:upload"}, []string{"slack:post"}},
		{"slack.com", "GET", "/api/chat.postMessage", nil, []string{"slack:post"}}, // reading is not posting
		{"CONTENT.DropboxAPI.com.", "post", "/2/files/upload", []string{"dropbox:upload"}, nil},
		{"pastebin.com", "POST", "/anything", []string{"pastebin:post"}, nil},
		{"pastebin.com", "GET", "/abc", nil, []string{"pastebin:post"}},
		{"chatgpt.com", "POST", "/backend-api/conversation", []string{"chatgpt:post"}, nil},
	}
	for _, tc := range cases {
		got := c.ActionsFor(tc.host, tc.method, tc.path)
		for _, w := range tc.want {
			if !has(got, w) {
				t.Errorf("%s %s %s: %v lacks %s", tc.method, tc.host, tc.path, got, w)
			}
		}
		for _, n := range tc.not {
			if has(got, n) {
				t.Errorf("%s %s %s: %v must not include %s", tc.method, tc.host, tc.path, got, n)
			}
		}
	}
	// look-alike hosts belong to nothing
	for _, h := range []string{"dropbox.com.evil.example", "notdropbox.com", "evilslack.com", "slack.com.attacker.net", "example.com", ""} {
		if apps := c.AppsFor(h); len(apps) != 0 {
			t.Errorf("%q must not belong to an app: %v", h, apps)
		}
		if a := c.ActionsFor(h, "POST", "/api/chat.postMessage"); len(a) != 0 {
			t.Errorf("%q must have no actions: %v", h, a)
		}
	}
	if got := c.AppsFor("www.dropbox.com"); len(got) != 1 || got[0] != "dropbox" {
		t.Errorf("a subdomain belongs to the app: %v", got)
	}
	var nilCatalog *Catalog
	if nilCatalog.AppsFor("dropbox.com") != nil || nilCatalog.ActionsFor("dropbox.com", "POST", "/") != nil {
		t.Error("a missing catalogue recognises nothing")
	}
}

func TestOwnAppsAddAndReplace(t *testing.T) { // AGT-031
	own, err := Validate(App{ID: "Our-Portal", Domains: []string{"Portal.Example.com."}, Actions: map[string][]Rule{
		"upload": {{Methods: []string{"post"}, Paths: []string{"/files"}}}, "post": {{Contains: []string{"/messages"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if own.ID != "our-portal" || own.Domains[0] != "portal.example.com" || own.Name != "our-portal" || own.Actions["upload"][0].Methods[0] != "POST" {
		t.Fatalf("not cleaned: %+v", own)
	}
	// a replacement of a built-in app wins
	repl, _ := Validate(App{ID: "dropbox", Domains: []string{"dropbox.com"}, Actions: map[string][]Rule{"upload": {{Methods: []string{"PUT"}, Paths: []string{"/up"}}}}})
	c := NewCatalog([]App{own, repl})
	if !c.Has("our-portal") || !c.Has("dropbox") || c.Has("nope") {
		t.Fatal("Has")
	}
	if got := c.ActionsFor("portal.example.com", "POST", "/files/new"); !has(got, "our-portal:upload") {
		t.Fatalf("%v", got)
	}
	if got := c.ActionsFor("portal.example.com", "GET", "/x/messages/1"); !has(got, "our-portal:post") {
		t.Fatalf("contains: %v", got)
	}
	if got := c.ActionsFor("content.dropboxapi.com", "POST", "/2/files/upload"); len(got) != 0 {
		t.Fatalf("the built-in dropbox was replaced: %v", got)
	}
	if got := c.ActionsFor("dropbox.com", "PUT", "/up"); !has(got, "dropbox:upload") {
		t.Fatalf("%v", got)
	}
	list := c.List()
	for i := 1; i < len(list); i++ {
		if list[i].ID < list[i-1].ID {
			t.Fatal("the list must be ordered")
		}
	}
}

func TestValidationRefusesBadApps(t *testing.T) { // AGT-031
	ok := App{ID: "x", Domains: []string{"x.example.com"}, Actions: map[string][]Rule{"upload": {{Paths: []string{"/u"}}}}}
	bad := map[string]func(App) App{
		"no id":          func(a App) App { a.ID = ""; return a },
		"bad id":         func(a App) App { a.ID = "Bad_ID!"; return a },
		"no domains":     func(a App) App { a.Domains = nil; return a },
		"url as domain":  func(a App) App { a.Domains = []string{"https://x.example.com/"}; return a },
		"wildcard":       func(a App) App { a.Domains = []string{"*.example.com"}; return a },
		"unknown action": func(a App) App { a.Actions = map[string][]Rule{"explode": {{}}}; return a },
		"empty rules":    func(a App) App { a.Actions = map[string][]Rule{"upload": nil}; return a },
		"host outside": func(a App) App {
			a.Actions = map[string][]Rule{"upload": {{Hosts: []string{"other.example.org"}}}}
			return a
		},
		"bad method":        func(a App) App { a.Actions = map[string][]Rule{"upload": {{Methods: []string{"PO ST"}}}}; return a },
		"path without /":    func(a App) App { a.Actions = map[string][]Rule{"upload": {{Paths: []string{"files"}}}}; return a },
		"path with query":   func(a App) App { a.Actions = map[string][]Rule{"upload": {{Paths: []string{"/f?x=1"}}}}; return a },
		"empty contains":    func(a App) App { a.Actions = map[string][]Rule{"upload": {{Contains: []string{""}}}}; return a },
		"name with newline": func(a App) App { a.Name = "a\nb"; return a },
		"too many domains": func(a App) App {
			a.Domains = nil
			for i := 0; i < 21; i++ {
				a.Domains = append(a.Domains, strings.Repeat("a", i+1)+".example.com")
			}
			return a
		},
	}
	if _, err := Validate(ok); err != nil {
		t.Fatalf("the good app: %v", err)
	}
	for name, mod := range bad {
		a := ok
		a.Domains = append([]string(nil), ok.Domains...)
		if _, err := Validate(mod(a)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
