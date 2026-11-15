package cp

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/store"
)

// The console shows the screens a role can use, from what the server says about the role (ADM-001, ADM-002).
func TestMeTellsTheConsoleWhatTheRoleMayDo(t *testing.T) { // AGT-038
	e := newEnrolEnv(t)
	want := map[store.Role][]string{
		store.Owner:    {"read", "logs", "audit", "support", "write", "sensitive", "admins"},
		store.Admin:    {"read", "logs", "audit", "support", "write", "sensitive"},
		store.Helpdesk: {"read", "logs", "support"},
		store.Auditor:  {"read", "logs", "audit"},
		store.Viewer:   {"read"},
	}
	for role, perms := range want {
		tok := e.adminA
		if role != store.Owner {
			var err error
			if tok, err = e.api.Store.AddAdmin("a", "me-"+string(role), role); err != nil {
				t.Fatal(err)
			}
		}
		code, body, _ := e.call("GET", "/v1/me", tok, nil)
		var got struct {
			Name        string   `json:"name"`
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		}
		if code != 200 || json.Unmarshal(body, &got) != nil {
			t.Fatalf("%s: %d %s", role, code, body)
		}
		if got.Role != string(role) || got.Name == "" || !reflect.DeepEqual(got.Permissions, perms) {
			t.Errorf("%s: %+v, want permissions %v", role, got, perms)
		}
	}
	if code, _, _ := e.call("GET", "/v1/me", "", nil); code != 401 {
		t.Errorf("without a token: %d", code)
	}
}

// The screen logic (simple and advanced mode, roles, who can reach each app in words) runs under Node.
func TestConsoleModesLogic(t *testing.T) { // AGT-038
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	if out, err := exec.Command(node, "uitest/modes.test.js").CombinedOutput(); err != nil || !strings.Contains(string(out), "modes: ok") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// The permission each screen asks for must be one the server has, and the logic file must not touch the page.
func TestModesFileIsPureLogic(t *testing.T) {
	b, err := os.ReadFile("ui/modes.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"document.", "window.", "innerHTML", "fetch(", "localStorage", "eval("} {
		if strings.Contains(string(b), bad) {
			t.Errorf("modes.js uses %q", bad)
		}
	}
}
