package cp

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestConsoleIsServedWithStrictHeaders(t *testing.T) {
	e := newEnv(t)
	for path, want := range map[string]string{"/": "SMB-ZTX console", "/ui/app.js": "use strict", "/ui/style.css": "--accent"} {
		resp, err := http.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		for _, must := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, must) {
				t.Errorf("%s: CSP lacks %q: %s", path, must, csp)
			}
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing hardening headers", path)
		}
	}
	// the page holds no inline script or style (the CSP would block them) and no secrets
	resp, _ := http.Get(e.srv.URL + "/")
	b, _ := io.ReadAll(resp.Body)
	page := strings.ToLower(string(b))
	if strings.Contains(page, "<script>") || strings.Contains(page, "onclick=") || strings.Contains(page, "style=") {
		t.Error("inline script or style in index.html")
	}
	if resp, _ := http.Get(e.srv.URL + "/ui/../store.json"); resp != nil && resp.StatusCode == 200 {
		t.Error("path traversal served a file")
	}
	// the API still demands a token
	if resp, _ := http.Get(e.srv.URL + "/v1/segments"); resp.StatusCode != 401 {
		t.Errorf("api without token: %d", resp.StatusCode)
	}
}

// Data in the console comes from users and hostnames, so the script must never
// turn it into HTML. This check fails if anyone adds an HTML-parsing sink.
func TestConsoleScriptHasNoHTMLSinks(t *testing.T) {
	b, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "createContextualFragment", "srcdoc", ".href =", "location ="} {
		if strings.Contains(js, sink) {
			t.Errorf("app.js uses %q", sink)
		}
	}
}

func TestConsoleScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	if out, err := exec.Command(node, "--check", "ui/app.js").CombinedOutput(); err != nil {
		t.Fatalf("syntax error: %v\n%s", err, out)
	}
}
