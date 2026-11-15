package webproxy

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/wcag"
)

// Every page a person sees when the proxy stops them is one accessible shape, whatever the reason (GAP-REQ-09).
func TestEveryStopPageIsAccessible(t *testing.T) { // AGT-047
	hostile := `evil"><script>alert(1)</script>.example`
	render := map[string]func(w *httptest.ResponseRecorder){
		"blocked site": func(w *httptest.ResponseRecorder) {
			blockPage(w, hostile, []string{"malware"}, "ref-1", "category blocked")
		},
		"upload blocked": func(w *httptest.ResponseRecorder) {
			dlpBlockPage(w, hostile, []string{"card"}, "ref-2", "sensitive data")
		},
		"response": func(w *httptest.ResponseRecorder) {
			responseBlockPage(w, hostile, []string{"card"}, "ref-3", "sensitive data")
		},
		"file blocked": func(w *httptest.ResponseRecorder) {
			fileBlockPage(w, hostile, "upload", []string{"exe"}, "ref-4", "program")
		},
		"proxy error": func(w *httptest.ResponseRecorder) {
			errorPage(w, 502, "Could not reach the site", "it did not answer", "ref-5")
		},
	}
	for name, f := range render {
		w := httptest.NewRecorder()
		f(w)
		body := w.Body.String()
		for _, want := range []string{`<!doctype html>`, `<html lang="en">`, `<meta charset="utf-8">`, `<meta name="viewport" content="width=device-width, initial-scale=1">`, `<title>`, `<main>`, `</main>`, "ref-"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %s", name, want)
			}
		}
		if n := strings.Count(body, "<h1>"); n != 1 {
			t.Errorf("%s: %d headings of level one", name, n)
		}
		if strings.Contains(body, "<script") || strings.Contains(body, `evil"`) {
			t.Errorf("%s: the host name was not escaped: %s", name, body)
		}
		if strings.Contains(body, "font-size:1") && !strings.Contains(body, "rem") {
			t.Errorf("%s: a fixed font size", name)
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: content type %q", name, w.Header().Get("Content-Type"))
		}
	}
	// the colours, in the light and the dark setting
	css := pageStyle
	get := func(re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("no match for %s in %s", re, css)
		}
		return m[1]
	}
	lightFG, lightBG, lightLink := get(`body\{[^}]*;color:(#[0-9a-f]{6});background:#fff`), "#ffffff", get(`a\{color:(#[0-9a-f]{6})\}@media`)
	darkFG, darkBG, darkLink := get(`@media[^{]*\{body\{color:(#[0-9a-f]{6});`), get(`@media[^{]*\{body\{color:#[0-9a-f]{6};background:(#[0-9a-f]{6})\}`), get(`a\{color:(#[0-9a-f]{6})\}\}`)
	for _, c := range []struct{ fg, bg, what string }{{lightFG, lightBG, "light text"}, {lightLink, lightBG, "light link"}, {darkFG, darkBG, "dark text"}, {darkLink, darkBG, "dark link"}} {
		if r, err := wcag.Contrast(c.fg, c.bg); err != nil || r < 4.5 {
			t.Errorf("%s: %s on %s is %.2f, needs 4.5 (%v)", c.what, c.fg, c.bg, r, err)
		}
	}
}
