package cp

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/wcag"
)

// The colours of the console, in the light and the dark setting, keep the contrast the guidelines ask for
// (GAP-REQ-09). Computed from the style sheet itself, so a changed colour fails here.
func TestConsoleColoursKeepTheirContrastInBothThemes(t *testing.T) { // AGT-047
	b, err := os.ReadFile("ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	themes := map[string]map[string]string{}
	re := regexp.MustCompile(`:root \{([^}]*)\}`)
	blocks := re.FindAllStringSubmatch(css, -1)
	if len(blocks) != 2 {
		t.Fatalf("expected a light and a dark :root block, found %d", len(blocks))
	}
	for i, name := range []string{"light", "dark"} {
		vars := map[string]string{}
		for _, m := range regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{3,6})`).FindAllStringSubmatch(blocks[i][1], -1) {
			vars[m[1]] = m[2]
		}
		themes[name] = vars
	}
	for name, v := range themes {
		for _, p := range []struct {
			fg, bg string
			min    float64
			what   string
		}{
			{"fg", "bg", 4.5, "body text"}, {"muted", "bg", 4.5, "secondary text"}, {"bad", "bg", 4.5, "error text"}, {"ok", "bg", 4.5, "success text"}, {"warn", "bg", 4.5, "warning text"},
			{"on-accent", "accent", 4.5, "text on a primary button"}, {"accent", "bg", 3, "the current-screen marker and focus ring"}, {"ctl", "bg", 3, "the border of a field or button"},
		} {
			a, ok1 := v[p.fg]
			bgc, ok2 := v[p.bg]
			if !ok1 || !ok2 {
				t.Errorf("%s: missing --%s or --%s", name, p.fg, p.bg)
				continue
			}
			if c, err := wcag.Contrast(a, bgc); err != nil || c < p.min {
				t.Errorf("%s theme, %s: %s on %s is %.2f, needs %.1f (%v)", name, p.what, a, bgc, c, p.min, err)
			}
		}
	}
}

// The structure that keyboard and screen reader users rely on stays in place (GAP-REQ-09).
func TestConsoleKeepsItsAccessibleStructure(t *testing.T) { // AGT-047
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	html, js, css := read("ui/index.html"), read("ui/app.js"), read("ui/style.css")
	for _, want := range []string{`<html lang="en">`, `name="viewport"`, `class="skip" href="#view"`, `<nav id="tabs" aria-label=`, "<main>", "<h1>"} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	// a field is never left without a name: each textarea gets a label
	for _, line := range strings.Split(js, "\n") {
		if strings.Contains(line, "el('textarea')") && !strings.Contains(line, "aria-label") {
			t.Errorf("a textarea without an accessible name: %s", strings.TrimSpace(line))
		}
	}
	for _, want := range []string{"th.setAttribute('scope', 'col')", "'Actions', 'sr-only'", "setAttribute('role', 'alert')", "h.focus({ preventScroll: true })"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	// no focus outline is removed except on the heading that is focused by program, never by a person
	for _, m := range regexp.MustCompile(`([^{}]+)\{[^}]*outline:\s*none`).FindAllStringSubmatch(css, -1) {
		if strings.TrimSpace(m[1]) != "h2:focus" {
			t.Errorf("focus outline removed on %q", strings.TrimSpace(m[1]))
		}
	}
	if !strings.Contains(css, ":focus-visible") || !strings.Contains(css, ".sr-only") {
		t.Error("visible focus or the screen-reader-only class is gone")
	}
	// a table scrolls in its own box, and that box must contain the hidden text that is positioned absolutely
	if !regexp.MustCompile(`\.scroll\s*\{[^}]*position:\s*relative`).MatchString(css) {
		t.Error(".scroll must be position:relative or the hidden header text widens the whole page on a phone")
	}
}
