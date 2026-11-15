package versions

import "testing"

func TestParse(t *testing.T) { // AGT-046 (GAP-REQ-08)
	for in, want := range map[string]Ver{"1.2.3": {1, 2, 3}, "v1.2.3": {1, 2, 3}, "0.1.0-dev": {0, 1, 0}, "2.10": {2, 10, 0}, "1.2.3+abc": {1, 2, 3}, " v3.4.5-rc1 ": {3, 4, 5}} {
		if got, ok := Parse(in); !ok || got != want {
			t.Errorf("%q: %v %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "dev", "1", "a.b.c", "1.2.3.4", "1..3", "-1.2.3", "1.2.x", "v", "99999999999.1.1"} {
		if _, ok := Parse(in); ok {
			t.Errorf("%q parsed", in)
		}
	}
}

func TestOneMinorBehindIsTheSupportedWindow(t *testing.T) { // AGT-046
	for _, c := range []struct{ cp, comp, want string }{
		{"1.5.0", "1.5.0", Current}, {"1.5.2", "1.5.9", Current}, {"v1.5.0", "1.5.0-dev", Current},
		{"1.5.0", "1.4.9", Behind},
		{"1.5.0", "1.3.0", TooOld}, {"1.5.0", "1.0.0", TooOld}, {"2.0.0", "1.9.0", TooOld},
		{"1.5.0", "1.6.0", Newer}, {"1.5.0", "2.0.0", Newer}, {"1.5.0", "1.5.1", Current},
		{"1.5.0", "dev", Unknown}, {"1.5.0", "", Unknown}, {"dev", "1.5.0", Unknown},
		{"1.0.0", "1.0.0", Current},
	} {
		if got, msg := Classify(c.cp, c.comp); got != c.want || (got != Current && msg == "") {
			t.Errorf("cp %q component %q: %q (%q), want %q with a message", c.cp, c.comp, got, msg, c.want)
		}
	}
	if _, m := Classify("1.5.0", "1.5.0"); m != "" {
		t.Errorf("a current component needs no message: %q", m)
	}
}
