package wcag

import (
	"math"
	"testing"
)

func TestContrastMatchesTheKnownValues(t *testing.T) { // AGT-047
	for _, c := range []struct {
		a, b string
		want float64
	}{{"#000", "#fff", 21}, {"#fff", "#fff", 1}, {"#767676", "#ffffff", 4.54}, {"#777", "#fff", 4.48}} {
		got, err := Contrast(c.a, c.b)
		if err != nil || math.Abs(got-c.want) > 0.02 {
			t.Errorf("%s on %s: %.2f, want %.2f (%v)", c.a, c.b, got, c.want, err)
		}
		if back, _ := Contrast(c.b, c.a); back != got {
			t.Errorf("not symmetric")
		}
	}
	for _, bad := range []string{"", "red", "#12", "#gggggg", "#1234567"} {
		if _, err := Contrast(bad, "#fff"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
