// Package wcag computes the contrast ratio the Web Content Accessibility Guidelines use, so a test can fail
// when a colour in the console or a block page stops being readable (GAP-REQ-09).
package wcag

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func lin(c float64) float64 {
	c /= 255
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// Luminance of a colour written #rgb or #rrggbb.
func Luminance(hex string) (float64, error) {
	h := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return 0, fmt.Errorf("not a colour: %q", hex)
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("not a colour: %q", hex)
	}
	return 0.2126*lin(float64(v>>16&255)) + 0.7152*lin(float64(v>>8&255)) + 0.0722*lin(float64(v&255)), nil
}

// Contrast is the ratio between two colours, from 1 to 21. Text needs 4.5 (AA), large text and the edges of
// controls need 3.
func Contrast(a, b string) (float64, error) {
	la, err := Luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := Luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}
