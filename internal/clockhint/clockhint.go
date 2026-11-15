// Package clockhint notices a wrong clock and says so in plain words (GAP-REQ-06). Certificates, short-lived
// tokens, approvals, time-of-day rules and the freshness of signed state all depend on the clock, and the
// usual symptom of a wrong one is an opaque TLS or "stale state" error. Each program compares its clock with
// the Date header of the control plane's answers and, when a certificate is refused for its dates, adds the
// likely cause to the message.
package clockhint

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Threshold is the difference from which a clock is called wrong. Certificates are issued with a
// two-minute allowance for skew, so beyond this things start to fail.
const Threshold = 2 * time.Minute

// Skew is how far local is ahead of the server (negative: behind), read from the Date header of an
// answer. ok is false when there is no usable header. The header has one-second resolution and the
// answer took some time to arrive, so differences of a few seconds mean nothing.
func Skew(h http.Header, local time.Time) (skew time.Duration, ok bool) {
	d := h.Get("Date")
	if d == "" {
		return 0, false
	}
	t, err := http.ParseTime(d)
	if err != nil {
		return 0, false
	}
	return local.Sub(t), true
}

// Wrong reports whether a skew is large enough to matter.
func Wrong(skew time.Duration) bool { return skew >= Threshold || skew <= -Threshold }

// Plain describes a skew in a sentence a person can act on.
func Plain(skew time.Duration) string {
	d := skew
	dir := "ahead of"
	if d < 0 {
		d, dir = -d, "behind"
	}
	return fmt.Sprintf("This computer's clock is about %s %s the control plane's. Set the date, time and time zone to update automatically (network time), then try again: certificates, approvals and time-based rules depend on it.", span(d), dir)
}

// Span writes a length of time the way Plain does ("7 minutes", "3 hours", "2 days").
func Span(d time.Duration) string { return span(d) }

func span(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		n := int(d.Minutes())
		if n <= 1 {
			return "a minute"
		}
		return fmt.Sprintf("%d minutes", n)
	}
}

// ExplainTLS returns a sentence when err is a certificate refused for its dates, which a wrong clock
// causes, and "" for any other error.
func ExplainTLS(err error, local time.Time) string {
	if err == nil {
		return ""
	}
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) && inv.Reason == x509.Expired {
		return fmt.Sprintf("A certificate was refused because of its dates. The usual cause is a wrong clock on this computer, which says it is %s. Check the date, time and time zone, then try again.", local.Format("2 Jan 2006 15:04 MST"))
	}
	if strings.Contains(err.Error(), "certificate has expired or is not yet valid") {
		return fmt.Sprintf("A certificate was refused because of its dates. The usual cause is a wrong clock on this computer, which says it is %s. Check the date, time and time zone, then try again.", local.Format("2 Jan 2006 15:04 MST"))
	}
	return ""
}

// Wrap adds the likely cause to a certificate-dates error and leaves any other error as it is.
func Wrap(err error, local time.Time) error {
	if s := ExplainTLS(err, local); s != "" {
		return fmt.Errorf("%w\n%s", err, s)
	}
	return err
}

// Tracker remembers the latest skew seen on any answer, and turns itself into an http.RoundTripper wrapper.
// The zero value is ready to use.
type Tracker struct {
	mu   sync.Mutex
	skew time.Duration
	seen time.Time
	Now  func() time.Time // tests
}

func (t *Tracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Note records the skew in an answer's headers.
func (t *Tracker) Note(h http.Header) {
	if s, ok := Skew(h, t.now()); ok {
		t.mu.Lock()
		t.skew, t.seen = s, t.now()
		t.mu.Unlock()
	}
}

// Current returns the latest skew and whether it is known and not older than a day.
func (t *Tracker) Current() (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen.IsZero() || t.now().Sub(t.seen) > 24*time.Hour {
		return 0, false
	}
	return t.skew, true
}

type roundTripper struct {
	t    *Tracker
	next http.RoundTripper
}

func (r roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return resp, Wrap(err, r.t.now())
	}
	r.t.Note(resp.Header)
	return resp, nil
}

// Transport wraps next so that every answer updates the tracker and a dates-related certificate error
// carries the explanation.
func (t *Tracker) Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return roundTripper{t, next}
}
