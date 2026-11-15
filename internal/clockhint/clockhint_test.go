package clockhint

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSkewIsReadFromTheDateHeader(t *testing.T) { // AGT-045 (GAP-REQ-06)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h := http.Header{}
	h.Set("Date", now.Add(-7*time.Minute).UTC().Format(http.TimeFormat))
	s, ok := Skew(h, now)
	if !ok || s != 7*time.Minute || !Wrong(s) {
		t.Fatalf("%v %v", s, ok)
	}
	if p := Plain(s); !strings.Contains(p, "7 minutes ahead of") || !strings.Contains(p, "network time") {
		t.Errorf("%q", p)
	}
	h.Set("Date", now.Add(3*time.Hour).UTC().Format(http.TimeFormat))
	s, _ = Skew(h, now)
	if p := Plain(s); !strings.Contains(p, "3 hours behind") {
		t.Errorf("%q", p)
	}
	h.Set("Date", now.Add(-72*time.Hour).UTC().Format(http.TimeFormat))
	s, _ = Skew(h, now)
	if p := Plain(s); !strings.Contains(p, "3 days ahead") {
		t.Errorf("%q", p)
	}
	// a few seconds is not a wrong clock; no header or a bad one is unknown, not zero
	h.Set("Date", now.Add(-20*time.Second).UTC().Format(http.TimeFormat))
	if s, _ := Skew(h, now); Wrong(s) {
		t.Errorf("20 seconds called wrong")
	}
	if _, ok := Skew(http.Header{}, now); ok {
		t.Error("no header is unknown")
	}
	h.Set("Date", "yesterday")
	if _, ok := Skew(h, now); ok {
		t.Error("a bad header is unknown")
	}
	for _, d := range []time.Duration{Threshold, -Threshold} {
		if !Wrong(d) {
			t.Errorf("%v at the threshold should be wrong", d)
		}
	}
	if Wrong(Threshold-time.Second) || Wrong(-Threshold+time.Second) {
		t.Error("just inside the threshold is not wrong")
	}
}

func TestACertificateRefusedForItsDatesGetsTheLikelyCause(t *testing.T) { // AGT-045
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	exp := x509.CertificateInvalidError{Reason: x509.Expired}
	for _, err := range []error{exp, fmt.Errorf("Get x: %w", &tls.CertificateVerificationError{Err: exp}), errors.New("x509: certificate has expired or is not yet valid: current time 2030")} {
		w := Wrap(err, now)
		if !strings.Contains(w.Error(), "wrong clock on this computer, which says it is 15 Nov 2026 12:00") || !errors.Is(w, err) && w.Error() == err.Error() {
			t.Errorf("%v -> %v", err, w)
		}
	}
	other := errors.New("connection refused")
	if Wrap(other, now) != other || ExplainTLS(nil, now) != "" {
		t.Error("an unrelated error must be left alone")
	}
	if ExplainTLS(x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, now) != "" {
		t.Error("an unknown authority is not a clock problem")
	}
}

func TestTrackerSeesSkewOnEveryAnswerAndExplainsRealTLSFailures(t *testing.T) { // AGT-045
	// a server whose clock (the Date header) is an hour away from ours
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	}))
	defer srv.Close()
	var tr Tracker
	if _, ok := tr.Current(); ok {
		t.Fatal("known before any answer")
	}
	cl := &http.Client{Transport: tr.Transport(srv.Client().Transport)}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	s, ok := tr.Current()
	if !ok || s < 59*time.Minute || s > 61*time.Minute {
		t.Errorf("%v %v", s, ok)
	}
	// forgotten after a day
	tr.Now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if _, ok := tr.Current(); ok {
		t.Error("a day-old skew is still believed")
	}
	// a real certificate refused for its dates: the client's clock says 2100
	var tr2 Tracker
	tr2.Now = func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) }
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	bad := &http.Client{Transport: tr2.Transport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Time: tr2.Now}})}
	_, err = bad.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "wrong clock on this computer") {
		t.Errorf("a certificate refused for its dates must say why: %v", err)
	}
}
