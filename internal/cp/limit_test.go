package cp

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/ratelimit"
)

func limiterAt(now *time.Time) *ratelimit.Limiter {
	l := ratelimit.New()
	l.Now = func() time.Time { return *now }
	return l
}

// A client that keeps presenting bad credentials is locked out for a while; the scopes are separate (GAP-REQ-04).
func TestBadCredentialsLockTheAddressOutForAWhile(t *testing.T) { // AGT-044
	e := newEnrolEnv(t)
	now := time.Now()
	e.api.Limit = limiterAt(&now)
	var logged []string
	e.api.Limit.OnLock = func(scope, ip string, until time.Time, n int) { logged = append(logged, scope+"|"+ip) }

	// requests with no token at all are not failed sign-ins: a monitor or a browser tab must not lock itself out
	for i := 0; i < 40; i++ {
		if c, _, _ := e.call("GET", "/v1/segments", "", nil); c != 401 {
			t.Fatalf("no token: %d", c)
		}
	}
	// nine bad tokens: refused, not yet locked, and a good token works in between
	for i := 0; i < 9; i++ {
		if c, _, _ := e.call("GET", "/v1/segments", "bad-"+strconv.Itoa(i), nil); c != 401 {
			t.Fatalf("bad token %d: %d", i, c)
		}
	}
	if c, _, _ := e.call("GET", "/v1/segments", e.adminA, nil); c != 200 {
		t.Fatalf("a good token before the limit: %d", c)
	}
	// the tenth bad token is still a 401 and starts the lockout; from then on this address gets 429
	if c, _, _ := e.call("GET", "/v1/segments", "bad-9", nil); c != 401 {
		t.Fatalf("the tenth: %d", c)
	}
	c, body, hdr := e.call("GET", "/v1/segments", "bad-10", nil)
	if c != 429 {
		t.Fatalf("locked out: %d %s", c, body)
	}
	secs, err := strconv.Atoi(hdr.Get("Retry-After"))
	if err != nil || secs < 250 || secs > 301 {
		t.Errorf("Retry-After %q", hdr.Get("Retry-After"))
	}
	var m map[string]string
	json.Unmarshal(body, &m)
	if m["code"] != "too_many_failures" {
		t.Errorf("%s", body)
	}
	// a lockout is a lockout: even the right token is refused from this address until it ends
	if c, _, _ := e.call("GET", "/v1/segments", e.adminA, nil); c != 429 {
		t.Errorf("the right token during a lockout: %d", c)
	}
	if len(logged) != 1 {
		t.Errorf("the lockout must be reported once: %v", logged)
	}
	// it ends by itself
	now = now.Add(5*time.Minute + 2*time.Second)
	if c, _, _ := e.call("GET", "/v1/segments", e.adminA, nil); c != 200 {
		t.Errorf("after the lockout: %d", c)
	}
	// a lockout is counted on the key page (a number, no address)
	_, kb, _ := e.call("GET", "/v1/keys", e.adminA, nil)
	var k map[string]any
	json.Unmarshal(kb, &k)
	if k["lockouts_last_24_hours"] != float64(1) {
		t.Errorf("keys: %v", k["lockouts_last_24_hours"])
	}
	if s := string(kb); len(logged) > 0 && containsAny(s, "127.0.0.1") {
		t.Errorf("an address is shown to every administrator: %s", s)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

func TestScopesAreSeparateAndTrustedNetworksAreExempt(t *testing.T) { // AGT-044
	e := newEnrolEnv(t)
	now := time.Now()
	e.api.Limit = limiterAt(&now)
	// the bootstrap token: ten bad ones lock the bootstrap scope only
	for i := 0; i < 10; i++ {
		e.call("POST", "/v1/tenants", "wrong", map[string]string{"id": "x", "name": "x"})
	}
	if c, _, _ := e.call("POST", "/v1/tenants", "wrong", map[string]string{"id": "x", "name": "x"}); c != 429 {
		t.Errorf("bootstrap: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/ens/tokens", "boot", map[string]any{"names": []string{"en1"}}); c != 429 {
		t.Errorf("a locked-out address must not use the bootstrap token either: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/segments", e.adminA, nil); c != 200 {
		t.Errorf("a bootstrap lockout must not block the admin API: %d", c)
	}
	// enrolment: ten junk connector tokens lock the enrolment scope only
	_, pub := newKey(t)
	for i := 0; i < 10; i++ {
		e.post("/enrol/connector", map[string]string{"token": "junk", "name": "c", "public_key": pub}, nil)
	}
	if c, _ := e.post("/enrol/connector", map[string]string{"token": "junk", "name": "c", "public_key": pub}, nil); c != 429 {
		t.Errorf("enrolment: %d", c)
	}
	if c, _ := e.post("/enrol/device", map[string]string{"tenant": "a", "id_token": "junk"}, nil); c != 429 {
		t.Errorf("every enrolment endpoint shares the scope: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/segments", e.adminA, nil); c != 200 {
		t.Errorf("an enrolment lockout must not block the admin API: %d", c)
	}
	// a trusted network is never limited (the test client connects from 127.0.0.1)
	e2 := newEnrolEnv(t)
	now2 := time.Now()
	e2.api.Limit = limiterAt(&now2)
	e2.api.Limit.Exempt, _ = ratelimit.ParseExempt("127.0.0.0/8")
	for i := 0; i < 60; i++ {
		if c, _, _ := e2.call("GET", "/v1/segments", "bad", nil); c != 401 {
			t.Fatalf("an exempt address was limited at attempt %d: %d", i, c)
		}
	}
	// no limiter at all (as in every other test) changes nothing
	e3 := newEnrolEnv(t)
	for i := 0; i < 30; i++ {
		if c, _, _ := e3.call("GET", "/v1/segments", "bad", nil); c != 401 {
			t.Fatalf("with no limiter: %d", c)
		}
	}
}
