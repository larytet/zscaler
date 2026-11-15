package ratelimit

import (
	"net/http/httptest"
	"testing"
	"time"
)

func lim(now *time.Time) *Limiter {
	l := New()
	l.Now = func() time.Time { return *now }
	return l
}

func TestLockoutAfterTooManyFailuresAndItDoubles(t *testing.T) { // AGT-044 (GAP-REQ-04)
	now := time.Now()
	l := lim(&now)
	var calls []string
	l.OnLock = func(scope, ip string, until time.Time, n int) { calls = append(calls, scope+"|"+ip) }
	for i := 0; i < 9; i++ {
		if l.Fail("admin", "1.2.3.4") {
			t.Fatalf("locked after only %d failures", i+1)
		}
		now = now.Add(time.Second)
	}
	if b, _ := l.Blocked("admin", "1.2.3.4"); b {
		t.Fatal("blocked before the limit")
	}
	if !l.Fail("admin", "1.2.3.4") {
		t.Fatal("the tenth failure in a minute must lock")
	}
	b, left := l.Blocked("admin", "1.2.3.4")
	if !b || left < 4*time.Minute || left > 5*time.Minute {
		t.Fatalf("%v %v", b, left)
	}
	if len(calls) != 1 || calls[0] != "admin|1.2.3.4" {
		t.Errorf("OnLock called %v", calls)
	}
	// other scopes and other addresses are not affected
	if b, _ := l.Blocked("enrol", "1.2.3.4"); b {
		t.Error("another scope was blocked")
	}
	if b, _ := l.Blocked("admin", "5.6.7.8"); b {
		t.Error("another address was blocked")
	}
	// more failures while locked do not extend or repeat the lockout
	l.Fail("admin", "1.2.3.4")
	if len(calls) != 1 {
		t.Errorf("a second lockout began inside the first: %v", calls)
	}
	// it ends
	now = now.Add(5*time.Minute + time.Second)
	if b, _ := l.Blocked("admin", "1.2.3.4"); b {
		t.Error("still blocked after the lock time")
	}
	// the next lockout is twice as long
	for i := 0; i < 10; i++ {
		l.Fail("admin", "1.2.3.4")
	}
	if _, left := l.Blocked("admin", "1.2.3.4"); left < 9*time.Minute || left > 10*time.Minute {
		t.Errorf("the second lockout should last 10 minutes: %v", left)
	}
	// the doubling stops at the ceiling
	for r := 0; r < 8; r++ {
		now = now.Add(2 * time.Hour)
		for i := 0; i < 10; i++ {
			l.Fail("admin", "1.2.3.4")
		}
	}
	if _, left := l.Blocked("admin", "1.2.3.4"); left > time.Hour {
		t.Errorf("above the ceiling: %v", left)
	}
	// a long quiet spell forgives
	now = now.Add(48 * time.Hour)
	for i := 0; i < 10; i++ {
		l.Fail("admin", "1.2.3.4")
	}
	if _, left := l.Blocked("admin", "1.2.3.4"); left > 5*time.Minute {
		t.Errorf("after a quiet spell the first lockout length applies again: %v", left)
	}
}

func TestSlowFailuresDoNotLockAndExemptNetworksAreNeverLimited(t *testing.T) { // AGT-044
	now := time.Now()
	l := lim(&now)
	for i := 0; i < 100; i++ { // one a minute: never ten in a minute
		l.Fail("admin", "1.1.1.1")
		now = now.Add(61 * time.Second)
	}
	if b, _ := l.Blocked("admin", "1.1.1.1"); b {
		t.Error("slow failures locked an address")
	}
	ex, err := ParseExempt("10.0.0.0/8, 192.168.1.5 ,::1")
	if err != nil || len(ex) != 3 {
		t.Fatalf("%v %v", ex, err)
	}
	l.Exempt = ex
	for _, ip := range []string{"10.20.30.40", "192.168.1.5", "::1"} {
		for i := 0; i < 50; i++ {
			l.Fail("admin", ip)
		}
		if b, _ := l.Blocked("admin", ip); b {
			t.Errorf("%s is exempt and was blocked", ip)
		}
	}
	for i := 0; i < 20; i++ {
		l.Fail("admin", "192.168.1.6")
	}
	if b, _ := l.Blocked("admin", "192.168.1.6"); !b {
		t.Error("a neighbour of an exempt address must not be exempt")
	}
	if _, err := ParseExempt("not-an-address"); err == nil {
		t.Error("garbage accepted")
	}
	// disabled and nil limiters never block
	off := &Limiter{}
	for i := 0; i < 50; i++ {
		off.Fail("a", "x")
	}
	if b, _ := off.Blocked("a", "x"); b {
		t.Error("a disabled limiter blocked")
	}
	var nilL *Limiter
	nilL.Fail("a", "x")
	if b, _ := nilL.Blocked("a", "x"); b || nilL.Recent(time.Hour) != 0 {
		t.Error("a nil limiter blocked")
	}
}

func TestRecentCountsLockoutsAndMemoryIsBounded(t *testing.T) { // AGT-044
	now := time.Now()
	l := lim(&now)
	for _, ip := range []string{"a", "b", "c"} {
		for i := 0; i < 10; i++ {
			l.Fail("admin", ip)
		}
	}
	if n := l.Recent(time.Hour); n != 3 {
		t.Errorf("%d", n)
	}
	now = now.Add(2 * time.Hour)
	if n := l.Recent(time.Hour); n != 0 {
		t.Errorf("old lockouts counted: %d", n)
	}
	// a flood of one-off addresses cannot grow the table without limit
	l2 := lim(&now)
	for i := 0; i < maxEntries+5000; i++ {
		l2.Fail("admin", "ip-"+time.Duration(i).String())
	}
	l2.mu.Lock()
	n := len(l2.entries)
	l2.mu.Unlock()
	if n > maxEntries {
		t.Errorf("%d entries", n)
	}
}

func TestClientIPIgnoresForwardingHeaders(t *testing.T) { // AGT-044
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if ClientIP(r) != "203.0.113.9" {
		t.Errorf("%s", ClientIP(r))
	}
	r.RemoteAddr = "[2001:db8::1]:80"
	if ClientIP(r) != "2001:db8::1" {
		t.Errorf("%s", ClientIP(r))
	}
}
