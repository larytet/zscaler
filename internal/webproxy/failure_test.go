package webproxy

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

func TestWebRequestsFollowTheTenantsFailureModes(t *testing.T) { // AGT-030 (NFR-012)
	r := newRig(t)
	o := newFileOrigin(t, r)
	target := hostport(o.URL)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 3}
	pol.Compile(nil)
	r.st.set(func(s *state) { s.pol = pol })
	var sinkOK atomic.Bool
	sinkOK.Store(true)
	r.proxy.SinkHealthy = sinkOK.Load

	// healthy: through
	if code, _ := r.connectPage(t, target); code != 200 {
		t.Fatalf("healthy: %d", code)
	}

	// stale, safe mode: refused with a page that says why, a reference that is in the log
	r.st.set(func(s *state) { s.stale = true })
	code, page := r.connectPage(t, target)
	if code != 503 || !strings.Contains(page, "not been reachable") {
		t.Fatalf("%d %q", code, page)
	}
	if rec := r.recordWithRef(t, refOf(t, page)); rec.Action != "deny" || rec.Reason != "state-stale" {
		t.Fatalf("%+v", rec)
	}
	// stale, cached: through under the last policy, and the log says so
	r.st.set(func(s *state) { s.onStale = "cached" })
	if code, _ := r.connectPage(t, target); code != 200 {
		t.Fatalf("stale with cached: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "state-stale-cached" && x.Action == "info" }) == nil {
		t.Fatal("going on with stale state must be recorded")
	}
	// the cached policy still decides
	deny := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Deny, Version: 4}
	deny.Compile(nil)
	r.st.set(func(s *state) { s.pol = deny })
	if code, _ := r.connectPage(t, target); code != 403 {
		t.Fatalf("the last policy must still apply: %d", code)
	}
	r.st.set(func(s *state) { s.pol = pol; s.stale = false })

	// log down: refused by default, allowed when the tenant chose that
	sinkOK.Store(false)
	code, page = r.connectPage(t, target)
	if code != 503 || !strings.Contains(page, "log cannot be written") {
		t.Fatalf("%d %q", code, page)
	}
	r.st.set(func(s *state) { s.onLog = "allow" })
	if code, _ := r.connectPage(t, target); code != 200 {
		t.Fatalf("log down with allow: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "log-sink-down-allowed" }) == nil {
		t.Fatal("going on without a log must be recorded")
	}
	// back to normal
	sinkOK.Store(true)
	r.st.set(func(s *state) { s.onLog, s.onStale = "", "" })
	if code, _ := r.connectPage(t, target); code != 200 {
		t.Fatalf("recovery: %d", code)
	}
}
