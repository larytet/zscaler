package cp

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/siem"
	"github.com/larytet/zscaler/internal/store"
)

type sink struct {
	srv    *httptest.Server
	mu     sync.Mutex
	events []map[string]any
	auth   map[string]bool
}

func newSink(t *testing.T) *sink {
	s := &sink{auth: map[string]bool{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		sc := bufio.NewScanner(q.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.auth[q.Header.Get("Authorization")] = true
		for sc.Scan() {
			var e map[string]any
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				s.events = append(s.events, e)
			}
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sink) ca() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}))
}

func (s *sink) types() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]int{}
	for _, e := range s.events {
		m[e["type"].(string)]++
	}
	return m
}

func (s *sink) has(f func(map[string]any) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if f(e) {
			return true
		}
	}
	return false
}

func until(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 250; i++ {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestLogStreamingEndToEnd(t *testing.T) { // AGT-023 (INT-004, ADM-006a)
	e := newEnrolEnv(t)
	rcv := newSink(t)
	// without a streamer the feature says so instead of pretending
	if c, _, _ := e.call("PUT", "/v1/siem", e.adminA, map[string]any{"kind": "https", "url": rcv.srv.URL}); c != 503 {
		t.Fatalf("no streamer: %d", c)
	}
	e.api.SIEM = &siem.Streamer{AllowLoopback: true, Backoff: 20 * time.Millisecond}
	t.Cleanup(func() { e.api.SIEM.Configure("a", nil); e.api.SIEM.Configure("b", nil) })

	put := map[string]any{"kind": "https", "url": rcv.srv.URL + "/ingest", "token": "Bearer TOKEN-xyz-77", "ca_pem": rcv.ca()}
	c, b, _ := e.call("PUT", "/v1/siem", e.adminA, put)
	if c != 200 || strings.Contains(string(b), "TOKEN-xyz-77") || !strings.Contains(string(b), `"has_token":true`) || strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatalf("%d %s", c, b)
	}
	if c, b, _ = e.call("GET", "/v1/siem", e.adminA, nil); c != 200 || strings.Contains(string(b), "TOKEN-xyz-77") || !strings.Contains(string(b), `"stats"`) || !strings.Contains(string(b), `"decisions":true`) {
		t.Fatalf("%d %s", c, b)
	}
	if c, b, _ = e.call("POST", "/v1/siem/test", e.adminA, nil); c != 200 || !strings.Contains(string(b), `"delivered":true`) {
		t.Fatalf("%d %s", c, b)
	}
	until(t, "the test event", func() bool { return rcv.types()["test"] == 1 })

	// decisions go through the real ingest path; captures, health reports and other tenants' records do not come
	now := time.Now()
	recs := []broker.Record{
		{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "u2", App: "erp", Rule: "r1", TS: now},
		{Tenant: "a", Kind: "web", Action: "allow", Event: "open", User: "u1", Target: "x.example:443", TS: now},
		{Tenant: "a", Kind: "capture", Action: "info", Event: "open", User: "u1", TS: now, Capture: &broker.Capture{Rule: "watch", Method: "GET", Host: "x.example", ReqBody: "c2VjcmV0LWJvZHk="}},
		{Tenant: "a", Kind: "health", Action: "info", User: "u1", TS: now},
		{Tenant: "b", Kind: "private", Action: "deny", Event: "open", User: "other-tenant-user", TS: now},
	}
	if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
		t.Fatalf("ingest %d", c)
	}
	until(t, "two decisions", func() bool { return rcv.types()["decision"] == 2 })
	time.Sleep(200 * time.Millisecond)
	if n := rcv.types()["decision"]; n != 2 {
		t.Fatalf("expected exactly the two decisions of tenant a, got %d", n)
	}
	if rcv.has(func(m map[string]any) bool { return m["user"] == "other-tenant-user" }) {
		t.Fatal("another tenant's record was streamed")
	}
	if rcv.has(func(m map[string]any) bool {
		return strings.Contains(toJSON(m), "c2VjcmV0") || m["capture"] != nil || m["kind"] == "capture"
	}) {
		t.Fatal("a capture was streamed")
	}
	if !rcv.has(func(m map[string]any) bool {
		return m["schema"] == siem.Schema && m["rule"] == "r1" && m["action"] == "deny"
	}) {
		t.Fatalf("the denial with its rule is missing: %v", rcv.events)
	}

	// admin actions are streamed as audit events, and the sink's own change is among them, without the token
	e.call("PUT", "/v1/policies/web", e.adminA, map[string]any{"default_action": "allow", "rules": []any{}}, "If-Match", "0")
	until(t, "the audit events", func() bool {
		return rcv.has(func(m map[string]any) bool { return m["type"] == "audit" && m["action"] == "policy.put" })
	})
	if rcv.has(func(m map[string]any) bool { return strings.Contains(toJSON(m), "TOKEN-xyz-77") }) {
		t.Fatal("the token was streamed")
	}
	if _, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil); strings.Contains(string(ab), "TOKEN-xyz-77") || !strings.Contains(string(ab), "siem.put") {
		t.Fatalf("the audit log must record the change but not the token: %s", ab)
	}

	// an update that does not mention the token keeps it
	e.call("PUT", "/v1/siem", e.adminA, map[string]any{"kind": "https", "url": rcv.srv.URL + "/ingest"})
	if _, err := e.api.Store.SIEM("a"), error(nil); err != nil || e.api.Store.SIEM("a").Token != "Bearer TOKEN-xyz-77" {
		t.Fatal("the token was lost on update")
	}

	// roles: only admin and owner; and bad input
	for _, role := range []store.Role{store.Viewer, store.Helpdesk, store.Auditor} {
		tok, _ := e.api.Store.AddAdmin("a", "r-"+string(role), role)
		for _, m := range []string{"GET", "PUT", "DELETE"} {
			if c, _, _ := e.call(m, "/v1/siem", tok, put); c != 403 {
				t.Errorf("%s may %s the log sink: %d", role, m, c)
			}
		}
		if c, _, _ := e.call("POST", "/v1/siem/test", tok, nil); c != 403 {
			t.Errorf("%s may test the log sink: %d", role, c)
		}
	}
	for name, body := range map[string]map[string]any{
		"metadata address": {"kind": "https", "url": "https://169.254.169.254/x"},
		"no kind":          {"url": "https://siem.example.com"},
		"syslog bad proto": {"kind": "syslog", "addr": "siem.example.com:514", "proto": "icmp"},
		"nothing to send":  {"kind": "https", "url": "https://siem.example.com", "decisions": false, "audit": false},
		"unknown field":    {"kind": "https", "url": "https://siem.example.com", "bogus": 1},
	} {
		if c, _, _ := e.call("PUT", "/v1/siem", e.adminA, body); c != 400 {
			t.Errorf("%s accepted: %d", name, c)
		}
	}

	// tenant isolation, and removal
	if c, b, _ := e.call("GET", "/v1/siem", e.adminB, nil); c != 200 || !strings.Contains(string(b), `"configured":false`) {
		t.Fatalf("tenant b sees a sink: %d %s", c, b)
	}
	e.call("DELETE", "/v1/siem", e.adminB, nil)
	if e.api.Store.SIEM("a") == nil {
		t.Fatal("another tenant removed the sink")
	}
	if c, _, _ := e.call("DELETE", "/v1/siem", e.adminA, nil); c != 200 {
		t.Fatal(c)
	}
	time.Sleep(300 * time.Millisecond) // let anything already in flight settle
	e.post("/ingest/records", []broker.Record{{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: "late", TS: time.Now()}}, enCert(t, e))
	time.Sleep(400 * time.Millisecond)
	if rcv.has(func(m map[string]any) bool { return m["user"] == "late" }) {
		t.Fatal("a record was streamed after the sink was removed")
	}
	if c, b, _ := e.call("GET", "/v1/siem", e.adminA, nil); !strings.Contains(string(b), `"configured":false`) {
		t.Fatalf("%d %s", c, b)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestLogSinkSurvivesARestart(t *testing.T) { // AGT-023
	p := t.TempDir() + "/s.json"
	s, _ := store.Open(p)
	s.CreateTenant("a", "A")
	cfg := siem.Config{Kind: "syslog", Addr: "10.0.0.5:514", Proto: "tcp", Decisions: true, Audit: true}
	if err := s.SetSIEM("a", &cfg); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.SIEMConfigs()["a"]; got.Addr != "10.0.0.5:514" || got.Kind != "syslog" {
		t.Fatalf("%+v", got)
	}
}
