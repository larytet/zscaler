package cp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/evidence"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

type env struct {
	t         *testing.T
	srv       *httptest.Server
	api       *API
	adminA    string
	adminB    string
	auditPath string
}

func newEnv(t *testing.T) *env {
	st, _ := store.Open("")
	ap := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := audit.Open(ap, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	api := &API{Store: st, Audit: al, AuditPath: ap, Tokens: pki.NewTokens(nil, time.Hour), BootstrapToken: "boot"}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, api: api, auditPath: ap}
	e.adminA = e.createTenant("a")
	e.adminB = e.createTenant("b")
	return e
}

func (e *env) call(method, path, token string, body any, hdr ...string) (int, []byte, http.Header) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (e *env) createTenant(id string) string {
	code, b, _ := e.call("POST", "/v1/tenants", "boot", map[string]string{"id": id, "name": id})
	if code != 201 {
		e.t.Fatalf("create tenant: %d %s", code, b)
	}
	var out map[string]string
	json.Unmarshal(b, &out)
	return out["admin_token"]
}

func TestOnboardingFlow(t *testing.T) { // CP-001, SMB-001
	e := newEnv(t)
	if c, b, _ := e.call("PUT", "/v1/idp", e.adminA, map[string]string{"issuer": "https://idp.example", "client_id": "cid"}); c != 200 {
		t.Fatalf("idp %d %s", c, b)
	}
	if c, b, _ := e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": "10.0.0.5", "ports": []int{5432}}}}); c != 200 {
		t.Fatalf("segment %d %s", c, b)
	}
	c, b, _ := e.call("POST", "/v1/policies/safe-defaults", e.adminA, nil)
	if c != 200 {
		t.Fatalf("safe defaults %d %s", c, b)
	}
	if c, b, _ := e.call("POST", "/v1/connectors/tokens", e.adminA, map[string]string{"group": "site1"}); c != 200 || !strings.Contains(string(b), "token") {
		t.Fatalf("token %d %s", c, b)
	}
	c, b, h := e.call("GET", "/v1/policies/private", e.adminA, nil)
	if c != 200 || h.Get("ETag") != "1" {
		t.Fatalf("get policy %d etag %q %s", c, h.Get("ETag"), b)
	}
	// audit has the steps, chain valid, and no token material
	c, b, _ = e.call("GET", "/v1/audit", e.adminA, nil)
	var ev []audit.Event
	json.Unmarshal(b, &ev)
	if c != 200 || len(ev) < 5 {
		t.Fatalf("audit %d %d events", c, len(ev))
	}
	if n, err := audit.Verify(e.auditPath); err != nil || n < 5 {
		t.Fatalf("chain %d %v", n, err)
	}
	if raw, _ := io.ReadAll(mustOpen(t, e.auditPath)); strings.Contains(string(raw), e.adminA) {
		t.Fatal("admin token leaked into audit log")
	}
}

func mustOpen(t *testing.T, p string) io.Reader {
	b, err := readFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func TestInvalidPolicyRejected(t *testing.T) { // CP-002
	e := newEnv(t)
	bad := map[string]any{"default_action": "allow", "rules": []any{}}
	c, b, _ := e.call("PUT", "/v1/policies/private", e.adminA, bad, "If-Match", "0")
	if c != 400 || !strings.Contains(string(b), "default_action must be deny") {
		t.Fatalf("%d %s", c, b)
	}
	if c, _, _ := e.call("GET", "/v1/policies/private", e.adminA, nil); c != 404 {
		t.Fatalf("invalid policy was stored: %d", c)
	}
	if c, b, _ := e.call("PUT", "/v1/policies/private", e.adminA, bad); c != 428 {
		t.Fatalf("missing If-Match: %d %s", c, b)
	}
	if c, _, _ := e.call("PUT", "/v1/policies/bogus", e.adminA, bad, "If-Match", "0"); c != 404 {
		t.Fatal("unknown kind")
	}
}

func TestConcurrentWrites(t *testing.T) { // CP-003
	e := newEnv(t)
	good := map[string]any{"default_action": "deny", "rules": []any{}}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, _ := e.call("PUT", "/v1/policies/private", e.adminA, good, "If-Match", "0")
			codes <- c
		}()
	}
	wg.Wait()
	close(codes)
	ok, conflict := 0, 0
	for c := range codes {
		switch c {
		case 200:
			ok++
		case 412:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("ok=%d conflict=%d", ok, conflict)
	}
}

func TestTenantIsolationAPI(t *testing.T) { // CP-004
	e := newEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g",
		"targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice"})
	e.api.Store.PutDevice("a", store.Device{ID: "d1", User: "alice"})
	e.call("PUT", "/v1/policies/web", e.adminA, map[string]any{"default_action": "allow", "rules": []any{}}, "If-Match", "0")
	for _, c := range []struct{ m, p string }{
		{"GET", "/v1/segments"}, {"GET", "/v1/devices"}, {"GET", "/v1/users"}, {"GET", "/v1/policies/web"}, {"GET", "/v1/audit"},
	} {
		code, b, _ := e.call(c.m, c.p, e.adminB, nil)
		s := string(b)
		if strings.Contains(s, "erp") || strings.Contains(s, "alice") || strings.Contains(s, `"d1"`) || (code == 200 && c.p == "/v1/policies/web") {
			t.Errorf("%s %s leaked tenant a data to b: %d %s", c.m, c.p, code, s)
		}
	}
	if c, _, _ := e.call("DELETE", "/v1/segments/erp", e.adminB, nil); c != 404 {
		t.Errorf("b deleted a's segment: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/devices/d1/revoke", e.adminB, nil); c != 404 {
		t.Errorf("b revoked a's device: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/users/alice/disable", e.adminB, nil); c != 404 {
		t.Errorf("b disabled a's user: %d", c)
	}
	// tenant id in the body is ignored: it comes from the token
	e.call("POST", "/v1/segments", e.adminB, map[string]any{"id": "x", "group": "g", "tenant_id": "a"})
	if segs, _ := e.api.Store.Segments("a"); len(segs) != 1 {
		t.Error("b wrote into a")
	}
}

func TestAuthAndRoles(t *testing.T) { // CP-005, SEC-008
	e := newEnv(t)
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	for name, tok := range map[string]string{"none": "", "wrong": "nope"} {
		if c, _, _ := e.call("GET", "/v1/segments", tok, nil); c != 401 {
			t.Errorf("%s: %d", name, c)
		}
	}
	if c, _, _ := e.call("GET", "/v1/segments?access_token="+e.adminA, "", nil); c != 401 {
		t.Error("token in URL accepted")
	}
	if c, _, _ := e.call("GET", "/v1/segments", viewer, nil); c != 200 {
		t.Errorf("viewer read: %d", c)
	}
	for _, w := range []struct{ m, p string }{
		{"PUT", "/v1/idp"}, {"POST", "/v1/segments"}, {"PUT", "/v1/policies/web"}, {"POST", "/v1/policies/safe-defaults"},
		{"POST", "/v1/connectors/tokens"}, {"POST", "/v1/devices/x/revoke"}, {"POST", "/v1/users/x/disable"},
	} {
		if c, _, _ := e.call(w.m, w.p, viewer, map[string]any{}); c != 403 {
			t.Errorf("viewer %s %s: %d", w.m, w.p, c)
		}
	}
	if c, _, _ := e.call("POST", "/v1/tenants", e.adminA, map[string]string{"id": "z"}); c != 401 {
		t.Error("tenant admin created a tenant")
	}
}

func TestDryRun(t *testing.T) { // CP-006
	e := newEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g",
		"targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	draft := map[string]any{"default_action": "deny", "rules": []map[string]any{
		{"id": "r", "priority": 1, "action": "allow", "match": map[string]any{"groups": []string{"fin"}, "apps": []string{"erp"}}}}}
	c, b, _ := e.call("POST", "/v1/policies/private/dry-run", e.adminA, map[string]any{"policy": draft, "groups": []string{"fin"}, "app": "erp"})
	var d policy.Decision
	json.Unmarshal(b, &d)
	if c != 200 || d.Action != policy.Allow || d.RuleID != "r" {
		t.Fatalf("%d %s", c, b)
	}
	_, b, _ = e.call("POST", "/v1/policies/private/dry-run", e.adminA, map[string]any{"policy": draft, "groups": []string{"hr"}, "app": "erp"})
	json.Unmarshal(b, &d)
	if d.Action != policy.Deny {
		t.Fatalf("%s", b)
	}
	if c, _, _ := e.call("GET", "/v1/policies/private", e.adminA, nil); c != 404 {
		t.Fatal("dry run stored the draft")
	}
	if c, _, _ := e.call("POST", "/v1/policies/private/dry-run", e.adminA, map[string]any{"app": "erp"}); c != 404 {
		t.Fatal("dry run without any policy must 404")
	}
}

func TestSafeDefaultsDecisions(t *testing.T) { // VAL-012
	segs := []struct{ id, class string }{{"erp", "standard"}, {"router", "admin"}}
	var in []brokerSeg
	for _, s := range segs {
		in = append(in, brokerSeg{ID: s.id, Class: s.class})
	}
	priv, web := SafeDefaults(toSegs(in))
	if err := priv.Compile(nil); err != nil {
		t.Fatal(err)
	}
	if err := web.Compile(nil); err != nil {
		t.Fatal(err)
	}
	tr := true
	now := time.Now()
	good := &policy.Posture{OS: "linux", DiskEncrypted: &tr, FirewallOn: &tr, ReportedAt: now.Add(-time.Minute)}
	ev := func(p *policy.Policy, r policy.Request) policy.Action { r.Now = now; return p.Evaluate(r).Action }
	staff := policy.User{Groups: []string{"all-staff"}}
	adm := policy.User{Groups: []string{"admins"}}
	for name, c := range map[string]struct {
		r    policy.Request
		want policy.Action
	}{
		"staff erp ok":         {policy.Request{Kind: policy.Private, User: staff, App: "erp", Device: policy.Device{Posture: good}}, policy.Allow},
		"staff erp no posture": {policy.Request{Kind: policy.Private, User: staff, App: "erp"}, policy.Deny},
		"staff router":         {policy.Request{Kind: policy.Private, User: staff, App: "router", Device: policy.Device{Posture: good}}, policy.Deny},
		"admin router ok":      {policy.Request{Kind: policy.Private, User: adm, App: "router", Device: policy.Device{Posture: good}}, policy.Allow},
		"stranger erp":         {policy.Request{Kind: policy.Private, App: "erp", Device: policy.Device{Posture: good}}, policy.Deny},
	} {
		if got := ev(priv, c.r); got != c.want {
			t.Errorf("%s: got %s", name, got)
		}
	}
	for cat, want := range map[string]policy.Action{"malware": policy.Deny, "phishing": policy.Deny, "newly-registered": policy.Warn, "news": policy.Allow} {
		if got := ev(web, policy.Request{Kind: policy.Web, Host: "x.test", Categories: []string{cat}}); got != want {
			t.Errorf("web %s: got %s", cat, got)
		}
	}
}

func TestRevokeAndDisableHooks(t *testing.T) { // AG-005/006 control-plane side
	e := newEnv(t)
	var gotDev, gotUser string
	e.api.OnRevokeDevice = func(tenant string, d store.Device) { gotDev = tenant + "/" + d.ID }
	e.api.OnDisableUser = func(tenant, s string) { gotUser = tenant + "/" + s }
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice"})
	e.api.Store.PutDevice("a", store.Device{ID: "d1", User: "alice", Serial: "123"})
	if c, _, _ := e.call("POST", "/v1/devices/d1/revoke", e.adminA, nil); c != 200 || gotDev != "a/d1" {
		t.Fatalf("revoke %d %q", c, gotDev)
	}
	if c, _, _ := e.call("POST", "/v1/users/alice/disable", e.adminA, nil); c != 200 || gotUser != "a/alice" {
		t.Fatalf("disable %d %q", c, gotUser)
	}
	if u, _ := e.api.Store.User("a", "alice"); !u.Disabled {
		t.Fatal("not disabled")
	}
}

func TestSegmentValidationAndUnknownFields(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]any{
		"no targets":    map[string]any{"id": "x", "group": "g"},
		"bad port":      map[string]any{"id": "x", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{70000}}}},
		"bad class":     map[string]any{"id": "x", "group": "g", "class": "root", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}},
		"unknown field": map[string]any{"id": "x", "group": "g", "evil": 1, "targets": []map[string]any{{"host": "h", "ports": []int{1}}}},
	} {
		if c, _, _ := e.call("POST", "/v1/segments", e.adminA, body); c != 400 {
			t.Errorf("%s: %d", name, c)
		}
	}
}

func TestAlertSettings(t *testing.T) {
	e := newEnv(t)
	if c, b, _ := e.call("PUT", "/v1/alert-settings", e.adminA, map[string]any{"emails": []string{"owner@example.com"}}); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	for _, bad := range []string{"no-at-sign", "a b@example.com", "x@example.com\r\nBcc: y@z", "a@b.c,d@e.f"} {
		if c, _, _ := e.call("PUT", "/v1/alert-settings", e.adminA, map[string]any{"emails": []string{bad}}); c != 400 {
			t.Errorf("%q accepted: %d", bad, c)
		}
	}
	_, b, _ := e.call("GET", "/v1/alert-settings", e.adminA, nil)
	if !strings.Contains(string(b), "owner@example.com") {
		t.Fatalf("%s", b)
	}
	_, b, _ = e.call("GET", "/v1/alert-settings", e.adminB, nil)
	if strings.Contains(string(b), "owner@example.com") {
		t.Fatal("tenant b sees tenant a recipients")
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("PUT", "/v1/alert-settings", viewer, map[string]any{"emails": []string{"x@example.com"}}); c != 403 {
		t.Fatalf("viewer changed settings: %d", c)
	}
}

func TestAdminAPIHostileInput(t *testing.T) { // SEC-015
	e := newEnv(t)
	evil := []string{"../../etc/passwd", "..%2f..%2fetc", "a/b", strings.Repeat("A", 100000), "\x00", "'; DROP TABLE x;--", "<script>", "%", "\r\nX: y", "ünï"}
	for _, id := range evil {
		for _, c := range []struct{ m, p string }{
			{"PUT", "/v1/segments/"}, {"DELETE", "/v1/segments/"}, {"POST", "/v1/devices/"}, {"POST", "/v1/users/"},
		} {
			path := c.p + url.PathEscape(id)
			if c.p == "/v1/devices/" || c.p == "/v1/users/" {
				path += map[string]string{"/v1/devices/": "/revoke", "/v1/users/": "/disable"}[c.p]
			}
			code, _, _ := e.call(c.m, path, e.adminA, map[string]any{"group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
			if code >= 500 {
				t.Errorf("%s %.40s: server error %d", c.m, path, code)
			}
		}
		code, _, _ := e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": id, "group": id, "targets": []map[string]any{{"host": id, "ports": []int{1}}}})
		if code >= 500 {
			t.Errorf("segment body %.40q: server error %d", id, code)
		}
	}
	for _, body := range []string{"", "null", "[]", "{", `{"id":}`, strings.Repeat("{", 5000), `{"id":"x","id":"y"}`} {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/segments", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+e.adminA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Errorf("body %.30q: server error %d", body, resp.StatusCode)
		}
	}
	big := bytes.Repeat([]byte("a"), 2<<20)
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/segments", bytes.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+e.adminA)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("oversize body accepted: %d", resp.StatusCode)
		}
	}
	// nothing was written outside the in-memory store: audit still verifies
	if n, err := audit.Verify(e.auditPath); err != nil {
		t.Fatalf("audit chain broken after hostile input (%d records): %v", n, err)
	}
}

func TestPagination(t *testing.T) { // CP-011
	e := newEnv(t)
	for i := 0; i < 7; i++ {
		e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": fmt.Sprint("s", i), "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	}
	var seen []int
	after := ""
	for page := 0; page < 10; page++ {
		path := "/v1/audit?limit=3"
		if after != "" {
			path += "&after=" + after
		}
		code, b, h := e.call("GET", path, e.adminA, nil)
		if code != 200 {
			t.Fatalf("%d %s", code, b)
		}
		var ev []audit.Event
		json.Unmarshal(b, &ev)
		if len(ev) > 3 {
			t.Fatalf("page of %d exceeds the limit", len(ev))
		}
		for _, x := range ev {
			seen = append(seen, x.Seq)
		}
		after = h.Get("X-Next-Cursor")
		if after == "" {
			break
		}
	}
	if len(seen) < 7 {
		t.Fatalf("pagination lost records: %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("pages overlap or are out of order: %v", seen)
		}
	}
	e.api.Alerts = alerts.New()
	for i := 0; i < 5; i++ {
		for j := 0; j < 10; j++ {
			e.api.Alerts.Ingest(broker.Record{Tenant: "a", Kind: "private", Action: "deny", Event: "open", User: fmt.Sprint("u", i), App: "erp"})
		}
	}
	code, b, h := e.call("GET", "/v1/alerts?limit=2", e.adminA, nil)
	var al []alerts.Alert
	json.Unmarshal(b, &al)
	if code != 200 || len(al) != 2 || al[0].ID < al[1].ID || h.Get("X-Next-Cursor") == "" {
		t.Fatalf("%d %s cursor %q", code, b, h.Get("X-Next-Cursor"))
	}
	_, b, _ = e.call("GET", "/v1/alerts?limit=2&after="+h.Get("X-Next-Cursor"), e.adminA, nil)
	var al2 []alerts.Alert
	json.Unmarshal(b, &al2)
	if len(al2) != 2 || al2[0].ID >= al[1].ID {
		t.Fatalf("second page overlaps the first: %v then %v", al, al2)
	}
}

func TestEvidenceEndpoint(t *testing.T) {
	e := newEnv(t)
	e.api.Decisions = decisions.New()
	e.call("PUT", "/v1/idp", e.adminA, map[string]string{"issuer": "https://idp.example", "client_id": "c"})
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "class": "standard",
		"targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	e.call("POST", "/v1/policies/safe-defaults", e.adminA, nil)
	code, b, _ := e.call("GET", "/v1/evidence", e.adminA, nil)
	var rep evidence.Report
	json.Unmarshal(b, &rep)
	if code != 200 || len(rep.Items) < 8 {
		t.Fatalf("%d %s", code, b)
	}
	status := map[string]evidence.Status{}
	for _, it := range rep.Items {
		status[it.Control] = it.Status
	}
	if status["Network segmentation / least-privilege access to internal systems"] != evidence.Evidenced ||
		status["Device health checks before access (encryption, firewall)"] != evidence.Evidenced ||
		status["Web filtering / malicious-site blocking"] != evidence.Evidenced {
		t.Fatalf("%v", status)
	}
	if status["Multi-factor authentication for staff"] != evidence.NotEvidenced {
		t.Fatal("MFA must never be claimed")
	}
	// tenant b has configured nothing, and must not inherit a's configuration
	_, bb, _ := e.call("GET", "/v1/evidence?format=text", e.adminB, nil)
	if !strings.Contains(string(bb), "No private-access segments") || strings.Contains(string(bb), "1 application segments") {
		t.Fatalf("tenant isolation: %s", bb)
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("GET", "/v1/evidence", viewer, nil); c != 200 {
		t.Fatalf("viewer: %d", c)
	}
}
