//go:build real

package real

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func contains(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// REAL-ZIA-001 (ZIA-001, ZIA-012, ZIA-014): web requests from an agent go through the platform to a
// service in the cluster, are allowed or refused by domain rules, and a refusal names its rule and
// leaves the service untouched.
func TestRealZIA001WebFilteringToClusterService(t *testing.T) {
	w, a := startWeb(t)
	w.putWebPolicy("allow", nil)
	var r webResult
	eventually(t, "a request to the origin to go through", 60*time.Second, func() bool {
		r = w.get(a, w.site.pool, "GET", "/hello", "", nil)
		return r.err == nil && r.code == 200
	})
	if r.body != `origin: GET /hello auth= body=0` {
		t.Fatalf("the origin's answer was changed on the way: %q", r.body)
	}
	if r.issuer != "ztx-real-origin" {
		t.Fatalf("without inspection the client must see the origin's own certificate, saw issuer %q", r.issuer)
	}

	w.putWebPolicy("allow", []map[string]any{{"id": "block-site", "priority": 1, "action": "deny", "reason": "blocked by the real test",
		"match": map[string]any{"domains": []string{w.site.ip}}}})
	eventually(t, "the block to take effect", 30*time.Second, func() bool {
		r = w.get(a, w.site.pool, "GET", "/blocked", "", nil)
		return r.err != nil || r.code == 403
	})
	seenBefore, _ := w.originSeen() // counted from here: requests sent while the policy was still syncing may legitimately have passed
	for i := 0; i < 3; i++ {
		if r = w.get(a, w.site.pool, "GET", "/blocked", "", nil); r.err == nil && r.code == 200 {
			t.Fatal("a blocked site was reached")
		}
	}
	if seen, _ := w.originSeen(); len(seen) != len(seenBefore) {
		t.Fatalf("the origin received %d requests while blocked", len(seen)-len(seenBefore))
	}
	found := false
	eventually(t, "the refusal to be recorded with its rule", 15*time.Second, func() bool {
		for _, d := range w.decisions() {
			if d["kind"] == "web" && d["action"] == "deny" && d["rule"] == "block-site" && d["user"] != nil {
				found = true
			}
		}
		return found
	})

	w.putWebPolicy("allow", nil)
	eventually(t, "access to return", 30*time.Second, func() bool {
		r = w.get(a, w.site.pool, "GET", "/back", "", nil)
		return r.err == nil && r.code == 200
	})
}

// REAL-ZIA-002 (ZIA-030, ZIA-040, ZIA-032): TLS inspection. The client sees a certificate from the
// tenant's CA, path and method rules apply to the decrypted traffic, and an exempt domain is left alone.
func TestRealZIA002TLSInspection(t *testing.T) {
	w, a := startWeb(t)
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true})
	w.putWebPolicy("allow", []map[string]any{{"id": "no-upload", "priority": 1, "action": "deny",
		"match": map[string]any{"domains": []string{w.site.ip}, "paths": []string{"/upload"}, "methods": []string{"POST"}}}})
	ca := w.inspectionPool()
	var r webResult
	eventually(t, "an inspected request to go through", 60*time.Second, func() bool {
		r = w.get(a, ca, "GET", "/ok", "", nil)
		return r.err == nil && r.code == 200
	})
	if r.issuer == "ztx-real-origin" || r.issuer == "" {
		t.Fatalf("the client should be shown a certificate from the tenant's CA, saw issuer %q", r.issuer)
	}
	if r.body != `origin: GET /ok auth= body=0` {
		t.Fatalf("%q", r.body)
	}
	// a client that does not trust the tenant's CA refuses the connection: inspection is not silent
	if r2 := w.get(a, w.site.pool, "GET", "/ok", "", nil); r2.err == nil {
		t.Fatal("a device that does not trust the inspection CA accepted the intercepted certificate")
	}
	// path and method rules, possible only after decryption
	before, _ := w.originSeen()
	if r = w.get(a, ca, "POST", "/upload", "file", nil); r.code != 403 {
		t.Fatalf("the upload was not blocked: %+v", r)
	}
	if seen, _ := w.originSeen(); len(seen) != len(before) {
		t.Fatal("the blocked upload reached the origin")
	}
	if r = w.get(a, ca, "GET", "/upload", "", nil); r.code != 200 {
		t.Fatalf("only POST is refused: %+v", r)
	}
	// an exempt domain is tunnelled untouched: the client sees the origin's own certificate
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true, "exempt": []string{w.site.ip}})
	eventually(t, "the exemption to take effect", 30*time.Second, func() bool {
		r = w.get(a, w.site.pool, "GET", "/exempt", "", nil)
		return r.err == nil && r.code == 200 && r.issuer == "ztx-real-origin"
	})
}

// REAL-ZIA-003 (DATA-001, DATA-006): data protection on decrypted uploads. Card numbers, listed
// values and indexed text are blocked at the node and never reach the origin; clean uploads arrive intact.
func TestRealZIA003DataProtection(t *testing.T) {
	w, a := startWeb(t)
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true})
	w.must("PUT", "/v1/edm/customers", map[string]any{"values": []string{"CUST-004711", "jane.doe@example.com"}})
	const priceList = "Acme Corp price list for 2027. The enterprise plan costs forty nine dollars per seat per month, billed annually, with a minimum of ten seats."
	w.must("PUT", "/v1/edm/pricelist", map[string]any{"documents": []string{priceList}})
	w.putWebPolicy("allow", []map[string]any{{"id": "no-sensitive-data", "priority": 1, "action": "deny",
		"match": map[string]any{"dlp": []string{"credit-card", "edm:customers", "edm:pricelist"}}}})
	ca := w.inspectionPool()
	clean := `{"note":"order 42 shipped"}`
	eventually(t, "a clean upload to go through intact", 60*time.Second, func() bool {
		r := w.get(a, ca, "POST", "/up", clean, nil)
		return r.err == nil && r.code == 200 && r.body == "origin: POST /up auth= body="+itoa(len(clean))
	})
	for name, body := range map[string]string{
		"card number":  `{"card":"4111 1111 1111 1111"}`,
		"listed value": `{"id":"CUST-004711"}`,
		"listed, case": `{"mail":"Jane.Doe@Example.com"}`,
		"indexed text": `{"text":"fyi ` + priceList + `"}`,
	} {
		if r := w.get(a, ca, "POST", "/up", body, nil); r.code != 403 {
			t.Errorf("%s was not blocked: %+v", name, r)
		}
	}
	if r := w.get(a, ca, "POST", "/up", `{"id":"CUST-009999"}`, nil); r.code != 200 {
		t.Errorf("a value that is not on the list must pass: %+v", r)
	}
	seen, _ := w.originSeen()
	for _, secret := range []string{"4111", "CUST-004711", "jane.doe", "enterprise plan"} {
		if contains(seen, secret) {
			t.Errorf("%q reached the origin", secret)
		}
	}
	if !contains(seen, "order 42 shipped") {
		t.Error("the clean upload never reached the origin")
	}
	raw := strings.ToLower(w.allDecisionsRaw())
	for _, secret := range []string{"4111", "cust-004711", "jane.doe", "enterprise plan"} {
		if strings.Contains(raw, secret) {
			t.Errorf("%q reached the decision log", secret)
		}
	}
}

// REAL-ZIA-004 (ZIA-022b, AGS-001): capture and credential injection against an API in the cluster.
// The key is added by the platform and reaches the origin; the agent, the capture, the logs and the
// admin API never see it, even though the origin echoes it back.
func TestRealZIA004CaptureAndCredentialInjection(t *testing.T) {
	const key = "Bearer REAL-TEST-KEY-8c1f"
	w, a := startWeb(t)
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true})
	w.must("PUT", "/v1/secrets/api", map[string]any{"host": w.site.ip, "header": "Authorization", "value": key})
	w.putWebPolicy("deny", []map[string]any{{"id": "agent-api", "priority": 1, "action": "allow", "inject": "api", "capture": true,
		"match": map[string]any{"domains": []string{w.site.ip}}}})
	ca := w.inspectionPool()
	var r webResult
	eventually(t, "the request to go through with the key added", 60*time.Second, func() bool {
		r = w.get(a, ca, "GET", "/v1/things", "", map[string]string{"Authorization": "Bearer agent-guess"})
		return r.err == nil && r.code == 200
	})
	seen, _ := w.originSeen()
	if !contains(seen, `auth="`+key+`"`) {
		t.Fatalf("the origin did not receive the stored key: %v", seen)
	}
	if contains(seen, "agent-guess") {
		t.Fatal("the agent's own credential reached the origin: it must be replaced")
	}
	if strings.Contains(r.body, "REAL-TEST-KEY") || strings.Contains(r.body, "agent-guess") {
		t.Fatalf("the agent saw a credential in the answer: %q", r.body)
	}
	// nothing the admin can read holds the key
	for _, p := range []string{"/v1/secrets", "/v1/audit", "/v1/captures"} {
		if _, b := w.api("GET", p, nil); strings.Contains(string(b), "REAL-TEST-KEY") {
			t.Fatalf("%s returned the key", p)
		}
	}
	// the capture exists, is readable by the admin, and holds neither key nor the agent's guess
	var list []struct {
		ID   int
		Rule string
	}
	eventually(t, "the capture to appear", 15*time.Second, func() bool {
		_, b := w.api("GET", "/v1/captures", nil)
		json.Unmarshal(b, &list)
		return len(list) > 0 && list[0].Rule == "agent-api"
	})
	_, cb := w.api("GET", "/v1/captures/"+itoa(list[0].ID), nil)
	if !strings.Contains(string(cb), "[redacted]") || strings.Contains(string(cb), "agent-guess") || strings.Contains(string(cb), "REAL-TEST-KEY") {
		t.Fatalf("the capture is not redacted: %s", cb)
	}
	if strings.Contains(w.allDecisionsRaw(), "REAL-TEST-KEY") {
		t.Fatal("the key reached the decision log")
	}
	// a capture is never written to the node's disk
	if strings.Contains(w.allDecisionsRaw(), `"kind":"capture"`) {
		t.Fatal("a capture was written to the enforcement node's log")
	}
}
