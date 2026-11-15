package cp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/store"
)

func TestAdminTokensCanBeReplaced(t *testing.T) { // AGT-042 (GAP-REQ-05)
	e := newEnrolEnv(t)
	st := e.api.Store
	clock := time.Now()
	st.Now = func() time.Time { return clock }
	carol, _ := st.AddAdmin("a", "carol", store.Helpdesk)
	temp, _ := st.AddAdminOpts("a", "temp", store.Viewer, store.AdminOpts{Expires: clock.Add(24 * time.Hour), Note: "audit week"})
	_ = temp
	// an owner replaces another administrator's token: the old one stops, the new one works, the role stays
	code, body, _ := e.call("POST", "/v1/admins/carol/rotate", e.adminA, nil)
	var out struct{ Name, Token string }
	if code != 200 || json.Unmarshal(body, &out) != nil || out.Token == "" || out.Token == carol {
		t.Fatalf("%d %s", code, body)
	}
	if c, _, _ := e.call("GET", "/v1/segments", carol, nil); c != 401 {
		t.Errorf("the old token still works: %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/segments", out.Token, nil); c != 200 {
		t.Errorf("the new token does not work: %d", c)
	}
	if c, _, _ := e.call("PUT", "/v1/idp", out.Token, map[string]string{}); c != 403 {
		t.Errorf("the role changed with the token: %d", c)
	}
	// the expiry and note of a temporary account survive a rotation
	if c, b, _ := e.call("POST", "/v1/admins/temp/rotate", e.adminA, nil); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	for _, ad := range st.Admins("a") {
		if ad.Name == "temp" && (ad.Expires.IsZero() || ad.Note != "audit week" || ad.Rotated.IsZero()) {
			t.Errorf("temporary account after rotation: %+v", ad)
		}
	}
	// only an owner replaces someone else's; anyone replaces their own; an unknown name is not found
	if c, _, _ := e.call("POST", "/v1/admins/owner/rotate", out.Token, nil); c != 403 {
		t.Errorf("a helpdesk administrator replaced the owner's token: %d", c)
	}
	if c, _, _ := e.call("POST", "/v1/admins/nobody/rotate", e.adminA, nil); c != 404 {
		t.Errorf("%d", c)
	}
	c2, b2, _ := e.call("POST", "/v1/me/rotate", out.Token, nil)
	var mine struct{ Name, Token string }
	if c2 != 200 || json.Unmarshal(b2, &mine) != nil || mine.Name != "carol" || mine.Token == out.Token {
		t.Fatalf("%d %s", c2, b2)
	}
	if c, _, _ := e.call("GET", "/v1/segments", out.Token, nil); c != 401 {
		t.Errorf("the token that was replaced still works: %d", c)
	}
	// an expired account cannot be revived by rotating it
	clock = clock.Add(48 * time.Hour)
	if c, _, _ := e.call("POST", "/v1/admins/temp/rotate", e.adminA, nil); c == 200 {
		t.Error("an expired account was given a new token")
	}
	// the audit log records it, and never the token
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if !strings.Contains(string(ab), "admin.rotate") || strings.Contains(string(ab), mine.Token) || strings.Contains(string(ab), out.Token) {
		t.Errorf("audit: %s", ab)
	}
}

func fingerprintOfPEM(t *testing.T, p string) string {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		t.Fatal("not PEM")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatal(err)
	}
	return store.Fingerprint(p)
}

func TestInspectionCAIsReplacedOnlyOnPurpose(t *testing.T) { // AGT-042
	e := newEnrolEnv(t)
	// never turned on: nothing to replace
	if c, _, _ := e.call("POST", "/v1/inspection/rotate", e.adminA, nil); c != 404 {
		t.Errorf("never on: %d", c)
	}
	e.call("PUT", "/v1/inspection", e.adminA, map[string]any{"enabled": true})
	_, ca1, _ := e.call("GET", "/v1/inspection/ca.pem", e.adminA, nil)
	fp1 := fingerprintOfPEM(t, string(ca1))
	spki1, _ := e.api.Store.InterceptSPKI("a")
	// with inspection on it is refused unless asked for with "now", and nothing changes
	if c, b, _ := e.call("POST", "/v1/inspection/rotate", e.adminA, nil); c != 409 || !strings.Contains(string(b), "Turn inspection off first") {
		t.Errorf("on: %d %s", c, b)
	}
	if _, again, _ := e.call("GET", "/v1/inspection/ca.pem", e.adminA, nil); string(again) != string(ca1) {
		t.Fatal("a refused rotation changed the CA")
	}
	// roles: needs write
	view, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("POST", "/v1/inspection/rotate", view, map[string]bool{"now": true}); c != 403 {
		t.Errorf("viewer: %d", c)
	}
	// off first, then it rotates without argument
	e.call("PUT", "/v1/inspection", e.adminA, map[string]any{"enabled": false})
	code, body, _ := e.call("POST", "/v1/inspection/rotate", e.adminA, nil)
	var out struct {
		Old string `json:"old_fingerprint"`
		New string `json:"new_fingerprint"`
	}
	if code != 200 || json.Unmarshal(body, &out) != nil || out.Old != fp1 || out.New == "" || out.New == fp1 {
		t.Fatalf("%d %s (old should be %s)", code, body, fp1)
	}
	_, ca2, _ := e.call("GET", "/v1/inspection/ca.pem", e.adminA, nil)
	if fingerprintOfPEM(t, string(ca2)) != out.New || string(ca2) == string(ca1) {
		t.Error("the downloadable certificate is not the new one")
	}
	e.call("PUT", "/v1/inspection", e.adminA, map[string]any{"enabled": true})
	if spki2, _ := e.api.Store.InterceptSPKI("a"); spki2 == spki1 || spki2 == "" {
		t.Error("the leaf key was not replaced, so the workspace pin would not change")
	}
	// the private keys are never in an answer
	_, cfg, _ := e.call("GET", "/v1/inspection", e.adminA, nil)
	if strings.Contains(string(cfg), "PRIVATE KEY") || !strings.Contains(string(cfg), "rotated") {
		t.Errorf("config: %s", cfg)
	}
	// on, with "now": it goes ahead
	if c, _, _ := e.call("POST", "/v1/inspection/rotate", e.adminA, map[string]bool{"now": true}); c != 200 {
		t.Errorf("now: %d", c)
	}
	if _, ca3, _ := e.call("GET", "/v1/inspection/ca.pem", e.adminA, nil); string(ca3) == string(ca2) {
		t.Error("not replaced")
	}
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if strings.Count(string(ab), "inspection.rotate") != 2 || strings.Contains(string(ab), "PRIVATE KEY") {
		t.Errorf("audit: %s", ab)
	}
}

func TestKeyStatusSaysHowOldEverythingIsAndWarns(t *testing.T) { // AGT-042
	e := newEnrolEnv(t)
	st := e.api.Store
	clock := time.Now()
	st.Now = func() time.Time { return clock }
	ca, _ := pki.NewCA("root", nil)
	e.api.RootCACert = ca.Cert
	get := func(tok string) (int, map[string]any) {
		c, b, _ := e.call("GET", "/v1/keys", tok, nil)
		var m map[string]any
		json.Unmarshal(b, &m)
		return c, m
	}
	// only roles that may read the audit log
	for _, r := range []store.Role{store.Viewer, store.Helpdesk} {
		tok, _ := st.AddAdmin("a", "k-"+string(r), r)
		if c, _ := get(tok); c != 403 {
			t.Errorf("%s: %d", r, c)
		}
	}
	c, m := get(e.adminA)
	if c != 200 {
		t.Fatal(c)
	}
	warnings := strings.Join(toStrings(m["warnings"]), "|")
	if !strings.Contains(warnings, "stored in clear") || m["master_key_in_use"] != false {
		t.Errorf("a missing master key must be warned about: %v", m)
	}
	// it shows the root CA with its end date and a way to replace each thing, and no secret
	raw, _ := json.Marshal(m)
	for _, want := range []string{"device certificate authority", "days_left", "POST /v1/admins/{name}/rotate", "rekey"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %q in %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), e.adminA) {
		t.Error("a secret is in the answer")
	}
	// sealed: the warning goes
	e.api.AtRestSealed = true
	_, m = get(e.adminA)
	if strings.Contains(strings.Join(toStrings(m["warnings"]), "|"), "stored in clear") || m["master_key_in_use"] != true {
		t.Errorf("sealed: %v", m)
	}
	// a token that has never been replaced in 180 days is listed, until it is replaced
	clock = clock.Add(200 * 24 * time.Hour)
	_, m = get(e.adminA)
	at := m["admin_tokens"].(map[string]any)
	if len(toStrings(at["not_replaced_in_180_days"])) == 0 || !strings.Contains(strings.Join(toStrings(m["warnings"]), "|"), "never been replaced") {
		t.Errorf("an old token must be listed: %v", at)
	}
	// the root CA close to its end is warned about (a CA made 10 years ago)
	old, _ := pki.NewCA("old", func() time.Time { return clock.Add(-9*365*24*time.Hour - 200*24*time.Hour) })
	e.api.RootCACert = old.Cert
	_, m = get(e.adminA)
	if !strings.Contains(strings.Join(toStrings(m["warnings"]), "|"), "expires in under 180 days") {
		t.Errorf("a CA near its end: %v", m["warnings"])
	}
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// The weekly summary shows who was given or lost administrator access, and an owner reset made at the server (GAP-REQ-03).
func TestDigestShowsOwnerResetFromTheServer(t *testing.T) { // AGT-043
	e := newEnrolEnv(t)
	if e.api.Audit == nil || e.api.AuditPath == "" {
		t.Skip("this environment has no audit log")
	}
	e.call("POST", "/v1/admins", e.adminA, map[string]string{"name": "dana", "role": "viewer"})
	e.api.Audit.Append("a", "host:ops", "owner.reset", "owner", nil, nil) // what `ztx-cp reset-owner` writes
	e.api.Audit.Append("b", "host:ops", "owner.reset", "owner", nil, nil) // another tenant's
	_, b, _ := e.call("GET", "/v1/digest?format=text", e.adminA, nil)
	txt := string(b)
	for _, want := range []string{"Administrator access changes", "gave administrator access to dana", "reset the owner token of owner", "break-in"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	if strings.Count(txt, "reset the owner token") != 1 {
		t.Errorf("another tenant's reset leaked into this digest:\n%s", txt)
	}
}

// The policy simulator takes the address a user would connect from, IPv4 or IPv6, and refuses a bad one (GAP-REQ-10).
func TestDryRunWithASourceAddress(t *testing.T) { // AGT-048
	e := newEnv(t)
	e.call("POST", "/v1/segments", e.adminA, map[string]any{"id": "erp", "group": "g", "targets": []map[string]any{{"host": "h", "ports": []int{1}}}})
	draft := map[string]any{"default_action": "deny", "rules": []map[string]any{{"id": "office", "priority": 1, "action": "allow",
		"match": map[string]any{"groups": []string{"fin"}, "apps": []string{"erp"}, "network": map[string]any{"src_cidrs": []string{"203.0.113.0/24", "2001:db8:1::/48"}}}}}}
	try := func(src string) (int, string) {
		c, b, _ := e.call("POST", "/v1/policies/private/dry-run", e.adminA, map[string]any{"policy": draft, "groups": []string{"fin"}, "app": "erp", "src_ip": src})
		var d struct {
			Action string `json:"Action"`
			RuleID string `json:"RuleID"`
		}
		json.Unmarshal(b, &d)
		if c != 200 {
			return c, string(b)
		}
		return c, d.Action + "/" + d.RuleID
	}
	for src, want := range map[string]string{
		"203.0.113.77": "allow/office", "2001:db8:1::99": "allow/office", "::ffff:203.0.113.5": "allow/office",
		"198.51.100.1": "deny/", "2001:db8:2::1": "deny/", "": "deny/", "::1": "deny/",
	} {
		if c, got := try(src); c != 200 || got != want {
			t.Errorf("src %q: %d %s, want %s", src, c, got, want)
		}
	}
	for _, bad := range []string{"not-an-ip", "203.0.113.0/24", "203.0.113.999", "[::1]"} {
		if c, _ := try(bad); c != 400 {
			t.Errorf("src %q should be refused: %d", bad, c)
		}
	}
}

// The tenant states who is told first if the platform loses its data (GAP-REQ-11).
func TestSecurityContactIsPerTenantAndValidated(t *testing.T) { // AGT-049
	e := newEnv(t)
	c, b, _ := e.call("GET", "/v1/security-contact", e.adminA, nil)
	if c != 200 || !strings.Contains(string(b), "No security contact is set") {
		t.Fatalf("%d %s", c, b)
	}
	if c, _, _ := e.call("PUT", "/v1/security-contact", e.adminA, map[string]string{"name": "Dana Owner", "email": "dana@acme.example"}); c != 200 {
		t.Fatalf("set: %d", c)
	}
	_, b, _ = e.call("GET", "/v1/security-contact", e.adminA, nil)
	var got map[string]string
	json.Unmarshal(b, &got)
	if got["email"] != "dana@acme.example" || got["name"] != "Dana Owner" || got["note"] != "" {
		t.Errorf("%v", got)
	}
	// another tenant has its own
	_, b, _ = e.call("GET", "/v1/security-contact", e.adminB, nil)
	if strings.Contains(string(b), "dana@") {
		t.Errorf("tenant b sees tenant a's contact: %s", b)
	}
	// bad input is refused, and only the people who manage administrators may change it; anyone who reads may look
	for _, in := range []map[string]string{{"email": "not-an-address"}, {"email": "a b@c.d"}, {"email": "@x.example"}, {"email": "x@"}, {"email": "a@b.example,c@d.example"}, {"name": strings.Repeat("n", 101), "email": "a@b.example"}, {"name": "x\r\ny", "email": "a@b.example"}} {
		if c, _, _ := e.call("PUT", "/v1/security-contact", e.adminA, in); c != 400 {
			t.Errorf("%v accepted: %d", in, c)
		}
	}
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	admin, _ := e.api.Store.AddAdmin("a", "ada", store.Admin)
	if c, _, _ := e.call("PUT", "/v1/security-contact", viewer, map[string]string{"email": "v@x.example"}); c != 403 {
		t.Errorf("viewer: %d", c)
	}
	if c, _, _ := e.call("PUT", "/v1/security-contact", admin, map[string]string{"email": "v@x.example"}); c != 403 {
		t.Errorf("admin (not owner): %d", c)
	}
	if c, _, _ := e.call("GET", "/v1/security-contact", viewer, nil); c != 200 {
		t.Errorf("viewer read: %d", c)
	}
	// clearing it is allowed, and every change is in the audit log with the old and new value
	if c, _, _ := e.call("PUT", "/v1/security-contact", e.adminA, map[string]string{"name": "", "email": ""}); c != 200 {
		t.Errorf("clear: %d", c)
	}
	_, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil)
	if strings.Count(string(ab), "security-contact.update") != 2 || !strings.Contains(string(ab), "dana@acme.example") {
		t.Errorf("audit: %s", ab)
	}
}
