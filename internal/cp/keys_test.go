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
