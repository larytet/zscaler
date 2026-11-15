//go:build real

package real

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// openSession returns an established session to the app and checks it works.
func openSession(t *testing.T, a *agentInst) interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
} {
	t.Helper()
	c, err := socksConnect(a.socks(), "erp.ztx", 7000)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("up"))
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "up" {
		t.Fatalf("the session does not work: %v %q", err, b)
	}
	return c
}

// endsWithin reports how long an established session takes to end, polling with writes.
func endsWithin(c interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	SetDeadline(time.Time) error
}, limit time.Duration) (time.Duration, bool) {
	start := time.Now()
	c.SetDeadline(time.Now().Add(limit))
	for time.Since(start) < limit {
		if _, err := c.Write([]byte("x")); err != nil {
			return time.Since(start), true
		}
		if _, err := c.Read(make([]byte, 1)); err != nil {
			return time.Since(start), true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return limit, false
}

// REAL-AG-001 (AG-005, AG-006, ARCH-006): an admin revokes one device and later disables the user
// while sessions are open. Each ends within seconds, new sessions are refused, and the user's other
// device is unaffected by the revocation of the first.
func TestRealAG001RevocationClosesSessions(t *testing.T) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector("connector")
	apps := map[string]string{"erp.ztx": "erp"}
	laptop := w.newAgent("laptop", apps)
	phone := w.newAgent("phone", apps)
	steady(t, laptop, 60*time.Second, 2)
	steady(t, phone, 30*time.Second, 2)
	lc, pc := openSession(t, laptop), openSession(t, phone)
	defer lc.Close()
	defer pc.Close()

	w.must("POST", "/v1/devices/"+deviceID(t, laptop)+"/revoke", nil)
	d, ended := endsWithin(lc, 15*time.Second)
	if !ended {
		t.Fatal("the revoked device's session survived")
	}
	t.Logf("REAL-AG-001: the revoked device's session ended %v after the revocation (target in the design: within seconds)", d.Round(100*time.Millisecond))
	if echoes(laptop.socks(), "erp.ztx", "x") {
		t.Fatal("the revoked device opened a new session")
	}
	if !echoes(phone.socks(), "erp.ztx", "still me") {
		t.Fatal("the user's other device was affected by the revocation")
	}

	w.must("POST", "/v1/users/u1/disable", nil)
	d, ended = endsWithin(pc, 15*time.Second)
	if !ended {
		t.Fatal("the disabled user's session survived")
	}
	t.Logf("REAL-AG-001: the disabled user's session ended %v after the user was disabled", d.Round(100*time.Millisecond))
	if echoes(phone.socks(), "erp.ztx", "x") {
		t.Fatal("a disabled user opened a new session")
	}
	_, b := w.api("GET", "/v1/audit", nil)
	for _, want := range []string{"device.revoke", "user.disable"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the audit log lacks %s", want)
		}
	}
}

// REAL-CP-001 (CP-007, ADM-004): a policy change takes effect at the enforcement node within seconds,
// and rolling it back restores the earlier behaviour.
func TestRealCP001PolicyChangeAndRollback(t *testing.T) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector("connector")
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 2)

	w.ifMatch = "1"
	changed := time.Now()
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []any{}})
	eventually(t, "the new policy to refuse access", 20*time.Second, func() bool { return !echoes(a.socks(), "erp.ztx", "x") })
	t.Logf("REAL-CP-001: a policy change took effect after %v (sync interval 500 ms)", time.Since(changed).Round(100*time.Millisecond))
	found := false
	for _, d := range w.decisions() {
		if d["policy_version"] == float64(2) && d["action"] == "deny" && d["kind"] == "private" {
			found = true
		}
	}
	if !found {
		t.Fatal("the decision log does not show the new policy version")
	}

	w.ifMatch = "2"
	rolled := time.Now()
	code, b := w.api("POST", "/v1/policies/private/rollback", map[string]int{"version": 1}) // If-Match: the current version
	if code != 200 {
		t.Fatalf("rollback: %d %s", code, b)
	}
	eventually(t, "the rollback to restore access", 20*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "back") })
	t.Logf("REAL-CP-001: the rollback took effect after %v", time.Since(rolled).Round(100*time.Millisecond))
	_, vb := w.api("GET", "/v1/policies/private/versions", nil)
	var vs []struct {
		Version int
		Note    string
	}
	json.Unmarshal(vb, &vs)
	if len(vs) != 3 || !strings.Contains(vs[2].Note, "rollback to version 1") {
		t.Fatalf("the history should show the rollback as version 3: %s", vb)
	}
}

// REAL-CP-002 (CP-008, NFR-011): the control plane is killed. Established and new sessions go on, on
// the node's cached policy; when the control plane returns, policy changes take effect again.
func TestRealCP002ControlPlaneDown(t *testing.T) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector("connector")
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 2)
	c := openSession(t, a)
	defer c.Close()

	w.cpProc.Process.Kill()
	w.cpProc.Wait()
	time.Sleep(3 * time.Second) // several failed syncs
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("during"))
	b := make([]byte, 6)
	if _, err := c.Read(b); err != nil || string(b) != "during" {
		t.Fatalf("the established session did not survive the control plane going down: %v %q", err, b)
	}
	if !echoes(a.socks(), "erp.ztx", "new session") {
		t.Fatal("new sessions were refused while the control plane was down: the cached policy should apply")
	}
	if echoes(a.socks(), "nope.ztx", "x") {
		t.Fatal("an unknown app was served")
	}
	w.restartCP()
	w.ifMatch = "1"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []any{}})
	eventually(t, "a change made after the control plane returned to take effect", 30*time.Second, func() bool { return !echoes(a.socks(), "erp.ztx", "x") })
}

// REAL-AI-001 (AI-001, AGS-002, AGS-004): an AI agent identity. It reaches only what it was granted,
// is read-only on the web with the pack from the platform, cannot reach other sites, and loses its
// access as soon as the person it runs for loses theirs.
func TestRealAI001AgentIdentity(t *testing.T) {
	w := newWorldN(t, 1, withWebSite)
	w.deployApp("erp")
	w.deployConnector("connector")
	w.deployOrigin()
	apps := map[string]string{"erp.ztx": "erp"}
	w.newAgent("alice-laptop", apps) // signs in as u1, which creates the person the agent runs for

	// the person may reach erp by her own rule; the agent only by a grant (approval), and never more than she may
	w.ifMatch = "1"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []map[string]any{
		{"id": "operator", "priority": 5, "action": "allow", "match": map[string]any{"users": []string{"u1"}, "apps": []string{"erp"}}},
		{"id": "agents-jit", "priority": 10, "action": "require_approval", "match": map[string]any{"groups": []string{"ai-agent"}, "apps": []string{"erp"}}}}})
	code, b := w.api("POST", "/v1/ai-agents", map[string]any{"name": "helper", "operator": "u1", "apps": []string{"erp"}, "minutes": 60})
	var created struct {
		Token string `json:"enrolment_token"`
	}
	json.Unmarshal(b, &created)
	if code != 200 || created.Token == "" {
		t.Fatalf("%d %s", code, b)
	}
	bot := w.newAgentTok("helper", apps, created.Token)
	steady(t, bot, 60*time.Second, 2)

	// the web side: the platform produces the read-only pack, the admin saves it in front of the rules
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true})
	_, pb := w.api("GET", "/v1/ai-agents/helper/readonly-pack?domains="+w.site.ip, nil)
	var pack struct {
		Rules    []map[string]any
		Warnings []string
	}
	if err := json.Unmarshal(pb, &pack); err != nil || len(pack.Rules) == 0 {
		t.Fatalf("no pack: %s", pb)
	}
	w.ifMatch = "1"
	w.putWebPolicy("allow", pack.Rules)
	ca := w.inspectionPool()
	var r webResult
	eventually(t, "the agent to read from the origin", 60*time.Second, func() bool {
		r = w.get(bot, ca, "GET", "/data", "", nil)
		return r.err == nil && r.code == 200
	})
	if r = w.get(bot, ca, "POST", "/data", "write", nil); r.code != 403 {
		t.Fatalf("a write by the read-only agent was not refused: %+v", r)
	}
	if seen, _ := w.originSeen(); contains(seen, "POST /data") {
		t.Fatal("the agent's write reached the origin")
	}
	// anywhere else is refused, by the pack's last rule, and the refusal is on record
	if out, err := sh("curl -s -m 8 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:"+itoa(bot.ports["http"])+" -k https://192.0.2.10/", 15*time.Second); err == nil && strings.TrimSpace(out) == "200" {
		t.Fatal("the agent reached a site that is not on its list")
	}
	refused := false
	eventually(t, "the refusal of the unlisted site to be recorded against the egress rule", 15*time.Second, func() bool {
		for _, d := range w.decisions() {
			if d["user"] == "agent:helper" && d["action"] == "deny" && d["rule"] == "agent-helper-egress-deny" && strings.Contains(d["target"].(string), "192.0.2.10") {
				refused = true
			}
		}
		return refused
	})

	// the operator loses her access: the agent loses it too, although its grant is still there
	w.ifMatch = "2"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []map[string]any{
		{"id": "agents-jit", "priority": 10, "action": "require_approval", "match": map[string]any{"groups": []string{"ai-agent"}, "apps": []string{"erp"}}}}})
	eventually(t, "the agent to lose access with its operator", 30*time.Second, func() bool { return !echoes(bot.socks(), "erp.ztx", "x") })
	found := false
	for _, d := range w.decisions() {
		if d["user"] == "agent:helper" && d["reason"] == "operator-lacks-access" {
			found = true
		}
	}
	if !found {
		t.Fatal("the refusal does not say that the operator lacks access")
	}
	// removing the agent ends its grant at once
	w.must("DELETE", "/v1/ai-agents/helper", nil)
}
