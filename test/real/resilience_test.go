//go:build real

package real

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// connected counts how often a connector reported itself connected to any enforcement node.
func (w *world) connected(name string) int {
	n := 0
	for _, d := range w.decisions() {
		if d["kind"] == "connector" && d["device"] == name && d["event"] == "connected" {
			n++
		}
	}
	return n
}

func (w *world) podUID(name string) string {
	return strings.TrimSpace(w.mustK("get pod " + name + " -n " + w.ns + " -o jsonpath={.metadata.uid}"))
}

// steady waits until the app answers, then requires n answers in a row.
func steady(t *testing.T, a *agentInst, wait time.Duration, n int) {
	t.Helper()
	eventually(t, "the app to answer", wait, func() bool { return echoes(a.socks(), "erp.ztx", "x") })
	for i := 0; i < n; i++ {
		if !echoes(a.socks(), "erp.ztx", "steady") {
			t.Fatalf("access broke again after it had recovered (answer %d of %d)", i+1, n)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// REAL-PA-003 (ZPA-010, ZPA-011, PA-009, PA-010): two connector pods of one group. One is taken
// away; access continues through the other, and when it returns it reconnects with the identity it
// enrolled with (the enrolment token is one-time), without anyone doing anything.
func TestRealPA003ConnectorRedundancy(t *testing.T) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector("connector")
	w.deployConnector("connector-b")
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 3)
	eventually(t, "both connectors to be connected", 30*time.Second, func() bool { return w.connected("connector") >= 1 && w.connected("connector-b") >= 1 })
	bIP := w.podIP("app=connector-b")
	aIP := w.podIP("app=connector")
	if aIP == bIP {
		t.Fatal("the two connectors share an address")
	}

	// take the first connector away: its pod goes, and is not replaced
	w.mustK("scale statefulset/connector -n " + w.ns + " --replicas=0")
	eventually(t, "the first connector pod to be gone", 60*time.Second, func() bool {
		return strings.TrimSpace(w.mustK("get pods -n "+w.ns+" -l app=connector -o name")) == ""
	})
	mark := len(w.appClients())
	steady(t, a, 30*time.Second, 5)
	for _, c := range w.appClients()[mark:] {
		if c != bIP {
			t.Fatalf("with the first connector gone, the app was reached from %s, not from the second connector %s", c, bIP)
		}
	}

	// bring it back: same volume, same identity, no new token
	before := w.connected("connector")
	w.mustK("scale statefulset/connector -n " + w.ns + " --replicas=1")
	w.mustK("rollout status statefulset/connector -n " + w.ns + " --timeout=120s")
	eventually(t, "the returned connector to reconnect", 60*time.Second, func() bool { return w.connected("connector") > before })
	steady(t, a, 30*time.Second, 3)
}

// REAL-PA-004 (ZPA-044, ARCH-003, NFR-011): two enforcement nodes. The one an agent is using is
// killed in the middle of a session: that session ends, and new sessions work through the other node
// at once. The killed node comes back with the identity it had.
func TestRealPA004EnforcementNodeFailure(t *testing.T) {
	w := newWorldN(t, 2)
	w.deployApp("erp")
	w.deployConnector("connector")
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 3)
	c, err := socksConnect(a.socks(), "erp.ztx", 7000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("before"))
	buf := make([]byte, 6)
	if _, err := c.Read(buf); err != nil || string(buf) != "before" {
		t.Fatalf("the session did not work before the failure: %v %q", err, buf)
	}

	// kill the node the agent is on: the first one in its list
	killedAt := time.Now()
	w.ens[0].proc.Process.Kill()
	w.ens[0].proc.Wait()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	for {
		c.Write([]byte("after"))
		if _, err := c.Read(buf); err != nil {
			break // the established session ended, as it must when its node dies
		}
		if time.Since(killedAt) > 20*time.Second {
			t.Fatal("the session survived its node being killed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	eventually(t, "new sessions through the other node", 40*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "second") })
	t.Logf("REAL-PA-004: new sessions worked %v after the node was killed (target in NFR-011: no outage for new sessions)", time.Since(killedAt).Round(100*time.Millisecond))
	via2 := false
	for _, d := range w.decisions() {
		if d["en"] == "en2" && d["kind"] == "private" && d["action"] == "allow" && d["app"] == "erp" {
			via2 = true
		}
	}
	if !via2 {
		t.Fatal("the other node has no allow record: the sessions did not go through it")
	}

	// the killed node returns with its stored identity and takes connections again
	w.runEN(w.ens[0], false)
	conn, err := net.DialTimeout("tcp", w.ens[0].brokerAddr(w), 3*time.Second)
	if err != nil {
		t.Fatalf("the restarted node does not accept connections: %v", err)
	}
	conn.Close()
	steady(t, a, 30*time.Second, 3)
}

// REAL-PA-007 (NFR-012, NFR-011): the network between the cluster and the enforcement node is cut,
// for real, with a packet filter rule on the node. Access fails closed, and returns by itself when
// the cut ends. The rule is scoped to the cluster node's address and this run's enforcement node
// port, and is removed even if the test fails.
func TestRealPA007NetworkCutFailsClosedAndRecovers(t *testing.T) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector("connector")
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 3)
	uid := w.podUID("connector-0")

	ip := strings.TrimSpace(mustSh(t, w.docker+" inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "+w.nodeCtr))
	if net.ParseIP(ip) == nil {
		t.Skipf("cannot find the cluster node's address on the 'kind' docker network (%q): this test needs a kind cluster", ip)
	}
	rule := "INPUT -s " + ip + " -p tcp --dport " + itoa(w.ens[0].broker) + " -j DROP"
	mustSh(t, "sudo iptables -I "+rule)
	removed := false
	remove := func() {
		if !removed {
			removed = true
			sh("sudo iptables -D "+rule, 20*time.Second)
		}
	}
	t.Cleanup(remove)

	cutAt := time.Now()
	eventually(t, "access to stop while the network is cut", 120*time.Second, func() bool { return !echoes(a.socks(), "erp.ztx", "x") })
	t.Logf("REAL-PA-007: access stopped %v after the cut", time.Since(cutAt).Round(time.Second))
	mark := len(w.appClients())
	for i := 0; i < 3; i++ {
		if echoes(a.socks(), "erp.ztx", "cut") {
			t.Fatal("access worked while the network was cut: it must fail closed")
		}
	}
	if n := len(w.appClients()); n != mark {
		t.Fatalf("the app was contacted %d times during the cut", n-mark)
	}

	remove()
	liftedAt := time.Now()
	steady(t, a, 120*time.Second, 3)
	t.Logf("REAL-PA-007: access returned %v after the cut ended", time.Since(liftedAt).Round(time.Second))
	if got := w.podUID("connector-0"); got != uid {
		t.Fatalf("the connector pod was replaced (%s to %s): recovery must not need a restart", uid, got)
	}
	if rc := strings.TrimSpace(w.mustK("get pod connector-0 -n " + w.ns + " -o jsonpath={.status.containerStatuses[0].restartCount}")); rc != "0" {
		t.Fatalf("the connector container restarted %s times", rc)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func mustSh(t *testing.T, line string) string {
	t.Helper()
	out, err := sh(line, 60*time.Second)
	if err != nil {
		t.Fatalf("%s: %v\n%s", line, err, out)
	}
	return out
}
