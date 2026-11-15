//go:build real

package real

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// appClients returns the addresses the app has logged as clients.
func (w *world) appClients() []string {
	out, _ := w.k("logs deployment/echo -n " + w.ns)
	var ips []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "conn from ") {
			a := strings.TrimPrefix(l, "conn from ")
			if i := strings.LastIndex(a, ":"); i > 0 {
				a = a[:i]
			}
			ips = append(ips, a)
		}
	}
	return ips
}

func (w *world) podIP(selector string) string {
	return strings.TrimSpace(w.mustK("get pod -n " + w.ns + " -l " + selector + " -o jsonpath={.items[0].status.podIP}"))
}

func startPrivateAccess(t *testing.T) (*world, *agentInst) {
	w := newWorld(t)
	w.deployApp("erp")
	w.deployConnector()
	return w, w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
}

// REAL-PA-001 (ZPA-001, ZPA-002, PA-001): a user reaches an app inside the cluster through the
// connector pod, and the app saw only the connector.
func TestRealPA001UserReachesClusterApp(t *testing.T) {
	w, a := startPrivateAccess(t)
	eventually(t, "the app to answer through the platform", 60*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "hello from the laptop") })
	connIP := w.podIP("app=connector")
	clients := w.appClients()
	if len(clients) == 0 {
		t.Fatal("the app logged no client")
	}
	for _, c := range clients {
		if c != connIP {
			t.Fatalf("the app was reached from %s, not only from the connector pod %s: %v", c, connIP, clients)
		}
	}
	// the decision is recorded with the user, the device and the app, and holds no payload
	var found bool
	eventually(t, "the decision record", 15*time.Second, func() bool {
		b := mustRead(t, w.dir+"/en/decisions.jsonl")
		for _, l := range strings.Split(strings.TrimSpace(b), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["app"] == "erp" && m["action"] == "allow" && m["user"] != nil && m["device"] != nil {
				found = true
			}
		}
		return found
	})
	if strings.Contains(mustRead(t, w.dir+"/en/decisions.jsonl"), "hello from the laptop") {
		t.Fatal("payload reached the decision log")
	}
}

// REAL-PA-002 (ZPA-003, PA-007): the app stays dark. Nothing in the cluster exposes it or the
// connector, and the connector pod opens no listening port.
func TestRealPA002AppStaysDark(t *testing.T) {
	w, a := startPrivateAccess(t)
	eventually(t, "access to work", 60*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "x") })
	svc := w.mustK("get svc -n " + w.ns + " -o json")
	var sl struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct {
				Type        string
				ExternalIPs []string `json:"externalIPs"`
				Ports       []struct {
					NodePort int `json:"nodePort"`
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(svc), &sl); err != nil {
		t.Fatal(err)
	}
	if len(sl.Items) != 1 || sl.Items[0].Metadata.Name != "echo" {
		t.Fatalf("expected exactly the app's service, got %s", svc)
	}
	s := sl.Items[0].Spec
	if s.Type != "ClusterIP" || len(s.ExternalIPs) > 0 || s.Ports[0].NodePort != 0 {
		t.Fatalf("the app is exposed outside the cluster: %+v", s)
	}
	if ing := strings.TrimSpace(w.mustK("get ingress -n " + w.ns + " -o name")); ing != "" {
		t.Fatalf("an ingress exists: %s", ing)
	}
	pod := w.mustK("get pod -n " + w.ns + " -l app=connector -o jsonpath={.items[0].spec.containers[*].ports}")
	if strings.TrimSpace(pod) != "" {
		t.Fatalf("the connector pod declares ports: %s", pod)
	}
	// the connector pod is not backed by any service or endpoint slice
	eps, err := w.k("get endpointslices -n " + w.ns + " -o jsonpath='{.items[*].metadata.labels.kubernetes\\.io/service-name}' 2>/dev/null")
	if err != nil || strings.TrimSpace(strings.Trim(eps, "'")) != "echo" {
		t.Fatalf("endpoint slices other than the app's: %q %v", eps, err)
	}
}

// REAL-PA-005 (PA-002, ZPA-020): a user the policy does not allow is refused, and the app is
// not contacted. The refusal is then lifted to show the same user can get in, so the test cannot
// pass by the platform simply being broken.
func TestRealPA005DeniedUserNeverReachesApp(t *testing.T) {
	w, a := startPrivateAccess(t)
	eventually(t, "access to work first", 60*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "x") })
	before := len(w.appClients())
	w.ifMatch = "1"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []any{}})
	eventually(t, "the refusal to take effect", 30*time.Second, func() bool { return !echoes(a.socks(), "erp.ztx", "x") })
	mark := len(w.appClients())
	for i := 0; i < 5; i++ {
		if echoes(a.socks(), "erp.ztx", "denied") {
			t.Fatal("a refused user got through")
		}
	}
	if after := len(w.appClients()); after != mark {
		t.Fatalf("the app was contacted %d times while the user was refused (it had %d before)", after-mark, before)
	}
	w.ifMatch = "2"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []map[string]any{{
		"id": "staff", "priority": 1, "action": "allow", "match": map[string]any{"groups": []string{"all-staff"}, "apps": []string{"erp"}}}}})
	eventually(t, "access to return", 30*time.Second, func() bool { return echoes(a.socks(), "erp.ztx", "back") })
}
