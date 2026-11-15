// ztx-demo serves the admin console and API over plain HTTP on loopback, seeded with
// sample data, so the console can be looked at and tested in a browser. LAB ONLY: it has
// no TLS, keeps everything in memory, and refuses to listen on anything but loopback.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/logx"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8099", "loopback address to listen on")
	flag.Parse()
	logx.Setup("ztx-demo")
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		logx.Fatal("ztx-demo only listens on a loopback address")
	}
	st, _ := store.Open("")
	tok, _ := st.CreateTenant("demo", "Demo Co")
	viewer, _ := st.AddAdmin("demo", "vera", store.Viewer)
	eng := alerts.New()
	api := &cp.API{Store: st, Tokens: pki.NewTokens(nil, time.Hour), Alerts: eng, Decisions: decisions.New(), Approvals: approvals.New()}

	st.SetIDP("demo", store.IDP{Issuer: "https://idp.example", ClientID: "demo", GroupClaim: "groups"})
	st.PutSegment("demo", broker.Segment{ID: "erp", Group: "office", Class: "standard", Targets: []broker.Target{{Host: "10.0.0.5", Ports: []int{5432}}}})
	st.PutSegment("demo", broker.Segment{ID: "router", Group: "office", Class: "admin", Targets: []broker.Target{{Host: "10.0.0.1", Ports: []int{22, 443}}}})
	for _, u := range []policy.User{
		{Subject: "alice", Email: "alice@example.com", Groups: []string{"all-staff", "finance"}},
		{Subject: "bob", Email: "bob@example.com", Groups: []string{"all-staff"}},
		{Subject: "carol", Email: "carol@example.com", Groups: []string{"all-staff", "admins"}},
		// hostile values: the console must show these as text, never run them
		{Subject: "mallory", Email: `<img src=x onerror="document.title='XSS'">`, Groups: []string{`<script>document.title='XSS'</script>`}},
	} {
		st.UpsertUser("demo", u)
	}
	st.PutDevice("demo", store.Device{ID: "d-alice-1", User: "alice"})
	st.PutDevice("demo", store.Device{ID: "d-bob-1", User: "bob"})
	st.PutDevice("demo", store.Device{ID: "d-lost-1", User: "bob", Revoked: true})
	priv, web := cp.SafeDefaults(mustSegs(st))
	st.PutPolicy("demo", policy.Private, priv, 0)
	st.PutPolicy("demo", policy.Web, web, 0)
	st.SetInspection("demo", true, []string{"bank.example"})
	st.SetRestricted("demo", "bob", true, "phishing report")

	now := time.Now()
	good := &broker.PostureSnap{DiskEncrypted: tru(), FirewallOn: tru()}
	bad := &broker.PostureSnap{DiskEncrypted: fal(), FirewallOn: tru()}
	add := func(r broker.Record) {
		r.Tenant, r.TS = "demo", now.Add(-time.Duration(len(api.Decisions.Since("demo", time.Time{})))*time.Minute)
		api.Decisions.Add(r)
		eng.Ingest(r)
	}
	for i := 0; i < 6; i++ {
		add(broker.Record{Kind: "private", Event: "open", Action: "allow", User: "alice", App: "erp", Rule: "sd-staff", Groups: []string{"finance"}, Posture: good})
	}
	for i := 0; i < 11; i++ {
		add(broker.Record{Kind: "private", Event: "open", Action: "deny", Reason: "default", User: "bob", App: "router", Groups: []string{"all-staff"}, Posture: bad})
	}
	add(broker.Record{Kind: "web", Event: "open", Action: "deny", User: "alice", Target: "evil.test:443", Rule: "sd-bad"})
	add(broker.Record{Kind: "web", Event: "open", Action: "deny", User: "mallory", Target: `<script>alert(1)</script>.test:443`, Rule: "sd-bad", Reason: `"><svg onload=alert(1)>`})
	add(broker.Record{Kind: "private", Event: "open", Action: "deny", Reason: "approval-required", Rule: "jit", User: "alice", App: "router"})
	api.Approvals.Add("demo", "alice", "router", "jit", now.Add(-5*time.Minute))
	api.Approvals.Add("demo", "carol", "erp", "jit", now.Add(-2*time.Minute))
	eng.Ingest(broker.Record{Tenant: "demo", Kind: "posture", Action: "pass", User: "alice", Device: "d-alice-1"})
	eng.Ingest(broker.Record{Tenant: "demo", Kind: "posture", Action: "fail", Reason: "disk encryption is off", User: "alice", Device: "d-alice-1"})
	api.RefreshRisk()

	fmt.Printf("ztx-demo (LAB ONLY, plain HTTP, in memory)\n  console:      http://%s/\n  admin token:  %s\n  viewer token: %s\n", *addr, tok, viewer)
	logx.Die((&http.Server{Addr: *addr, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

func tru() *bool { b := true; return &b }
func fal() *bool { b := false; return &b }

func mustSegs(s *store.Store) []broker.Segment { g, _ := s.Segments("demo"); return g }
