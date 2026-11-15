package cp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/store"
	"github.com/larytet/zscaler/internal/versions"
)

func certFor(t *testing.T, e *enrolEnv, id pki.Identity) *tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := e.ca.Sign(&k.PublicKey, id, time.Hour, "x.local")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// announce makes a request to the enrolment listener with a certificate and a version header.
func announce(t *testing.T, e *enrolEnv, cert *tls.Certificate, method, path, ver string) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{*cert}}}}
	req, _ := http.NewRequest(method, e.en.URL+path, strings.NewReader("{}"))
	if ver != "\x00" {
		req.Header.Set(versions.Header, ver)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// The control plane lists who runs which version, says who is outside the supported window, and shows each
// tenant only its own connectors and devices (GAP-REQ-08).
func TestVersionListSaysWhoIsOutsideTheSupportedWindow(t *testing.T) { // AGT-046
	e := newEnrolEnv(t)
	e.api.Version, e.api.MinAgentVersion = "1.5.0", "1.4.0"
	en := certFor(t, e, pki.Identity{Tenant: "platform", Subject: "en", Device: "en1", Role: pki.RoleEN})
	en2 := certFor(t, e, pki.Identity{Tenant: "platform", Subject: "en", Device: "en2", Role: pki.RoleEN})
	conA := certFor(t, e, pki.Identity{Tenant: "a", Subject: "connector", Device: "office", Role: pki.RoleConnector})
	conA2 := certFor(t, e, pki.Identity{Tenant: "a", Subject: "connector", Device: "lab", Role: pki.RoleConnector})
	conB := certFor(t, e, pki.Identity{Tenant: "b", Subject: "connector", Device: "other-site", Role: pki.RoleConnector})
	dev := certFor(t, e, pki.Identity{Tenant: "a", Subject: "alice", Device: "d-alice", Role: pki.RoleDevice})
	silent := certFor(t, e, pki.Identity{Tenant: "a", Subject: "bob", Device: "d-bob", Role: pki.RoleDevice})
	announce(t, e, en, "GET", "/sync/state", "1.5.2")
	announce(t, e, en2, "GET", "/sync/state", "1.6.0") // newer than the control plane
	announce(t, e, conA, "GET", "/enrol/targets", "1.4.9")
	announce(t, e, conA2, "GET", "/enrol/targets", "dev") // a source-tree build
	announce(t, e, conB, "GET", "/enrol/targets", "1.0.0")
	announce(t, e, dev, "POST", "/enrol/renew", "1.2.0")                          // too old, and below the minimum agent version
	announce(t, e, silent, "POST", "/enrol/renew", "\x00")                        // announces nothing
	announce(t, e, dev, "POST", "/enrol/renew", "1.2.0<script>alert(1)</script>") // a hostile header changes nothing
	announce(t, e, dev, "POST", "/enrol/renew", strings.Repeat("9", 80))          // too long

	code, body, _ := e.call("GET", "/v1/versions", e.adminA, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var out struct {
		ControlPlane string `json:"control_plane"`
		Counts       map[string]int
		Components   []component
		Warnings     []string
		Supported    string
		UpgradeOrder string `json:"upgrade_order"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]component{}
	for _, c := range out.Components {
		got[c.Role+"/"+c.Name] = c
	}
	want := map[string]string{
		"en/en1": versions.Current, "en/en2": versions.Newer, "connector/office": versions.Behind, "connector/lab": versions.Unknown, "device/d-alice": versions.TooOld,
	}
	for k, st := range want {
		if got[k].Status != st {
			t.Errorf("%s: %+v, want %s", k, got[k], st)
		}
	}
	if _, ok := got["connector/other-site"]; ok {
		t.Error("another tenant's connector is listed")
	}
	if _, ok := got["device/d-bob"]; ok {
		t.Error("a device that announced nothing is listed with a version it never gave")
	}
	if got["device/d-alice"].User != "alice" || got["device/d-alice"].Version != "1.2.0" {
		t.Errorf("hostile or oversized headers replaced the real version: %+v", got["device/d-alice"])
	}
	if out.ControlPlane != "1.5.0" || len(out.Components) != 5 {
		t.Errorf("%+v", out)
	}
	w := strings.Join(out.Warnings, "|")
	for _, need := range []string{"device d-alice is more than one minor version behind", "en en2 is newer than the control plane", "below the minimum agent version (1.4.0)"} {
		if !strings.Contains(w, need) {
			t.Errorf("missing warning %q in %v", need, out.Warnings)
		}
	}
	for _, not := range []string{"connector office", "connector lab", "en en1"} {
		if strings.Contains(w, not) {
			t.Errorf("a supported or unknown component was warned about: %q", w)
		}
	}
	if !strings.Contains(out.Supported, "at most one minor version older") || !strings.Contains(out.UpgradeOrder, "control plane, then enforcement nodes, then connectors, then agents") {
		t.Errorf("the rule is not stated: %+v", out)
	}
	// tenant b sees its own connector and the nodes, not tenant a's things
	_, bb, _ := e.call("GET", "/v1/versions", e.adminB, nil)
	var ob struct{ Components []component }
	json.Unmarshal(bb, &ob)
	names := map[string]bool{}
	for _, c := range ob.Components {
		names[c.Role+"/"+c.Name] = true
	}
	if !names["connector/other-site"] || !names["en/en1"] || names["connector/office"] || names["device/d-alice"] {
		t.Errorf("tenant b sees: %v", names)
	}
	// any role that may read can see it
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("GET", "/v1/versions", viewer, nil); c != 200 {
		t.Errorf("viewer: %d", c)
	}
}
