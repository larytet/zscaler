package webproxy

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/cloudapps"
	"github.com/larytet/zscaler/internal/policy"
)

func TestCloudAppControlOnDecryptedAndTunnelledTraffic(t *testing.T) { // AGT-031 (ZIA-011)
	r := newRig(t)
	o := newFileOrigin(t, r)
	target := hostport(o.URL)
	host := strings.Split(target, ":")[0]
	enableInspection(r)
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	// an app of the organisation's own, on the test origin
	app, err := cloudapps.Validate(cloudapps.App{ID: "boxcopy", Name: "Box copy", Domains: []string{host}, Actions: map[string][]cloudapps.Rule{
		"upload": {{Methods: []string{"POST"}, Paths: []string{"/up"}}},
		"post":   {{Methods: []string{"POST"}, Paths: []string{"/msg"}}},
		"share":  {{Methods: []string{"POST"}, Contains: []string{"/share"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) { s.catalog = cloudapps.NewCatalog([]cloudapps.App{app}) })
	set := func(rules ...policy.Rule) {
		p := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 8, Rules: rules}
		if err := p.Compile(nil); err != nil {
			t.Fatal(err)
		}
		r.st.set(func(s *state) { s.pol = p })
	}

	// actions: uploads and shares are refused, a post and plain reads go through
	set(policy.Rule{ID: "no-upload-share", Priority: 1, Action: policy.Deny, Reason: "Files may not be put in outside storage",
		Match: policy.Match{CloudApps: []string{"boxcopy"}, CloudActions: []string{"upload", "share"}}})
	for _, c := range []struct {
		method, path string
		want         int
	}{{"POST", "/up", 403}, {"POST", "/team/share/1", 403}, {"POST", "/msg", 200}, {"GET", "/up", 200}, {"GET", "/dl/report.pdf", 200}} {
		code, body := do(t, r, roots, target, c.method, c.path, "text/plain", []byte("x"))
		if code != c.want {
			t.Errorf("%s %s: %d, want %d (%q)", c.method, c.path, code, c.want, body)
		}
		if c.want == 403 && !strings.Contains(body, "Files may not be put in outside storage") {
			t.Errorf("%s %s: the rule's own reason is not on the page: %q", c.method, c.path, body)
		}
	}
	got := o.received() // the origin records what it was sent outside /dl/: the post and the read of /up arrived, the refused ones did not
	if len(got) != 2 || !strings.Contains(strings.Join(got, "|"), "POST /msg") || !strings.Contains(strings.Join(got, "|"), "GET /up") || strings.Contains(strings.Join(got, "|"), "POST /up") || strings.Contains(strings.Join(got, "|"), "share") {
		t.Fatalf("the refused upload and share must not have reached the origin: %v", got)
	}
	time.Sleep(50 * time.Millisecond)
	if rec := r.find(func(x broker_Record) bool { return x.Rule == "no-upload-share" && x.Action == "deny" }); rec == nil {
		t.Fatal("the refusal must be recorded with its rule")
	}

	// the whole app: a rule with no action is decided when the connection is made, before anything is decrypted
	set(policy.Rule{ID: "no-boxcopy", Priority: 1, Action: policy.Deny, Match: policy.Match{CloudApps: []string{"boxcopy"}}})
	if code, page := r.connectPage(t, target); code != 403 || !strings.Contains(page, "Why:") {
		t.Fatalf("the app as a whole must be refused at the connection: %d %q", code, page)
	}
	// an app the host does not belong to does not match
	set(policy.Rule{ID: "no-dropbox", Priority: 1, Action: policy.Deny, Match: policy.Match{CloudApps: []string{"dropbox"}}})
	if code, _ := do(t, r, roots, target, "POST", "/up", "text/plain", []byte("x")); code != 200 {
		t.Fatalf("a rule about another app must not touch this one: %d", code)
	}
}
