package webproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/larytet/zscaler/internal/dlp"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/store"
)

const apiKey = "sk-live-TOPSECRET-123"

// echoOrigin reports the Authorization header it received, and hands it back in the body and a header.
func echoOrigin(t *testing.T, r *rig) *httptest.Server {
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		a := q.Header.Get("Authorization")
		w.Header().Set("X-Echo", a)
		fmt.Fprintf(w, "auth=%s", a)
	}))
	t.Cleanup(o.Close)
	r.exemptAdd(hostport(o.URL))
	r.up.AddCert(o.Certificate())
	return o
}

func injectRig(t *testing.T, secretHost string, capture bool) (*rig, string, func(method, path string, hdr string) (int, string)) {
	r := newRig(t)
	o := echoOrigin(t, r)
	host := strings.Split(hostport(o.URL), ":")[0]
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Deny, Version: 1, Rules: []policy.Rule{
		{ID: "agent-api", Priority: 1, Action: policy.Allow, Inject: "api", Capture: capture, Match: policy.Match{Domains: []string{host}}},
	}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) {
		s.pol = pol
		s.secrets = map[string]store.Secret{"api": {Name: "api", Host: secretHost, Header: "Authorization", Value: apiKey}}
	})
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	do := func(method, path, hdr string) (int, string) {
		c, br, err := r.tunnel(t, hostport(o.URL), roots)
		if err != nil {
			t.Fatal(err)
		}
		extra := ""
		if hdr != "" {
			extra = "Authorization: " + hdr + "\r\n"
		}
		fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: 0\r\n\r\n", method, path, hostport(o.URL), extra)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b) + "|" + resp.Header.Get("X-Echo")
	}
	return r, host, do
}

func TestInjectAddsTheCredentialAndReplacesTheAgents(t *testing.T) { // AGT-001
	_, _, do := injectRig(t, "127.0.0.1", false)
	code, body := do("GET", "/x", "Bearer agent-made-up")
	if code != 200 || !strings.Contains(body, "|") {
		t.Fatalf("%d %q", code, body)
	}
	// the origin got the real key, but the agent is never shown it: body and header are scrubbed
	if strings.Contains(body, apiKey) {
		t.Fatalf("the credential came back to the agent: %q", body)
	}
	if !strings.HasPrefix(body, "auth=[redacted]|[redacted]") {
		t.Fatalf("expected the origin to have received the injected value (shown redacted): %q", body)
	}
	if strings.Contains(body, "agent-made-up") {
		t.Fatalf("the agent's own header should have been replaced: %q", body)
	}
}

func TestInjectNeverReachesLogsOrCaptures(t *testing.T) { // AGT-004
	r, _, do := injectRig(t, "127.0.0.1", true)
	do("GET", "/x", "")
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	all := fmt.Sprint(r.logs)
	r.mu.Unlock()
	if strings.Contains(all, apiKey) {
		t.Fatal("secret value reached the decision log or a capture")
	}
	if r.find(func(x broker_Record) bool { return x.Reason == "injected:api" }) == nil {
		t.Fatal("the injection was not recorded")
	}
}

func TestInjectIsBoundToItsHost(t *testing.T) { // AGT-002
	r, _, do := injectRig(t, "api.other.example", false)
	code, body := do("GET", "/x", "")
	if code == 200 || strings.Contains(body, apiKey) {
		t.Fatalf("a secret bound to another host must not be used: %d %q", code, body)
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "secret-unavailable" && x.Action == "deny" }) == nil {
		t.Fatal("the refusal was not logged")
	}
}

func TestInjectWithAMissingSecretIsRefused(t *testing.T) { // AGT-003
	r, _, do := injectRig(t, "127.0.0.1", false)
	r.st.set(func(s *state) { s.secrets = nil })
	if code, _ := do("GET", "/x", "Bearer mine"); code == 200 {
		t.Fatal("must not forward the request without its credential")
	}
}

func TestInjectNeedsInspection(t *testing.T) { // AGT-005
	for name, setup := range map[string]func(r *rig, host string){
		"inspection off": func(r *rig, host string) { r.st.set(func(s *state) { s.enabled = false }) },
		"exempt domain":  func(r *rig, host string) { enableInspection(r, host) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			o := echoOrigin(t, r)
			host := strings.Split(hostport(o.URL), ":")[0]
			enableInspection(r)
			pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Deny, Rules: []policy.Rule{
				{ID: "r", Priority: 1, Action: policy.Allow, Inject: "api", Match: policy.Match{Domains: []string{host}}}}}
			if err := pol.Compile(nil); err != nil {
				t.Fatal(err)
			}
			r.st.set(func(s *state) {
				s.pol = pol
				s.secrets = map[string]store.Secret{"api": {Name: "api", Host: host, Header: "Authorization", Value: apiKey}}
			})
			setup(r, host)
			c, err := tls.Dial("tcp", r.addr, r.cli)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport(o.URL), hostport(o.URL))
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil || resp.StatusCode != 403 {
				t.Fatalf("a tunnel that would carry no credential must be refused: %v %v", resp, err)
			}
		})
	}
}

func TestExactDataMatchBlocksListedValuesOnly(t *testing.T) { // AGT-017 (DATA-006)
	r, o, c, br, got := dlpRig(t)
	host := hostport(o.URL)
	salt := []byte("test-salt")
	var hs []string
	for _, v := range []string{"CUST-004711", "jane.doe@example.com"} {
		h, _ := dlp.Hash(salt, v)
		hs = append(hs, h)
	}
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 7, Rules: []policy.Rule{
		{ID: "no-customers", Priority: 1, Action: policy.Deny, Match: policy.Match{DLP: []string{"edm:customers"}}}}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) { s.pol = pol; s.edm = map[string]*dlp.EDM{"customers": dlp.NewEDM(salt, hs)} })
	code, body := get(t, c, br, "POST", host, "/up", `{"id":"CUST-004711","note":"hello"}`)
	if code != 403 || !strings.Contains(body, "edm:customers") || strings.Contains(body, "CUST-004711") {
		t.Fatalf("a listed value was not blocked, or the page echoed it: %d %q", code, body)
	}
	if len(got.get()) != 0 {
		t.Fatal("the origin received the blocked body")
	}
	if code, _ := get(t, c, br, "POST", host, "/up", `{"id":"CUST-004712"}`); code != 200 {
		t.Fatalf("a value that is not on the list must pass: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if strings.Contains(fmt.Sprint(l), "CUST-004711") {
			t.Fatal("the value reached the decision log")
		}
	}
}
