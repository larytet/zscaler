package webproxy

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/tenancy"
)

// headerOrigin answers with the values of the restriction headers it received.
func headerOrigin(t *testing.T, r *rig) *httptest.Server {
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		fmt.Fprintf(w, "tenants=%q context=%q google=%q", q.Header.Get("Restrict-Access-To-Tenants"), q.Header.Get("Restrict-Access-Context"), q.Header.Get("X-GoogApps-Allowed-Domains"))
	}))
	t.Cleanup(o.Close)
	r.exemptAdd(hostport(o.URL))
	r.up.AddCert(o.Certificate())
	return o
}

// tenancyState wraps the rig's state with a tenancy source that restricts one host.
func (s *state) TenancyHeaders(_, host string) (string, []tenancy.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tenancyHost != "" && host == s.tenancyHost {
		return "microsoft", []tenancy.Header{{Name: "Restrict-Access-To-Tenants", Value: "contoso.com"}, {Name: "Restrict-Access-Context", Value: "72f988bf-86f1-41af-91ab-2d7cd011db47"}}
	}
	return "", nil
}

func TestTenancyHeadersAreAddedOnDecryptedSignIn(t *testing.T) { // AGT-024 (DATA-002a)
	r := newRig(t)
	o := headerOrigin(t, r)
	host := strings.Split(hostport(o.URL), ":")[0]
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 3}
	pol.Compile(nil)
	r.st.set(func(s *state) { s.pol = pol; s.tenancyHost = host })

	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	c, br, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	// a request that sends its own, weaker header gets the organisation's value instead
	fmt.Fprintf(c, "GET /login HTTP/1.1\r\nHost: %s\r\nRestrict-Access-To-Tenants: evil.example\r\nRestrict-Access-Context: 00000000-0000-0000-0000-000000000000\r\nContent-Length: 0\r\n\r\n", hostport(o.URL))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b [512]byte
	n, _ := resp.Body.Read(b[:])
	resp.Body.Close()
	got := string(b[:n])
	if !strings.Contains(got, `tenants="contoso.com"`) || !strings.Contains(got, `context="72f988bf-86f1-41af-91ab-2d7cd011db47"`) || strings.Contains(got, "evil.example") {
		t.Fatalf("the origin received %s", got)
	}
	time.Sleep(50 * time.Millisecond)
	if r.find(func(x broker_Record) bool { return x.Reason == "tenancy-restriction:microsoft" && x.Action == "info" }) == nil {
		t.Fatal("the restriction was not recorded")
	}

	// a host that has no restriction is left as it is: nothing is added
	r.st.set(func(s *state) { s.tenancyHost = "somewhere-else.example" })
	c2, br2, err := r.tunnel(t, hostport(o.URL), roots)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c2, "GET /x HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", hostport(o.URL))
	resp, _ = http.ReadResponse(br2, nil)
	n, _ = resp.Body.Read(b[:])
	resp.Body.Close()
	if got := string(b[:n]); !strings.Contains(got, `tenants=""`) {
		t.Fatalf("a host with no restriction got headers: %s", got)
	}
}
