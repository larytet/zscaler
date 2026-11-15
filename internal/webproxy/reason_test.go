package webproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

var refRe = regexp.MustCompile(`reference <b>([0-9a-f]{12})</b>`)

func refOf(t *testing.T, page string) string {
	t.Helper()
	m := refRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no reference on the page: %q", page)
	}
	return m[1]
}

func (r *rig) recordWithRef(t *testing.T, ref string) *broker_Record {
	t.Helper()
	var rec *broker_Record
	for i := 0; i < 50 && rec == nil; i++ {
		rec = r.find(func(x broker_Record) bool { return x.Ref == ref })
		time.Sleep(20 * time.Millisecond)
	}
	if rec == nil {
		t.Fatalf("the reference %s on the page is in no decision record: the user would quote a number nobody can find", ref)
	}
	return rec
}

// connectPage opens CONNECT through the proxy and returns the answer's status and body.
func (r *rig) connectPage(t *testing.T, target string) (int, string) {
	t.Helper()
	c, err := tls.Dial("tcp", r.addr, r.cli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 200 { // an open tunnel: there is no body to read, and reading would wait for the connection to end
		return 200, ""
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestReasonTextIsPlainSafeAndFallsBack(t *testing.T) { // AGT-028 (ZIA-014)
	for code := range reasonTexts {
		if txt := reasonText(code, nil); txt == "" || txt == code {
			t.Errorf("code %q has no sentence", code)
		}
	}
	if got := reasonText("Social media is closed in work hours", nil); got != "Social media is closed in work hours" {
		t.Errorf("an admin's reason must be shown as written: %q", got)
	}
	if got := reasonText("", []string{"malware", "phishing"}); !strings.Contains(got, "malware, phishing") {
		t.Errorf("%q", got)
	}
	if got := reasonText("", nil); !strings.Contains(got, "rule") {
		t.Errorf("%q", got)
	}
	// text from an admin or a category is escaped on the page
	var sb strings.Builder
	sb.WriteString(pageTail(`<script>alert(1)</script>`, `<b>x`))
	if strings.Contains(sb.String(), "<script>") || strings.Contains(sb.String(), "<b>x") {
		t.Errorf("the page must escape what it is given: %s", sb.String())
	}
}

func TestEveryBlockPageGivesAReasonAndAReferenceInTheLog(t *testing.T) { // AGT-028 (ZIA-014)
	r := newRig(t)
	o := newFileOrigin(t, r)
	target := hostport(o.URL)
	host := strings.Split(target, ":")[0]
	enableInspection(r)
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	set := func(def policy.Action, rules ...policy.Rule) {
		p := &policy.Policy{Kind: policy.Web, DefaultAction: def, Version: 5, Rules: rules}
		if err := p.Compile(nil); err != nil {
			t.Fatal(err)
		}
		r.st.set(func(s *state) { s.pol = p })
	}

	// no policy at all
	r.st.set(func(s *state) { s.pol = nil })
	code, page := r.connectPage(t, target)
	if code != 403 || !strings.Contains(page, "has not set up a web policy") {
		t.Fatalf("%d %q", code, page)
	}
	if rec := r.recordWithRef(t, refOf(t, page)); rec.Action != "deny" || rec.Reason != "no-policy" {
		t.Fatalf("%+v", rec)
	}

	// the default action
	set(policy.Deny)
	code, page = r.connectPage(t, target)
	if code != 403 || !strings.Contains(page, "no rule that allows this site") {
		t.Fatalf("%d %q", code, page)
	}
	r.recordWithRef(t, refOf(t, page))

	// a rule with the admin's own reason: shown as written, the rule is in the record, the page does not show the rule id
	set(policy.Allow, policy.Rule{ID: "block-this", Priority: 1, Action: policy.Deny, Reason: "Not allowed in work hours <b>", Match: policy.Match{Domains: []string{host}}})
	code, page = r.connectPage(t, target)
	if code != 403 || !strings.Contains(page, "Not allowed in work hours &lt;b&gt;") || strings.Contains(page, "block-this") {
		t.Fatalf("%d %q", code, page)
	}
	if rec := r.recordWithRef(t, refOf(t, page)); rec.Rule != "block-this" || rec.Action != "deny" {
		t.Fatalf("%+v", rec)
	}

	// a warning also has a reference in the log
	set(policy.Allow, policy.Rule{ID: "careful", Priority: 1, Action: policy.Warn, Match: policy.Match{Domains: []string{host}}})
	c, br, err := r.tunnel(t, target, roots)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET /w HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", target)
	resp, _ := http.ReadResponse(br, nil)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "<b>Why:</b>") || strings.Contains(string(b), "()") {
		t.Fatalf("the warning page needs a reason and no empty category: %q", b)
	}
	if rec := r.recordWithRef(t, refOf(t, string(b))); rec.Action != "warn" {
		t.Fatalf("%+v", rec)
	}

	// inspected: a file-type block, a data block, a block by rule; each page has its reason and a reference in the log
	set(policy.Allow,
		policy.Rule{ID: "no-exe-up", Priority: 1, Action: policy.Deny, Reason: "Programs may not be sent out", Match: policy.Match{UploadFileTypes: []string{"executable"}}},
		policy.Rule{ID: "no-card", Priority: 2, Action: policy.Deny, Match: policy.Match{DLP: []string{"credit-card"}}},
		policy.Rule{ID: "no-exe-down", Priority: 3, Action: policy.Deny, Match: policy.Match{DownloadFileTypes: []string{"executable"}}})
	for name, c := range map[string]struct {
		method, path, ctype string
		body                []byte
		want                string
	}{
		"upload of a program":   {"PUT", "/f", "application/octet-stream", peBytes, "Programs may not be sent out"},
		"a card number":         {"POST", "/f", "text/plain", []byte("4111 1111 1111 1111"), "web policy does not allow this"},
		"download of a program": {"GET", "/dl/setup.exe", "", nil, "kind of file to be downloaded"},
	} {
		code, page := do(t, r, roots, target, c.method, c.path, c.ctype, c.body)
		if code != 403 || !strings.Contains(page, "Why:") || !strings.Contains(page, c.want) {
			t.Errorf("%s: %d %q", name, code, page)
			continue
		}
		if rec := r.recordWithRef(t, refOf(t, page)); rec.Action != "deny" {
			t.Errorf("%s: %+v", name, rec)
		}
	}

	// an error of the proxy's own, with a reason and a reference too: a request that names another host inside the tunnel
	c2, br2, err := r.tunnel(t, target, roots)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c2, "GET / HTTP/1.1\r\nHost: another.example\r\nContent-Length: 0\r\n\r\n")
	resp, _ = http.ReadResponse(br2, nil)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 421 || !strings.Contains(string(b), "different site") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if rec := r.recordWithRef(t, refOf(t, string(b))); rec.Reason != "host-mismatch" {
		t.Fatalf("%+v", rec)
	}
}

func TestBlockPageNamesTheCategoriesAndEscapesThem(t *testing.T) { // AGT-028
	w := httptest.NewRecorder()
	blockPage(w, "evil.test", []string{"malware", "<i>x"}, "0123456789ab", reasonText("Known-bad categories", nil))
	body := w.Body.String()
	if w.Code != 403 || !strings.Contains(body, "(category: malware, &lt;i&gt;x)") || !strings.Contains(body, "Known-bad categories") || strings.Contains(body, "<i>x") {
		t.Fatalf("%d %s", w.Code, body)
	}
	w = httptest.NewRecorder()
	blockPage(w, "plain.example", nil, "0123456789ab", reasonText("default", nil))
	if strings.Contains(w.Body.String(), "category") {
		t.Fatalf("no category to name: %s", w.Body.String())
	}
}
