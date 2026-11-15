package webproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

var peBytes = append([]byte("MZ\x90\x00\x03"), bytes.Repeat([]byte{0}, 200)...)

type fileOrigin struct {
	*httptest.Server
	mu   sync.Mutex
	got  []string
	size map[string]int
}

func newFileOrigin(t *testing.T, r *rig) *fileOrigin {
	o := &fileOrigin{size: map[string]int{}}
	big := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB of text-like data, no signature
	o.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch {
		case strings.HasPrefix(q.URL.Path, "/dl/"):
			switch q.URL.Path {
			case "/dl/setup.exe":
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(peBytes)
			case "/dl/holiday.jpg": // a program under a picture's name and type
				w.Header().Set("Content-Type", "image/jpeg")
				w.Write(peBytes)
			case "/dl/get":
				w.Header().Set("Content-Disposition", `attachment; filename="update.exe"`)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(peBytes)
			case "/dl/report.pdf":
				w.Header().Set("Content-Type", "application/pdf")
				w.Write([]byte("%PDF-1.7 a clean document"))
			case "/dl/big.dat":
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(big)
			default:
				w.Write([]byte("just text"))
			}
		default:
			b, _ := io.ReadAll(q.Body)
			o.mu.Lock()
			o.got = append(o.got, fmt.Sprintf("%s %s %d", q.Method, q.URL.Path, len(b)))
			o.mu.Unlock()
			fmt.Fprintf(w, "stored %d", len(b))
		}
	}))
	t.Cleanup(o.Close)
	r.exemptAdd(hostport(o.URL))
	r.up.AddCert(o.Certificate())
	return o
}

func (o *fileOrigin) received() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.got...)
}

func fileRig(t *testing.T) (*rig, *fileOrigin, string, *x509.CertPool) {
	r := newRig(t)
	o := newFileOrigin(t, r)
	host := hostport(o.URL)
	enableInspection(r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 9, Rules: []policy.Rule{
		{ID: "no-exe-up", Priority: 1, Action: policy.Deny, Match: policy.Match{UploadFileTypes: []string{"executable"}}},
		{ID: "no-exe-down", Priority: 2, Action: policy.Deny, Match: policy.Match{DownloadFileTypes: []string{"executable"}}},
	}}
	if err := pol.Compile(nil); err != nil {
		t.Fatal(err)
	}
	r.st.set(func(s *state) { s.pol = pol })
	roots := x509.NewCertPool()
	roots.AddCert(r.tenCA.Cert)
	return r, o, host, roots
}

func do(t *testing.T, r *rig, roots *x509.CertPool, host, method, path, ctype string, body []byte) (int, string) {
	t.Helper()
	c, br, err := r.tunnel(t, host, roots)
	if err != nil {
		t.Fatal(err)
	}
	extra := ""
	if ctype != "" {
		extra = "Content-Type: " + ctype + "\r\n"
	}
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n", method, path, host, extra, len(body))
	c.Write(body)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

func formWith(files map[string][]byte) (string, []byte) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	w.WriteField("title", "my upload")
	for name, content := range files {
		fw, _ := w.CreateFormFile("file", name)
		fw.Write(content)
	}
	w.Close()
	return w.FormDataContentType(), b.Bytes()
}

func TestUploadsOfBlockedFileTypesNeverReachTheOrigin(t *testing.T) { // AGT-025 (ZIA-013)
	r, o, host, roots := fileRig(t)
	ct, body := formWith(map[string][]byte{"cv.pdf": []byte("%PDF-1.7 fine")})
	if code, _ := do(t, r, roots, host, "POST", "/up", ct, body); code != 200 {
		t.Fatalf("a clean upload must pass: %d", code)
	}
	for name, files := range map[string]map[string][]byte{
		"a program":                 {"tool.exe": peBytes},
		"a program with a pdf":      {"cv.pdf": []byte("%PDF-1.7"), "tool.exe": peBytes},
		"a program named as a jpeg": {"holiday.jpg": peBytes},
	} {
		ct, body := formWith(files)
		if code, page := do(t, r, roots, host, "POST", "/up", ct, body); code != 403 || !strings.Contains(page, "File blocked") || !strings.Contains(page, "executable") {
			t.Errorf("%s: %d %q", name, code, page)
		}
	}
	if code, _ := do(t, r, roots, host, "PUT", "/files/raw", "application/octet-stream", peBytes); code != 403 {
		t.Errorf("a raw upload of a program must be refused: %d", code)
	}
	if code, _ := do(t, r, roots, host, "POST", "/api/items", "application/json", []byte(`{"name":"MZ is just letters"}`)); code != 200 {
		t.Errorf("an ordinary API call must pass: %d", code)
	}
	if got := o.received(); len(got) != 2 {
		t.Fatalf("only the clean upload and the API call may reach the origin: %v", got)
	}
	time.Sleep(50 * time.Millisecond)
	rec := r.find(func(x broker_Record) bool { return x.Rule == "no-exe-up" && x.Action == "deny" })
	if rec == nil || len(rec.FileTypes) == 0 || !contains2(rec.FileTypes, "executable") {
		t.Fatalf("the record must name the kind: %+v", rec)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if strings.Contains(fmt.Sprint(l), "MZ") && !strings.Contains(fmt.Sprint(l), "MZ is") {
			t.Errorf("file content in a record: %s", fmt.Sprint(l))
		}
	}
}

func contains2(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestDownloadsOfBlockedFileTypesAreRefused(t *testing.T) { // AGT-025 (ZIA-013)
	r, _, host, roots := fileRig(t)
	for _, p := range []string{"/dl/setup.exe", "/dl/holiday.jpg", "/dl/get"} { // by name, by signature despite the name, by Content-Disposition
		if code, page := do(t, r, roots, host, "GET", p, "", nil); code != 403 || !strings.Contains(page, "File blocked") {
			t.Errorf("%s was not blocked: %d %q", p, code, page)
		}
	}
	for p, want := range map[string]string{"/dl/report.pdf": "%PDF-1.7 a clean document", "/dl/notes.txt": "just text"} {
		if code, body := do(t, r, roots, host, "GET", p, "", nil); code != 200 || body != want {
			t.Errorf("%s: %d %q", p, code, body)
		}
	}
	// a large download that is not blocked arrives whole and unchanged (only the first bytes are inspected)
	code, body := do(t, r, roots, host, "GET", "/dl/big.dat", "", nil)
	if code != 200 || len(body) != 1<<20 || body[:16] != "0123456789abcdef" || body[len(body)-16:] != "0123456789abcdef" {
		t.Fatalf("the large download was damaged: %d %d bytes", code, len(body))
	}
	time.Sleep(50 * time.Millisecond)
	if rec := r.find(func(x broker_Record) bool {
		return x.Rule == "no-exe-down" && x.Reason == "file-type-download" && len(x.FileTypes) > 0
	}); rec == nil {
		t.Fatal("the refusal was not recorded with the kind")
	}
}

func TestFileTypeRulesDoNothingWithoutInspection(t *testing.T) { // AGT-025
	r := newRig(t)
	o := newFileOrigin(t, r)
	pol := &policy.Policy{Kind: policy.Web, DefaultAction: policy.Allow, Version: 2, Rules: []policy.Rule{
		{ID: "no-exe-down", Priority: 1, Action: policy.Deny, Match: policy.Match{DownloadFileTypes: []string{"executable"}}}}}
	pol.Compile(nil)
	r.st.set(func(s *state) { s.pol = pol })
	// inspection is off: the tunnel is not opened, so the rule cannot see the file and does not match
	c, err := tls.Dial("tcp", r.addr, r.cli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport(o.URL), hostport(o.URL))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("an untouched tunnel is expected when nothing is decrypted: %v %v", resp, err)
	}
}
