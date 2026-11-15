//go:build e2e

// End-to-end scenarios that start the real binaries (TEST-PLAN.md T2.6).
package e2e

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tidp "github.com/larytet/zscaler/test/idp"
)

type stack struct {
	t       *testing.T
	dir     string
	bin     string
	idp     *tidp.Server
	admin   *http.Client
	adminU  string
	enrolU  string
	token   string // tenant admin token
	caPEM   []byte
	procs   []*exec.Cmd
	fakeBin string
	echo    net.Listener
	ports   map[string]int
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d never opened", port)
}

func build(t *testing.T) string {
	bin := t.TempDir()
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/...")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func (s *stack) start(name string, env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(s.bin, name), args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.procs = append(s.procs, cmd)
	s.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if s.t.Failed() {
			s.t.Logf("--- %s output ---\n%s", name, buf.String())
		}
	})
	return cmd
}

func (s *stack) api(method, path string, body any, tok string) (int, []byte) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, s.adminU+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	if method == "PUT" && strings.HasPrefix(path, "/v1/policies/") {
		req.Header.Set("If-Match", "0")
	}
	resp, err := s.admin.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func writeFake(t *testing.T, dir, name, out string) {
	script := "#!/bin/sh\ncat <<'EOF'\n" + out + "\nEOF\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newStack(t *testing.T) *stack {
	s := &stack{t: t, dir: t.TempDir(), bin: build(t), ports: map[string]int{}}
	s.idp = tidp.New("cid")
	t.Cleanup(s.idp.Close)

	// private application: a TCP echo server on loopback
	var err error
	s.echo, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.echo.Close() })
	go func() {
		for {
			c, err := s.echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	s.ports["echo"] = s.echo.Addr().(*net.TCPAddr).Port

	// fake posture tools, found through PATH by the real agent probes
	s.fakeBin = filepath.Join(s.dir, "fakebin")
	os.MkdirAll(s.fakeBin, 0o755)
	writeFake(t, s.fakeBin, "lsblk", "disk\npart\ncrypt")
	writeFake(t, s.fakeBin, "ufw", "Status: active")
	writeFake(t, s.fakeBin, "uname", "6.8.0-test")

	for _, n := range []string{"admin", "enrol", "broker", "proxy", "socks", "http", "status"} {
		s.ports[n] = freePort(t)
	}
	cpData := filepath.Join(s.dir, "cp")
	s.start("ztx-cp", []string{"ZTX_BOOTSTRAP_TOKEN=boot"}, "--data", cpData,
		"--admin-listen", fmt.Sprintf("127.0.0.1:%d", s.ports["admin"]),
		"--enrol-listen", fmt.Sprintf("127.0.0.1:%d", s.ports["enrol"]))
	waitPort(t, s.ports["admin"])
	waitPort(t, s.ports["enrol"])
	s.caPEM, err = os.ReadFile(filepath.Join(cpData, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.caPEM)
	s.admin = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	s.adminU = fmt.Sprintf("https://localhost:%d", s.ports["admin"])
	s.enrolU = fmt.Sprintf("https://localhost:%d", s.ports["enrol"])

	// tenant, IdP, segment, safe defaults
	code, b := s.api("POST", "/v1/tenants", map[string]string{"id": "t1", "name": "Acme"}, "boot")
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var o struct {
		AdminToken string `json:"admin_token"`
	}
	json.Unmarshal(b, &o)
	s.token = o.AdminToken
	s.must("PUT", "/v1/idp", map[string]string{"issuer": s.idp.URL, "client_id": "cid"}, s.token)
	s.must("POST", "/v1/segments", map[string]any{"id": "erp", "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": "127.0.0.1", "ports": []int{s.ports["echo"]}}}}, s.token)
	s.must("POST", "/v1/policies/safe-defaults", nil, s.token)

	// enforcement node
	code, b = s.api("POST", "/v1/ens/tokens", map[string]any{"names": []string{"localhost", "127.0.0.1"}}, "boot")
	if code != 200 {
		t.Fatalf("en token: %d %s", code, b)
	}
	var tk struct{ Token string }
	json.Unmarshal(b, &tk)
	cats := filepath.Join(s.dir, "categories.json")
	os.WriteFile(cats, []byte(`{"malware":["evil.test"],"file-sharing-unsanctioned":["share.test"]}`), 0o600)
	s.start("ztx-en", []string{"ZTX_EN_TOKEN=" + tk.Token}, "--cp", s.enrolU, "--cp-ca", filepath.Join(cpData, "ca.pem"),
		"--data", filepath.Join(s.dir, "en"), "--listen", fmt.Sprintf("127.0.0.1:%d", s.ports["broker"]),
		"--proxy-listen", fmt.Sprintf("127.0.0.1:%d", s.ports["proxy"]), "--categories", cats, "--sync-every", "300ms")
	waitPort(t, s.ports["broker"])
	waitPort(t, s.ports["proxy"])

	// connector
	code, b = s.api("POST", "/v1/connectors/tokens", map[string]string{"group": "site1"}, s.token)
	if code != 200 {
		t.Fatalf("connector token: %d %s", code, b)
	}
	json.Unmarshal(b, &tk)
	s.start("ztx-connector", []string{"ZTX_CONNECTOR_TOKEN=" + tk.Token}, "--cp", s.enrolU, "--cp-ca", filepath.Join(cpData, "ca.pem"),
		"--data", filepath.Join(s.dir, "connector"), "--en", fmt.Sprintf("127.0.0.1:%d", s.ports["broker"]), "--en-name", "localhost")
	return s
}

func (s *stack) must(method, path string, body any, tok string) {
	s.t.Helper()
	if code, b := s.api(method, path, body, tok); code != 200 && code != 201 {
		s.t.Fatalf("%s %s failed: %d %s", method, path, code, b)
	}
}

func (s *stack) agentDir() string { return filepath.Join(s.dir, "agent") }

func (s *stack) writeAgentConfig() {
	cfg := map[string]any{
		"tenant": "t1", "issuer": s.idp.URL, "client_id": "cid", "enrol_url": s.enrolU, "enrol_ca_pem": string(s.caPEM),
		"en_addrs": []string{fmt.Sprintf("127.0.0.1:%d", s.ports["broker"])}, "proxy_addrs": []string{fmt.Sprintf("127.0.0.1:%d", s.ports["proxy"])},
		"en_name": "localhost", "socks_addr": fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]),
		"http_addr": fmt.Sprintf("127.0.0.1:%d", s.ports["http"]), "status_addr": fmt.Sprintf("127.0.0.1:%d", s.ports["status"]),
		"apps": map[string]string{"erp.ztx": "erp"},
	}
	b, _ := json.Marshal(cfg)
	os.MkdirAll(s.agentDir(), 0o700)
	os.WriteFile(filepath.Join(s.agentDir(), "config.json"), b, 0o600)
}

func (s *stack) agentEnv() []string {
	return []string{"PATH=" + s.fakeBin + string(os.PathListSeparator) + os.Getenv("PATH")}
}

// enrolAgent runs `ztx-agent enrol --no-browser` and plays the browser.
func (s *stack) enrolAgent() {
	s.writeAgentConfig()
	cmd := exec.Command(filepath.Join(s.bin, "ztx-agent"), "--dir", s.agentDir(), "--no-browser", "enrol")
	cmd.Env = append(os.Environ(), s.agentEnv()...)
	out, _ := cmd.StdoutPipe()
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "http") {
			resp, err := http.Get(line)
			if err != nil {
				s.t.Fatal(err)
			}
			resp.Body.Close()
		}
	}
	if err := cmd.Wait(); err != nil {
		s.t.Fatalf("enrol failed: %v\n%s", err, errb.String())
	}
}

func (s *stack) runAgent() *exec.Cmd {
	cmd := s.start("ztx-agent", s.agentEnv(), "--dir", s.agentDir(), "run")
	waitPort(s.t, s.ports["socks"])
	waitPort(s.t, s.ports["http"])
	return cmd
}

// socksConnect speaks SOCKS5 CONNECT to a domain name.
func socksConnect(addr, host string, port int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		c.Close()
		return nil, err
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	c.Write(append(req, pb[:]...))
	var resp [10]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, err
	}
	if resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks reply %d", resp[1])
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func echoOnce(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo: %v %q", err, buf)
	}
}

func (s *stack) decisions() []map[string]any {
	b, _ := os.ReadFile(filepath.Join(s.dir, "en", "decisions.jsonl"))
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func eventually(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// SCN-001: day one.
func TestScn001DayOne(t *testing.T) {
	start := time.Now()
	s := newStack(t)
	// wait for the connector to be connected and the EN to have synced
	s.enrolAgent()
	s.runAgent()

	var c net.Conn
	eventually(t, "private access to work", 20*time.Second, func() bool {
		var err error
		c, err = socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "erp.ztx", s.ports["echo"])
		return err == nil
	})
	echoOnce(t, c, "hello through the whole stack")
	c.Close()

	// the app name is the only way in: raw IP and unknown names are refused
	if c, err := socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "nope.ztx", 80); err == nil {
		c.Close()
		t.Fatal("unknown app name was served")
	}

	// web: a malware-category host is blocked, with a block page
	req := "GET http://evil.test/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n"
	pc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.ports["http"]))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(pc, req)
	resp, err := http.ReadResponse(bufio.NewReader(pc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	pc.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(body), "malware") {
		t.Fatalf("expected block page, got %d %s", resp.StatusCode, body)
	}

	eventually(t, "decision log entries", 5*time.Second, func() bool {
		var allow, deny, web bool
		for _, d := range s.decisions() {
			switch {
			case d["kind"] == "private" && d["action"] == "allow":
				allow = true
			case d["kind"] == "private" && d["action"] == "deny":
				deny = true
			case d["kind"] == "web" && d["action"] == "deny":
				web = true
			}
		}
		return allow && deny && web
	})
	t.Logf("scripted day-one flow took %v (excludes manual steps)", time.Since(start).Round(time.Second))
}

// SCN-002: leaver.
func TestScn002Leaver(t *testing.T) {
	s := newStack(t)
	s.enrolAgent()
	s.runAgent()
	var c net.Conn
	eventually(t, "private access to work", 20*time.Second, func() bool {
		var err error
		c, err = socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "erp.ztx", s.ports["echo"])
		return err == nil
	})
	echoOnce(t, c, "before")
	s.must("POST", "/v1/users/u1/disable", nil, s.token)
	// the live session must end, within the sync interval plus a margin
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte("x"))
	buf := make([]byte, 1)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
		c.Write([]byte("x"))
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("session survived %v after the user was disabled", time.Since(start))
	}
	c.Close()
	if c2, err := socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "erp.ztx", s.ports["echo"]); err == nil {
		c2.Close()
		t.Fatal("disabled user opened a new session")
	}
	// the audit trail has the change
	code, b := s.api("GET", "/v1/audit", nil, s.token)
	if code != 200 || !strings.Contains(string(b), "user.disable") {
		t.Fatalf("audit lacks user.disable: %d", code)
	}
}

// SCN-004: bad posture.
func TestScn004BadPosture(t *testing.T) {
	s := newStack(t)
	s.enrolAgent()
	agent := s.runAgent()
	eventually(t, "private access to work", 20*time.Second, func() bool {
		c, err := socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "erp.ztx", s.ports["echo"])
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	// disk encryption "turned off": the fake lsblk no longer reports a crypt device
	writeFake(t, s.fakeBin, "lsblk", "disk\npart")
	agent.Process.Kill()
	agent.Wait()
	time.Sleep(500 * time.Millisecond)
	s.runAgent()
	time.Sleep(1 * time.Second)
	if c, err := socksConnect(fmt.Sprintf("127.0.0.1:%d", s.ports["socks"]), "erp.ztx", s.ports["echo"]); err == nil {
		c.Close()
		t.Fatal("device with disk encryption off reached a posture-protected app")
	}
	found := false
	for _, d := range s.decisions() {
		if d["action"] == "deny" && d["kind"] == "private" {
			found = true
		}
	}
	if !found {
		t.Fatal("no deny decision logged")
	}
	// the admin sees a plain-language alert naming the failed check (ALR-003)
	eventually(t, "posture alert", 15*time.Second, func() bool {
		code, b := s.api("GET", "/v1/alerts?open=1", nil, s.token)
		return code == 200 && strings.Contains(string(b), "posture-failed") && strings.Contains(string(b), "disk encryption is off")
	})
}
