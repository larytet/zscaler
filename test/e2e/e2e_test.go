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
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tidp "github.com/larytet/zscaler/test/idp"
)

const bootTok = "q7Zr-bootstrap-3f9a1c5e8b2d"

// lockedBuf is a bytes.Buffer that is safe to read while a process is still writing.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type stack struct {
	t        *testing.T
	dir      string
	bin      string
	idp      *tidp.Server
	admin    *http.Client
	adminU   string
	enrolU   string
	token    string // tenant admin token
	caPEM    []byte
	procs    []*exec.Cmd
	fakeBin  string
	echo     net.Listener
	ports    map[string]int
	enArgs   []string
	enProc   *exec.Cmd
	bufs     map[string]*lockedBuf
	secrets  []string
	ifMatch  string // If-Match for policy PUTs, default "0"
	connArgs []string
	connProc *exec.Cmd
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
	buf := &lockedBuf{}
	cmd.Stdout, cmd.Stderr = buf, buf
	s.bufs[name+fmt.Sprint(len(s.procs))] = buf
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
		req.Header.Set("If-Match", s.ifMatch)
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
	s := &stack{t: t, dir: t.TempDir(), bin: build(t), ports: map[string]int{}, ifMatch: "0", bufs: map[string]*lockedBuf{}}
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
	s.start("ztx-cp", []string{"ZTX_BOOTSTRAP_TOKEN=" + bootTok}, "--data", cpData,
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
	code, b := s.api("POST", "/v1/tenants", map[string]string{"id": "t1", "name": "Acme"}, bootTok)
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var o struct {
		AdminToken string `json:"admin_token"`
	}
	json.Unmarshal(b, &o)
	s.token = o.AdminToken
	s.secrets = append(s.secrets, bootTok, o.AdminToken)
	s.must("PUT", "/v1/idp", map[string]string{"issuer": s.idp.URL, "client_id": "cid"}, s.token)
	s.must("POST", "/v1/segments", map[string]any{"id": "erp", "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": "127.0.0.1", "ports": []int{s.ports["echo"]}}}}, s.token)
	s.must("POST", "/v1/segments", map[string]any{"id": "wiki", "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": "127.0.0.1", "ports": []int{s.ports["echo"]}}}}, s.token)
	s.must("POST", "/v1/policies/safe-defaults", nil, s.token)

	// enforcement node
	code, b = s.api("POST", "/v1/ens/tokens", map[string]any{"names": []string{"localhost", "127.0.0.1"}}, bootTok)
	if code != 200 {
		t.Fatalf("en token: %d %s", code, b)
	}
	var tk struct{ Token string }
	json.Unmarshal(b, &tk)
	s.secrets = append(s.secrets, tk.Token)
	cats := filepath.Join(s.dir, "categories.json")
	os.WriteFile(cats, []byte(`{"malware":["evil.test"],"file-sharing-unsanctioned":["share.test"]}`), 0o600)
	s.enArgs = []string{"--cp", s.enrolU, "--cp-ca", filepath.Join(cpData, "ca.pem"),
		"--data", filepath.Join(s.dir, "en"), "--listen", fmt.Sprintf("127.0.0.1:%d", s.ports["broker"]),
		"--proxy-listen", fmt.Sprintf("127.0.0.1:%d", s.ports["proxy"]), "--categories", cats, "--sync-every", "300ms"}
	s.enProc = s.start("ztx-en", []string{"ZTX_EN_TOKEN=" + tk.Token}, s.enArgs...)
	waitPort(t, s.ports["broker"])
	waitPort(t, s.ports["proxy"])

	// connector
	code, b = s.api("POST", "/v1/connectors/tokens", map[string]string{"group": "site1"}, s.token)
	if code != 200 {
		t.Fatalf("connector token: %d %s", code, b)
	}
	json.Unmarshal(b, &tk)
	s.secrets = append(s.secrets, tk.Token)
	s.connArgs = []string{"--cp", s.enrolU, "--cp-ca", filepath.Join(cpData, "ca.pem"),
		"--data", filepath.Join(s.dir, "connector"), "--en", fmt.Sprintf("127.0.0.1:%d", s.ports["broker"]), "--en-name", "localhost", "--targets-every", "500ms"}
	s.connProc = s.start("ztx-connector", []string{"ZTX_CONNECTOR_TOKEN=" + tk.Token}, s.connArgs...)
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
		"apps": map[string]string{"erp.ztx": "erp", "wiki.ztx": "wiki"}, "posture_every_seconds": 1,
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

// PERF-004: connector idle memory under 30 MB (resident set of the real process).
func TestPerf004ConnectorIdleMemory(t *testing.T) {
	s := newStack(t)
	var pid int
	for _, p := range s.procs {
		if strings.HasSuffix(p.Path, "ztx-connector") {
			pid = p.Process.Pid
		}
	}
	if pid == 0 {
		t.Fatal("connector process not found")
	}
	time.Sleep(10 * time.Second)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Skip("no /proc on this platform")
	}
	var kb int
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			fmt.Sscanf(strings.TrimPrefix(l, "VmRSS:"), "%d", &kb)
		}
	}
	t.Logf("PERF-004 connector RSS after 10 s idle: %.1f MB (target < 30 MB)", float64(kb)/1024)
	if kb > 30*1024 {
		t.Errorf("PERF-004 missed: %d kB", kb)
	}
}

// RES-001: the enforcement node dies and comes back; connector and agent recover on their own.
func TestRes001ENRestart(t *testing.T) {
	s := newStack(t)
	s.enrolAgent()
	s.runAgent()
	socks := fmt.Sprintf("127.0.0.1:%d", s.ports["socks"])
	var c net.Conn
	eventually(t, "private access to work", 20*time.Second, func() bool {
		var err error
		c, err = socksConnect(socks, "erp.ztx", s.ports["echo"])
		return err == nil
	})
	echoOnce(t, c, "before")

	s.enProc.Process.Kill()
	s.enProc.Wait()
	// the live session breaks
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte("x"))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("session survived the EN dying")
	}
	c.Close()
	start := time.Now()
	// restart with the stored identity: no token needed
	s.enProc = s.start("ztx-en", nil, s.enArgs...)
	waitPort(t, s.ports["broker"])
	eventually(t, "access after restart", 30*time.Second, func() bool {
		c2, err := socksConnect(socks, "erp.ztx", s.ports["echo"])
		if err != nil {
			return false
		}
		defer c2.Close()
		c2.SetDeadline(time.Now().Add(5 * time.Second))
		c2.Write([]byte("ok"))
		b := make([]byte, 2)
		_, err = io.ReadFull(c2, b)
		return err == nil && string(b) == "ok"
	})
	t.Logf("RES-001 recovered %v after the EN was restarted (target within 30 s)", time.Since(start).Round(100*time.Millisecond))
}

// A second agent on the same machine, with its own directory and local ports.
type agentInst struct {
	dir   string
	ports map[string]int
}

func (s *stack) newAgent(t *testing.T, name string) *agentInst {
	a := &agentInst{dir: filepath.Join(s.dir, name), ports: map[string]int{}}
	for _, n := range []string{"socks", "http", "status"} {
		a.ports[n] = freePort(t)
	}
	cfg := map[string]any{
		"tenant": "t1", "issuer": s.idp.URL, "client_id": "cid", "enrol_url": s.enrolU, "enrol_ca_pem": string(s.caPEM),
		"en_addrs": []string{fmt.Sprintf("127.0.0.1:%d", s.ports["broker"])}, "proxy_addrs": []string{fmt.Sprintf("127.0.0.1:%d", s.ports["proxy"])},
		"en_name": "localhost", "socks_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["socks"]),
		"http_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["http"]), "status_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["status"]),
		"apps": map[string]string{"erp.ztx": "erp", "wiki.ztx": "wiki"}, "posture_every_seconds": 1,
	}
	b, _ := json.Marshal(cfg)
	os.MkdirAll(a.dir, 0o700)
	os.WriteFile(filepath.Join(a.dir, "config.json"), b, 0o600)
	cmd := exec.Command(filepath.Join(s.bin, "ztx-agent"), "--dir", a.dir, "--no-browser", "enrol")
	cmd.Env = append(os.Environ(), s.agentEnv()...)
	out, _ := cmd.StdoutPipe()
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Start()
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "http") {
			if resp, err := http.Get(line); err == nil {
				resp.Body.Close()
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("enrol %s: %v\n%s", name, err, errb.String())
	}
	return a
}

func (s *stack) runInst(a *agentInst) {
	s.start("ztx-agent", s.agentEnv(), "--dir", a.dir, "run")
	waitPort(s.t, a.ports["socks"])
}

func (a *agentInst) socks() string { return fmt.Sprintf("127.0.0.1:%d", a.ports["socks"]) }

func (s *stack) reachable(addr, app string) bool {
	c, err := socksConnect(addr, app, s.ports["echo"])
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("p"))
	b := make([]byte, 1)
	_, err = io.ReadFull(c, b)
	return err == nil
}

// SCN-003: lost laptop. One device is revoked mid-transfer; the user's other device is unaffected.
func TestScn003LostLaptop(t *testing.T) {
	s := newStack(t)
	laptop := s.newAgent(t, "laptop")
	phone := s.newAgent(t, "phone")
	s.runInst(laptop)
	s.runInst(phone)
	eventually(t, "both devices to reach the app", 20*time.Second, func() bool {
		return s.reachable(laptop.socks(), "erp.ztx") && s.reachable(phone.socks(), "erp.ztx")
	})
	c, err := socksConnect(laptop.socks(), "erp.ztx", s.ports["echo"])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, "transfer in progress")

	// find the laptop's device id: the enrolled devices are listed by the admin API
	code, b := s.api("GET", "/v1/devices", nil, s.token)
	var devs []struct{ ID string }
	json.Unmarshal(b, &devs)
	if code != 200 || len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d: %s", len(devs), b)
	}
	// the laptop's cert names its device id
	certPEM, _ := os.ReadFile(filepath.Join(laptop.dir, "device.crt"))
	blk, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	laptopID := strings.Split(leaf.Subject.CommonName, "/")[2]
	s.must("POST", "/v1/devices/"+laptopID+"/revoke", nil, s.token)

	start := time.Now()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, err := c.Write([]byte("x")); err != nil {
			break
		}
		if _, err := c.Read(make([]byte, 1)); err != nil {
			break
		}
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("transfer survived %v after revocation", d)
	}
	if s.reachable(laptop.socks(), "erp.ztx") {
		t.Fatal("revoked device opened a new session")
	}
	if !s.reachable(phone.socks(), "erp.ztx") {
		t.Fatal("the user's other device was affected")
	}
}

// SCN-005: site outage. The connector dies and returns; the agent resumes without a new login.
func TestScn005SiteOutage(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })

	s.connProc.Process.Kill()
	s.connProc.Wait()
	time.Sleep(1 * time.Second)
	if _, err := socksConnect(a.socks(), "erp.ztx", s.ports["echo"]); err == nil {
		t.Fatal("app reachable with no connector")
	} else if !strings.Contains(err.Error(), "socks reply 4") {
		t.Fatalf("expected 'host unreachable' (4), got %v", err)
	}
	s.connProc = s.start("ztx-connector", nil, s.connArgs...) // stored identity, no token
	eventually(t, "access after the connector returned", 30*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
}

// SCN-006: contractor. A group that may reach one app only.
func TestScn006Contractor(t *testing.T) {
	s := newStack(t)
	s.idp.Groups = []string{"contractors"}
	s.ifMatch = "1" // safe-defaults created version 1
	policy := map[string]any{"default_action": "deny", "rules": []map[string]any{{
		"id": "contractor-erp", "priority": 10, "action": "allow", "reason": "contractors reach the ERP only",
		"match": map[string]any{"groups": []string{"contractors"}, "apps": []string{"erp"},
			"posture": map[string]any{"disk_encrypted": true, "firewall_on": true, "max_age_seconds": 3600}}}}}
	s.must("PUT", "/v1/policies/private", policy, s.token)
	a := s.newAgent(t, "contractor")
	s.runInst(a)
	eventually(t, "the allowed app", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
	if s.reachable(a.socks(), "wiki.ztx") {
		t.Fatal("contractor reached an app outside the rule")
	}
	// the safe-default web policy still applies to the contractor
	pc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", a.ports["http"]))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	io.WriteString(pc, "GET http://evil.test/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(pc), nil)
	if err != nil || resp.StatusCode != 403 {
		t.Fatalf("web block for contractor: %v %v", resp, err)
	}
}

// CP-007: a policy change reaches the enforcement node and takes effect on new sessions.
func TestCp007PolicyChangePropagates(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
	// version 1 came from safe-defaults; replace it with a policy that allows nobody
	s.ifMatch = "1"
	s.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []any{}}, s.token)
	start := time.Now()
	eventually(t, "the new policy to take effect", 10*time.Second, func() bool { return !s.reachable(a.socks(), "erp.ztx") })
	t.Logf("CP-007 policy change took effect after %v (sync interval 300 ms)", time.Since(start).Round(100*time.Millisecond))
	found := false
	for _, d := range s.decisions() {
		if d["policy_version"] == float64(2) && d["action"] == "deny" {
			found = true
		}
	}
	if !found {
		t.Fatal("decision log does not show the new policy version")
	}
}

// CP-008: the control plane goes away; live sessions and new decisions continue from the EN's cache.
func TestCp008ControlPlaneDown(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
	c, err := socksConnect(a.socks(), "erp.ztx", s.ports["echo"])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, "before")
	s.procs[0].Process.Kill() // ztx-cp is the first process started
	s.procs[0].Wait()
	time.Sleep(2 * time.Second) // several failed sync attempts
	echoOnce(t, c, "established session still works")
	if !s.reachable(a.socks(), "erp.ztx") {
		t.Fatal("new sessions were refused while the control plane was down (cached policy should apply)")
	}
	if s.reachable(a.socks(), "nope.ztx") {
		t.Fatal("unknown app served")
	}
}

// PA-008: the connector opens no listening port.
func TestPa008ConnectorHasNoListener(t *testing.T) {
	s := newStack(t)
	time.Sleep(2 * time.Second)
	pid := s.connProc.Process.Pid
	inodes := map[string]bool{}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Skip("no /proc on this platform")
	}
	for _, fd := range fds {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fld := strings.Fields(line)
			if len(fld) < 10 {
				continue
			}
			listening := fld[3] == "0A" || strings.HasPrefix(f, "/proc/net/udp") // UDP sockets bound at all are suspect
			if listening && inodes[fld[9]] {
				t.Fatalf("connector has a listening socket (%s, %s)", f, fld[1])
			}
		}
	}
}

// SEC-009: no secret or token appears in any log, output or stored log file.
func TestSec009NoSecretsInLogs(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
	s.must("PUT", "/v1/alert-settings", map[string]any{"emails": []string{"o@example.com"}}, s.token)
	s.api("GET", "/v1/segments", nil, "wrong-token-value-xyz")
	time.Sleep(1500 * time.Millisecond)
	secrets := append([]string{"wrong-token-value-xyz"}, s.secrets...)
	scan := func(name, text string) {
		for _, sec := range secrets {
			if sec != "" && strings.Contains(text, sec) {
				t.Errorf("secret %.6s... found in %s", sec, name)
			}
		}
		if strings.Contains(text, "eyJ") {
			t.Errorf("an ID token (JWT) appears in %s", name)
		}
		if strings.Contains(text, "PRIVATE KEY") {
			t.Errorf("private key material appears in %s", name)
		}
	}
	for n, b := range s.bufs {
		scan("output of "+n, b.String())
	}
	filepath.Walk(s.dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (strings.HasSuffix(p, ".jsonl") || strings.HasSuffix(p, "store.json")) {
			b, _ := os.ReadFile(p)
			scan(p, string(b))
		}
		return nil
	})
}

// AG-013: posture is re-sent on the configured cadence (1 s here; 5 minutes by default).
func TestAg013PostureCadence(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "erp.ztx") })
	time.Sleep(5 * time.Second)
	n := 0
	for _, d := range s.decisions() {
		if d["kind"] == "posture" {
			n++
		}
	}
	if n < 4 {
		t.Fatalf("expected at least 4 posture reports in about 6 seconds at a 1 s cadence, saw %d", n)
	}
}

// PA-016: changing a segment's target reaches the connector's allow-list.
func TestPa016SegmentTargetChange(t *testing.T) {
	s := newStack(t)
	a := s.newAgent(t, "laptop")
	s.runInst(a)
	eventually(t, "access", 20*time.Second, func() bool { return s.reachable(a.socks(), "wiki.ztx") })
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	go func() {
		for {
			c, err := second.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	port2 := second.Addr().(*net.TCPAddr).Port
	s.must("PUT", "/v1/segments/wiki", map[string]any{"id": "wiki", "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": "127.0.0.1", "ports": []int{port2}}}}, s.token)
	reach := func(port int) bool {
		c, err := socksConnect(a.socks(), "wiki.ztx", port)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("p"))
		b := make([]byte, 1)
		_, err = io.ReadFull(c, b)
		return err == nil
	}
	start := time.Now()
	eventually(t, "the new target to work", 30*time.Second, func() bool { return reach(port2) })
	t.Logf("PA-016 new target usable after %v (sync 300 ms, connector refresh 500 ms; default refresh is 30 s)", time.Since(start).Round(100*time.Millisecond))
	if reach(s.ports["echo"]) {
		t.Fatal("the old target is still reachable through the segment")
	}
}
