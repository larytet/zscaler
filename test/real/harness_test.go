//go:build real

package real

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
	"sync"
	"testing"
	"time"

	tidp "github.com/larytet/zscaler/test/idp"
)

// This harness starts the service side (control plane, enforcement node, test identity provider)
// as processes on the test node, and puts the customer side (connector and a private app) into the
// cluster, in the run's own namespace. Parts mirror test/e2e on purpose: the same flows, but with the
// connector and the app running in containers.

const bootTok = "q7Zr-real-bootstrap-3f9a1c5e"

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

func freePort(t *testing.T, host string) int {
	l, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitAddr(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never opened", addr)
}

func eventually(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// enInst is one enforcement node process.
type enInst struct {
	name   string
	data   string
	broker int
	proxy  int
	proc   *exec.Cmd
	token  string
}

func (e *enInst) brokerAddr(w *world) string { return fmt.Sprintf("%s:%d", w.hostIP, e.broker) }

// world is one run's complete setup.
type world struct {
	*env
	t       *testing.T
	dir     string
	bin     string
	hostIP  string // address of the node that pods can reach; the service side listens only on it
	idp     *tidp.Server
	admin   *http.Client
	adminU  string
	enrolU  string
	token   string
	caPath  string
	ports   map[string]int
	bufs    map[string]*lockedBuf
	ifMatch string
	fakeBin string
	ens     []*enInst
	connImg string
	echoImg string
	nodeCtr string // the container that is the cluster node (for removing loaded images)
}

func (w *world) start(name string, env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(w.bin, name), args...)
	cmd.Env = append(os.Environ(), env...)
	buf := &lockedBuf{}
	cmd.Stdout, cmd.Stderr = buf, buf
	w.bufs[fmt.Sprintf("%s-%d", name, len(w.bufs))] = buf
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if w.t.Failed() {
			w.t.Logf("--- %s output ---\n%s", name, buf.String())
		}
	})
	return cmd
}

func (w *world) api(method, path string, body any) (int, []byte) {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, w.adminU+path, rd)
	req.Header.Set("Authorization", "Bearer "+w.token)
	if method == "PUT" && strings.HasPrefix(path, "/v1/policies/") {
		req.Header.Set("If-Match", w.ifMatch)
	}
	resp, err := w.admin.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (w *world) must(method, path string, body any) {
	w.t.Helper()
	if code, b := w.api(method, path, body); code != 200 && code != 201 {
		w.t.Fatalf("%s %s: %d %s", method, path, code, b)
	}
}

// hostAddress finds an address of the node that the pods can reach and that is not on the
// network's public side: the gateway of the cluster's docker network when there is one.
func (e *env) hostAddress() string {
	e.t.Helper()
	if out, err := sh(e.docker+` network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}'`, 20*time.Second); err == nil {
		for _, f := range strings.Fields(out) {
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				return f
			}
		}
	}
	out, err := sh("hostname -I", 5*time.Second)
	if err != nil || len(strings.Fields(out)) == 0 {
		e.t.Fatalf("cannot find an address of the node: %v %s", err, out)
	}
	return strings.Fields(out)[0]
}

func (e *env) clusterNodeContainer() string {
	out := strings.TrimSpace(e.mustK("get nodes -o name"))
	return strings.TrimPrefix(strings.Fields(out)[0], "node/")
}

// loadImage builds a one-binary image and makes it available to the cluster. kind clusters get it
// loaded into the node; a registry is used instead when ZTX_TEST_REGISTRY is set.
func (w *world) loadImage(name, binary string) string {
	w.t.Helper()
	dir := filepath.Join(w.dir, "img-"+name)
	os.MkdirAll(dir, 0o755)
	data, err := os.ReadFile(filepath.Join(w.bin, binary))
	if err != nil {
		w.t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, binary), data, 0o755)
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\nCOPY "+binary+" /"+binary+"\nENTRYPOINT [\"/"+binary+"\"]\n"), 0o644)
	img := "ztx-real-" + name + ":" + w.runID
	if out, err := sh(w.docker+" build -q -t "+img+" "+dir, 3*time.Minute); err != nil {
		w.t.Fatalf("docker build: %v\n%s", err, out)
	}
	ref := img
	if reg := os.Getenv("ZTX_TEST_REGISTRY"); reg != "" {
		ref = reg + "/" + img
		if out, err := sh(w.docker+" tag "+img+" "+ref+" && "+w.docker+" push "+ref, 3*time.Minute); err != nil {
			w.t.Fatalf("push to %s: %v\n%s", reg, err, out)
		}
	} else {
		cluster := strings.TrimSuffix(w.nodeCtr, "-control-plane")
		if out, err := sh(getenv("ZTX_TEST_KIND", "sudo kind")+" load docker-image "+img+" --name "+cluster, 5*time.Minute); err != nil {
			w.t.Fatalf("kind load (set ZTX_TEST_REGISTRY if this cluster is not kind): %v\n%s", err, out)
		}
	}
	w.t.Cleanup(func() {
		sh(w.docker+" rmi -f "+img+" "+ref, 60*time.Second)
		if os.Getenv("ZTX_TEST_REGISTRY") == "" {
			// remove the copy loaded into the cluster node, so the run leaves nothing behind
			sh(w.docker+" exec "+w.nodeCtr+" crictl rmi docker.io/library/"+img+" "+img, 60*time.Second)
		}
	})
	return ref
}

// apply creates objects in the run's namespace from a manifest (all objects carry the test label).
func (w *world) apply(manifest string) {
	w.t.Helper()
	f := filepath.Join(w.dir, fmt.Sprintf("m-%d.yaml", time.Now().UnixNano()))
	os.WriteFile(f, []byte(manifest), 0o644)
	w.mustK("apply -n " + w.ns + " -f " + f)
}

const labels = `    app.kubernetes.io/part-of: ztx-real-test`

// newWorld builds the service side on the node and the customer side in the cluster.
func newWorld(t *testing.T) *world { return newWorldN(t, 1) }

// newWorldN builds the service side with n enforcement nodes.
func newWorldN(t *testing.T, n int) *world {
	t.Helper()
	e := newEnv(t)
	bin := os.Getenv("ZTX_BIN")
	if bin == "" {
		t.Skip("ZTX_BIN is not set: run through test/real/run.sh")
	}
	e.namespace()
	dir, err := os.MkdirTemp("", "ztx-real-"+e.runID+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	w := &world{env: e, t: t, dir: dir, bin: bin, ports: map[string]int{}, bufs: map[string]*lockedBuf{}, ifMatch: "0"}
	w.hostIP = e.hostAddress()
	w.nodeCtr = e.clusterNodeContainer()
	w.idp = tidp.New("cid")
	t.Cleanup(w.idp.Close)

	// fake posture tools for the agent's probes, as in the single-machine e2e: the posture of this
	// test node is not what is being tested here
	w.fakeBin = filepath.Join(dir, "fakebin")
	os.MkdirAll(w.fakeBin, 0o755)
	for n, out := range map[string]string{"lsblk": "disk\npart\ncrypt", "ufw": "Status: active", "uname": "6.8.0-test"} {
		os.WriteFile(filepath.Join(w.fakeBin, n), []byte("#!/bin/sh\ncat <<'EOF'\n"+out+"\nEOF\n"), 0o755)
	}

	w.ports["enrol"] = freePort(t, w.hostIP)
	w.ports["admin"] = freePort(t, "127.0.0.1")
	cpData := filepath.Join(dir, "cp")
	w.start("ztx-cp", []string{"ZTX_BOOTSTRAP_TOKEN=" + bootTok}, "--data", cpData,
		"--admin-listen", fmt.Sprintf("127.0.0.1:%d", w.ports["admin"]),
		"--enrol-listen", fmt.Sprintf("%s:%d", w.hostIP, w.ports["enrol"]),
		"--names", "localhost,127.0.0.1,"+w.hostIP)
	waitAddr(t, fmt.Sprintf("127.0.0.1:%d", w.ports["admin"]))
	waitAddr(t, fmt.Sprintf("%s:%d", w.hostIP, w.ports["enrol"]))
	w.caPath = filepath.Join(cpData, "ca.pem")
	caPEM, err := os.ReadFile(w.caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	w.admin = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	w.adminU = fmt.Sprintf("https://localhost:%d", w.ports["admin"])
	w.enrolU = fmt.Sprintf("https://%s:%d", w.hostIP, w.ports["enrol"])

	// tenant, identity provider, safe defaults
	req, _ := http.NewRequest("POST", w.adminU+"/v1/tenants", strings.NewReader(`{"id":"t1","name":"Acme"}`))
	req.Header.Set("Authorization", "Bearer "+bootTok)
	resp, err := w.admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("tenant: %d %s", resp.StatusCode, b)
	}
	var o struct {
		AdminToken string `json:"admin_token"`
	}
	json.Unmarshal(b, &o)
	w.token = o.AdminToken
	w.must("PUT", "/v1/idp", map[string]string{"issuer": w.idp.URL, "client_id": "cid"})

	// enforcement nodes, listening only on the cluster-facing address
	for i := 1; i <= n; i++ {
		w.startEN(i)
	}
	t.Cleanup(func() {
		if t.Failed() {
			lines := strings.Split(strings.TrimSpace(w.allDecisionsRaw()), "\n")
			if len(lines) > 12 {
				lines = lines[len(lines)-12:]
			}
			t.Logf("--- last decisions ---\n%s", strings.Join(lines, "\n"))
		}
	})
	// customer side: images, the app, and the connector as a pod
	w.connImg = w.loadImage("connector", "ztx-connector")
	w.echoImg = w.loadImage("echo", "echoapp")
	return w
}

// deployApp runs the echo app in the cluster and registers it as segment `id`, reached by its
// service name. It returns the in-cluster host name of the app.
func (w *world) deployApp(id string) string {
	w.t.Helper()
	w.apply(fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  labels:
%s
spec:
  replicas: 1
  selector:
    matchLabels: {app: echo}
  template:
    metadata:
      labels: {app: echo}
    spec:
      containers:
      - name: echo
        image: %s
        imagePullPolicy: IfNotPresent
        args: ["--listen", ":7000"]
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 200m, memory: 64Mi}}
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  labels:
%s
spec:
  selector: {app: echo}
  ports: [{port: 7000, targetPort: 7000}]
`, labels, w.echoImg, labels))
	w.mustK("rollout status deployment/echo -n " + w.ns + " --timeout=120s")
	host := "echo." + w.ns + ".svc.cluster.local"
	w.must("POST", "/v1/segments", map[string]any{"id": id, "group": "site1", "class": "standard",
		"targets": []map[string]any{{"host": host, "ports": []int{7000}}}})
	w.must("POST", "/v1/policies/safe-defaults", nil) // after the segment exists: its rules name the segments that are there
	return host
}

// deployConnector runs a connector as a pod, as a StatefulSet so that its enrolled identity (kept on a
// volume) survives the pod being deleted and recreated: the enrolment token is one-time. Several
// connectors of the same group give redundancy. Every enforcement node is listed.
func (w *world) deployConnector(name string) {
	w.t.Helper()
	code, b := w.api("POST", "/v1/connectors/tokens", map[string]string{"group": "site1"})
	var tk struct{ Token string }
	json.Unmarshal(b, &tk)
	if code != 200 || tk.Token == "" {
		w.t.Fatalf("connector token: %d %s", code, b)
	}
	caPEM, _ := os.ReadFile(w.caPath)
	w.apply(fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %[1]s-token
  labels:
%[2]s
stringData:
  token: %[3]q
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-ca
  labels:
%[2]s
data:
  ca.pem: |
%[4]s
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[1]s
  labels:
%[2]s
spec:
  serviceName: %[1]s
  replicas: 1
  selector:
    matchLabels: {app: %[1]s}
  template:
    metadata:
      labels: {app: %[1]s}
    spec:
      containers:
      - name: connector
        image: %[5]s
        imagePullPolicy: IfNotPresent
        args: ["--cp", %[6]q, "--cp-ca", "/conf/ca.pem", "--data", "/data", "--en", %[7]q, "--en-name", %[8]q, "--targets-every", "3s", "--name", %[1]q]
        env:
        - name: ZTX_CONNECTOR_TOKEN
          valueFrom: {secretKeyRef: {name: %[1]s-token, key: token}}
        volumeMounts:
        - {name: conf, mountPath: /conf}
        - {name: data, mountPath: /data}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 200m, memory: 128Mi}}
      volumes:
      - name: conf
        configMap: {name: platform-ca}
  volumeClaimTemplates:
  - metadata:
      name: data
      labels:
        app.kubernetes.io/part-of: ztx-real-test
    spec:
      accessModes: ["ReadWriteOnce"]
      resources: {requests: {storage: 16Mi}}
`, name, labels, tk.Token, indent(string(caPEM), "    "), w.connImg, w.enrolU, strings.Join(w.brokerAddrs(), ","), w.hostIP))
	w.mustK("rollout status statefulset/" + name + " -n " + w.ns + " --timeout=180s")
	w.t.Cleanup(func() { // runs before the namespace is deleted: show what the pods said when a test failed
		if w.t.Failed() {
			out, _ := w.k("logs statefulset/" + name + " -n " + w.ns + " --tail=30")
			w.t.Logf("--- %s pod log ---\n%s", name, out)
			out, _ = w.k("get pods -n " + w.ns + " -o wide")
			w.t.Logf("--- pods ---\n%s", out)
		}
	})
}

func indent(s, pre string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pre + lines[i]
	}
	return strings.Join(lines, "\n")
}

// agentInst is one laptop: an agent process with its own directory and local ports.
type agentInst struct {
	dir   string
	ports map[string]int
}

func (a *agentInst) socks() string { return fmt.Sprintf("127.0.0.1:%d", a.ports["socks"]) }

func (w *world) newAgent(name string, apps map[string]string) *agentInst {
	t := w.t
	a := &agentInst{dir: filepath.Join(w.dir, name), ports: map[string]int{}}
	for _, n := range []string{"socks", "http", "status"} {
		a.ports[n] = freePort(t, "127.0.0.1")
	}
	cfg := map[string]any{
		"tenant": "t1", "issuer": w.idp.URL, "client_id": "cid", "enrol_url": w.enrolU, "enrol_ca_pem": mustRead(t, w.caPath),
		"en_addrs": w.brokerAddrs(), "proxy_addrs": w.proxyAddrs(),
		"en_name": w.hostIP, "socks_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["socks"]),
		"http_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["http"]), "status_addr": fmt.Sprintf("127.0.0.1:%d", a.ports["status"]),
		"apps": apps, "posture_every_seconds": 1,
	}
	b, _ := json.Marshal(cfg)
	os.MkdirAll(a.dir, 0o700)
	os.WriteFile(filepath.Join(a.dir, "config.json"), b, 0o600)
	env := []string{"PATH=" + w.fakeBin + string(os.PathListSeparator) + os.Getenv("PATH")}
	cmd := exec.Command(filepath.Join(w.bin, "ztx-agent"), "--dir", a.dir, "--no-browser", "enrol")
	cmd.Env = append(os.Environ(), env...)
	out, _ := cmd.StdoutPipe()
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() { // the test plays the browser: it opens the sign-in URL the agent prints
		if line := sc.Text(); strings.HasPrefix(line, "http") {
			if resp, err := http.Get(line); err == nil {
				resp.Body.Close()
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("enrol %s: %v\n%s", name, err, errb.String())
	}
	w.start("ztx-agent", env, "--dir", a.dir, "run")
	waitAddr(t, a.socks())
	return a
}

func mustRead(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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

// echoes reports whether a round trip through the platform to the app works.
func echoes(socks, host string, msg string) bool {
	c, err := socksConnect(socks, host, 7000)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(c, buf)
	return err == nil && string(buf) == msg
}

// startEN enrols and starts enforcement node number i (names en1, en2, ...).
func (w *world) startEN(i int) *enInst {
	t := w.t
	e := &enInst{name: fmt.Sprintf("en%d", i), broker: freePort(t, w.hostIP), proxy: freePort(t, w.hostIP)}
	e.data = filepath.Join(w.dir, e.name)
	req, _ := http.NewRequest("POST", w.adminU+"/v1/ens/tokens", strings.NewReader(fmt.Sprintf(`{"names":["localhost","127.0.0.1","%s"]}`, w.hostIP)))
	req.Header.Set("Authorization", "Bearer "+bootTok)
	resp, err := w.admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var tk struct{ Token string }
	json.Unmarshal(b, &tk)
	if tk.Token == "" {
		t.Fatalf("en token: %s", b)
	}
	e.token = tk.Token
	w.ens = append(w.ens, e)
	w.runEN(e, true)
	return e
}

// runEN starts (or restarts, with the stored identity and no token) an enforcement node.
func (w *world) runEN(e *enInst, first bool) {
	var env []string
	if first {
		env = []string{"ZTX_EN_TOKEN=" + e.token}
	}
	e.proc = w.start("ztx-en", env, "--name", e.name, "--cp", w.enrolU, "--cp-ca", w.caPath, "--data", e.data,
		"--listen", e.brokerAddr(w), "--proxy-listen", fmt.Sprintf("%s:%d", w.hostIP, e.proxy), "--sync-every", "500ms")
	waitAddr(w.t, e.brokerAddr(w))
}

func (w *world) brokerAddrs() []string {
	var out []string
	for _, e := range w.ens {
		out = append(out, e.brokerAddr(w))
	}
	return out
}

func (w *world) proxyAddrs() []string {
	var out []string
	for _, e := range w.ens {
		out = append(out, fmt.Sprintf("%s:%d", w.hostIP, e.proxy))
	}
	return out
}

// allDecisionsRaw returns the decision logs of every enforcement node, one after the other.
func (w *world) allDecisionsRaw() string {
	var sb strings.Builder
	for _, e := range w.ens {
		b, _ := os.ReadFile(filepath.Join(e.data, "decisions.jsonl"))
		sb.Write(b)
		sb.WriteString("\n")
	}
	return sb.String()
}

// decisions returns every decision record of every enforcement node.
func (w *world) decisions() []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(w.allDecisionsRaw(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}
