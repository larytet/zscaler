//go:build real

// Package real holds the real-environment tests (TEST-PLAN.md T7). They run ON a Linux test node
// that has Docker, kubectl and a Kubernetes cluster, started by test/real/run.sh. Everything they
// create lives in one namespace named ztx-real-<run id> and is removed at the end.
package real

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const partOfLabel = "app.kubernetes.io/part-of=ztx-real-test"

// env is the test node as the tests see it. Commands are plain shell words so that "sudo kubectl"
// works; nothing here names a particular machine.
type env struct {
	t       *testing.T
	kubectl string
	docker  string
	runID   string
	ns      string
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newRunID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// sh runs a shell command line and returns combined output.
func sh(line string, timeout time.Duration) (string, error) {
	cmd := exec.Command("sh", "-c", line)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		cmd.Process.Kill()
		return out.String(), fmt.Errorf("timed out after %v: %s", timeout, line)
	}
}

func (e *env) k(args string) (string, error) {
	return sh(e.kubectl+" "+args, 60*time.Second)
}

func (e *env) mustK(args string) string {
	e.t.Helper()
	out, err := e.k(args)
	if err != nil {
		e.t.Fatalf("kubectl %s: %v\n%s", args, err, out)
	}
	return out
}

// newEnv checks that a cluster is reachable and skips (with the reason) when it is not: a missing
// prerequisite is the only reason a REAL- test may be skipped (T7.4, rule 7).
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, kubectl: getenv("ZTX_TEST_KUBECTL", "sudo kubectl"), docker: getenv("ZTX_TEST_DOCKER", "sudo docker"), runID: newRunID()}
	if out, err := sh(e.kubectl+" get nodes -o name", 30*time.Second); err != nil || strings.TrimSpace(out) == "" {
		t.Skipf("no Kubernetes cluster reachable with %q (see TEST-PLAN.md T7.2): %v %s", e.kubectl, err, strings.TrimSpace(out))
	}
	e.ns = "ztx-real-" + e.runID
	return e
}

// namespace creates the run's namespace, labelled so the clean command can find leftovers, and
// removes it when the test ends, also on failure. It refuses to reuse an existing one.
func (e *env) namespace() {
	e.t.Helper()
	if out, err := e.k("get namespace " + e.ns + " -o name"); err == nil && strings.TrimSpace(out) != "" {
		e.t.Fatalf("namespace %s already exists; refusing to use it", e.ns)
	}
	e.mustK("create namespace " + e.ns)
	e.mustK("label namespace " + e.ns + " " + partOfLabel)
	e.t.Cleanup(func() {
		out, err := e.k("delete namespace " + e.ns + " --wait=true --timeout=120s")
		if err != nil {
			e.t.Errorf("clean-up of namespace %s failed: %v\n%s", e.ns, err, out)
		}
	})
}

// REAL-ENV-001 (T7.2, T7.4): the node has what the suite needs, and the isolated namespace can be
// created and removed.
func TestRealENV001Prerequisites(t *testing.T) {
	e := newEnv(t)
	for _, tool := range []string{"rsync", "curl", "python3"} {
		if out, err := sh("command -v "+tool, 10*time.Second); err != nil {
			t.Errorf("tool %s is missing on the node: %s", tool, out)
		}
	}
	if out, err := sh(e.docker+" info --format '{{.ServerVersion}}'", 30*time.Second); err != nil {
		t.Errorf("docker is not usable with %q: %v %s", e.docker, err, out)
	} else {
		t.Logf("docker server %s", strings.TrimSpace(out))
	}
	t.Logf("cluster nodes: %s", strings.Fields(strings.ReplaceAll(e.mustK("get nodes -o name"), "\n", " ")))
	if out, err := sh("nproc", 5*time.Second); err == nil {
		t.Logf("cores: %s", strings.TrimSpace(out))
	}
	// the account running the tests may only touch its own namespace: check that creating and
	// removing one works, and that nothing is left
	e.namespace()
	out := e.mustK("get namespace -l " + partOfLabel + " -o name")
	if !strings.Contains(out, e.ns) {
		t.Fatalf("labelled namespace not found: %q", out)
	}
	if got := e.mustK("get pods -n " + e.ns + " -o name"); strings.TrimSpace(got) != "" {
		t.Fatalf("a fresh namespace should be empty: %q", got)
	}
}
