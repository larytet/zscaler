package devenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ca = "-----BEGIN CERTIFICATE-----\nTENANTCA\n-----END CERTIFICATE-----\n"

func TestBuildBundleAppendsTheTenantCAToThePublicRoots(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "roots.crt")
	os.WriteFile(sys, []byte("-----BEGIN CERTIFICATE-----\nPUBLICROOT\n-----END CERTIFICATE-----\n"), 0o600)
	b, used := BuildBundle([]byte(ca), []string{filepath.Join(dir, "missing"), sys})
	if used != sys || !strings.Contains(string(b), "PUBLICROOT") || !strings.HasSuffix(string(b), ca) {
		t.Fatalf("%q used=%s", b, used)
	}
	if strings.Count(string(b), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("expected the public root and the tenant CA, nothing else")
	}
}

func TestBuildBundleWithoutSystemRootsSaysSo(t *testing.T) {
	b, used := BuildBundle([]byte(ca), []string{"/definitely/not/here", t.TempDir()})
	if used != "" || string(b) != ca {
		t.Fatalf("%q %q", b, used)
	}
	notPEM := filepath.Join(t.TempDir(), "x")
	os.WriteFile(notPEM, []byte("not a certificate bundle"), 0o600)
	if _, used := BuildBundle([]byte(ca), []string{notPEM}); used != "" {
		t.Fatal("a file that is not a PEM bundle was used as the public roots")
	}
}

func TestExports(t *testing.T) {
	lines := Exports("/d/ca.pem", "/d/bundle.pem", true, "http://127.0.0.1:3129")
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"export HTTPS_PROXY='http://127.0.0.1:3129'", "export NO_PROXY='localhost,127.0.0.1,::1'",
		"export CURL_CA_BUNDLE='/d/bundle.pem'", "export SSL_CERT_FILE='/d/bundle.pem'", "export REQUESTS_CA_BUNDLE='/d/bundle.pem'",
		"export GIT_SSL_CAINFO='/d/bundle.pem'", "export NODE_EXTRA_CA_CERTS='/d/ca.pem'",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Node only ADDS roots, so it must get the CA alone; replace-the-roots variables must get the bundle
	if strings.Contains(all, "NODE_EXTRA_CA_CERTS='/d/bundle.pem'") || strings.Contains(all, "CURL_CA_BUNDLE='/d/ca.pem'") {
		t.Fatal("the wrong file was given to a variable")
	}
	seen := map[string]int{}
	for _, l := range lines {
		seen[strings.SplitN(l, "=", 2)[0]]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("%s set %d times", k, n)
		}
	}
}

func TestWithoutPublicRootsReplaceVariablesAreNotSet(t *testing.T) {
	all := strings.Join(Exports("/d/ca.pem", "/d/ca.pem", false, "http://127.0.0.1:1"), "\n")
	if strings.Contains(all, "CURL_CA_BUNDLE") || strings.Contains(all, "SSL_CERT_FILE") {
		t.Fatal("pointing a tool at a file with only the tenant CA would break every non-inspected site for it")
	}
	if !strings.Contains(all, "NODE_EXTRA_CA_CERTS='/d/ca.pem'") {
		t.Fatal("additive variables are still safe and useful")
	}
}

func TestShellQuoteResistsInjection(t *testing.T) {
	line := Exports("/d/it's $(touch /tmp/pwned)/ca.pem", "/b", true, "http://p")
	joined := strings.Join(line, "\n")
	if !strings.Contains(joined, `'/d/it'\''s $(touch /tmp/pwned)/ca.pem'`) {
		t.Fatalf("path not quoted safely:\n%s", joined)
	}
}

func TestEveryToolHasANameAndVariablesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range Tools {
		if tl.Name == "" {
			t.Fatal("tool without a name")
		}
		if tl.Var != "" && seen[tl.Var] {
			t.Fatalf("duplicate variable %s", tl.Var)
		}
		seen[tl.Var] = true
	}
	if len(Uncovered) < 3 {
		t.Fatal("what is not covered must be stated")
	}
}
