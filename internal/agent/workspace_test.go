package agent

import (
	"strings"
	"testing"
)

func TestWorkspaceFlagsAreFixedAndSafe(t *testing.T) { // WBT-007
	flags := workspaceFlags("/tmp/profile", "http://127.0.0.1:5000/proxy.pac", "")
	all := strings.Join(flags, " ")
	for _, want := range []string{"--user-data-dir=/tmp/profile", "--proxy-pac-url=http://127.0.0.1:5000/proxy.pac", "--disable-quic", "--disable-sync", "--disable-extensions", "EncryptedClientHello", "DnsOverHttps", "--password-store=basic"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, forbidden := range []string{"remote-debugging", "load-extension", "enable-automation", "disable-web-security", "ignore-certificate-errors", "no-sandbox", "incognito"} {
		if strings.Contains(all, forbidden) {
			t.Errorf("the workspace must not start the browser with %q", forbidden)
		}
	}
	proxyOnce := 0
	for _, f := range flags {
		if strings.HasPrefix(f, "--proxy") {
			proxyOnce++
		}
	}
	if proxyOnce != 1 {
		t.Errorf("expected exactly one proxy setting, got %d", proxyOnce)
	}
}

func TestWorkspaceRefusesBrowserFlags(t *testing.T) { // WBT-008
	for _, bad := range [][]string{
		{"--remote-debugging-port=9222"}, {"--load-extension=/tmp/evil"}, {"--user-data-dir=/home/me/.config/google-chrome"},
		{"-x"}, {"file:///etc/passwd"}, {"javascript:alert(1)"}, {"ftp://x"}, {"https://a.example", "https://b.example"}, {"--proxy-server=direct://"},
	} {
		if err := ValidateWorkspaceArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	for _, ok := range [][]string{nil, {}, {"https://apps.example.com/"}, {"http://intranet.example/"}} {
		if err := ValidateWorkspaceArgs(ok); err != nil {
			t.Errorf("%v refused: %v", ok, err)
		}
	}
}

func TestBelowBaseline(t *testing.T) { // WBT-011: unknown fails
	tr, fa := true, false
	o := WorkspaceOptions{RequireDisk: true, RequireFirewall: true}
	for name, c := range map[string]struct {
		disk, fw *bool
		want     bool
	}{
		"both on":          {&tr, &tr, false},
		"disk off":         {&fa, &tr, true},
		"firewall off":     {&tr, &fa, true},
		"disk unknown":     {nil, &tr, true},
		"firewall unknown": {&tr, nil, true},
		"all unknown":      {nil, nil, true},
	} {
		r := Collect(Probes{OS: "linux", Run: func(string, ...string) (string, error) { return "", nil }})
		r.DiskEncrypted, r.FirewallOn = c.disk, c.fw
		if got := belowBaseline(&r, o) != ""; got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	// a tenant that does not require the firewall is not locked out for lacking one
	r := Collect(Probes{OS: "linux", Run: func(string, ...string) (string, error) { return "", nil }})
	r.DiskEncrypted = &tr
	if belowBaseline(&r, WorkspaceOptions{RequireDisk: true}) != "" {
		t.Error("an unrequired check locked the workspace")
	}
	if belowBaseline(&r, WorkspaceOptions{}) != "" {
		t.Error("with nothing required, nothing should fail")
	}
}

func TestRefusalVersusUnreachable(t *testing.T) {
	if !isRefusal(errString("agent: control plane said 403: {\"code\":\"device_revoked\"}")) || !isRefusal(errString("agent: control plane said 401: x")) {
		t.Fatal("an explicit refusal must lock at once")
	}
	if isRefusal(errString("dial tcp: connection refused")) || isRefusal(errString("agent: control plane said 502: bad gateway")) {
		t.Fatal("an outage is not a refusal: it gets the grace period")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestSPKIFlagOnlyWhenInspectionIsOn(t *testing.T) {
	if strings.Contains(strings.Join(workspaceFlags("/p", "http://x/pac", ""), " "), "spki") {
		t.Fatal("no inspection, no pin")
	}
	with := workspaceFlags("/p", "http://x/pac", "abc123=")
	n := 0
	for _, f := range with {
		if strings.HasPrefix(f, "--ignore-certificate-errors-spki-list=abc123=") {
			n++
		}
		if f == "--ignore-certificate-errors" {
			t.Fatal("the blanket flag turns certificate checking off; only the pin is allowed")
		}
	}
	if n != 1 {
		t.Fatalf("%v", with)
	}
}
