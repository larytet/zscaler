package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/posture"
)

// The workspace browser launcher (requirements v0.6, DESIGN.md D8, slice W1). It does not
// replace the browser: it starts a Chromium-family browser with an isolated profile, makes
// that browser reach everything through this agent's local proxies, and locks the workspace
// (kills the browser, erases the profile) when the device or the credential stops being
// trustworthy. Limits are stated in WB-013: it cannot defend a compromised operating system.

// ErrLocked is returned when the workspace was shut down by policy rather than by the user.
var ErrLocked = errors.New("workspace locked")

type WorkspaceOptions struct {
	Browser  string // path of the Chromium-family browser
	StartURL string // optional first page
	// How often the posture is re-checked and the credential refreshed. Defaults: 90 s and 30 s.
	PostureEvery time.Duration
	RenewEvery   time.Duration
	// Grace is how long the control plane may be unreachable before the workspace locks (default 5 min).
	Grace time.Duration
	// The device baseline. A check that cannot be made counts as failing.
	RequireDisk, RequireFirewall bool
	// Probes override how the device is checked (tests); nil means the real checks.
	Probes *Probes
	// KeepProfile leaves the profile on disk after exit (debugging only).
	KeepProfile bool
	Log         func(string)
}

// workspaceFlags are the only settings the browser is started with.
func workspaceFlags(profile, pacURL, spki string) []string {
	flags := []string{
		"--user-data-dir=" + profile,
		"--proxy-pac-url=" + pacURL,
		"--disable-quic", // nothing may bypass the proxy
		"--disable-features=EncryptedClientHello,DnsOverHttps,Translate,AutofillServerCommunication",
		"--disable-sync",       // no personal account sync
		"--disable-extensions", // WB-005: none until the workspace extension exists (W3)
		"--disable-background-networking",
		"--no-first-run",
		"--no-default-browser-check",
		"--password-store=basic", // do not touch the personal keyring
	}
	if spki != "" {
		// Trust certificates carrying the tenant's inspection key, in THIS browser instance only.
		// The device's own trust store is never changed (WB-003).
		flags = append(flags, "--ignore-certificate-errors-spki-list="+spki)
	}
	return flags
}

// ValidateWorkspaceArgs refuses anything that looks like a browser flag. The user cannot add
// extension, debugging or profile switches to the workspace (WB-005).
func ValidateWorkspaceArgs(args []string) error {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("workspace: %q looks like a browser flag; the workspace does not accept browser flags", a)
		}
		if !strings.HasPrefix(a, "https://") && !strings.HasPrefix(a, "http://") {
			return fmt.Errorf("workspace: %q is not an http or https address", a)
		}
	}
	if len(args) > 1 {
		return errors.New("workspace: at most one start address")
	}
	return nil
}

func (o *WorkspaceOptions) defaults() {
	if o.PostureEvery == 0 {
		o.PostureEvery = 90 * time.Second
	}
	if o.RenewEvery == 0 {
		o.RenewEvery = 30 * time.Second
	}
	if o.Grace == 0 {
		o.Grace = 5 * time.Minute
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
}

func eraseProfile(dir string) error { return os.RemoveAll(dir) }

// RunWorkspace starts the browser and supervises it until it exits, the context ends, or the
// workspace locks. The agent must already be enrolled with EnrolWorkspace.
func (a *Agent) RunWorkspace(ctx context.Context, o WorkspaceOptions) error {
	o.defaults()
	if o.Browser == "" {
		return errors.New("workspace: no browser given")
	}
	if err := a.Load(); err != nil {
		return fmt.Errorf("%w (enrol the workspace first)", err)
	}
	profile := filepath.Join(a.Dir, "workspace-profile")
	eraseProfile(profile) // every start is a clean slate
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}
	cleanup := func() {
		if !o.KeepProfile {
			eraseProfile(profile)
		}
	}
	defer cleanup()

	// local listeners on ephemeral loopback ports; only this browser is pointed at them
	var lns []net.Listener
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}
	a.Cfg.SocksAddr, a.Cfg.HTTPAddr, a.Cfg.StatusAddr = lns[0].Addr().String(), lns[1].Addr().String(), lns[2].Addr().String()
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go a.ServeSOCKS(sctx, lns[0], a.opener())
	go a.ServeHTTPProxy(sctx, lns[1])
	srv := &http.Server{Handler: a.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(lns[2])
	defer srv.Close()

	spki, err := a.InspectionSPKI()
	if err != nil {
		o.Log("could not ask whether inspection is on (continuing without it): " + err.Error())
	}
	args := workspaceFlags(profile, "http://"+a.Cfg.StatusAddr+"/proxy.pac", spki)
	if o.StartURL != "" {
		args = append(args, o.StartURL)
	}
	cmd := exec.Command(o.Browser, args...)
	cmd.Env = os.Environ()
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("workspace: starting the browser: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	o.Log("workspace started")

	lock := func(reason string) error {
		o.Log("workspace locked: " + reason)
		killProcessGroup(cmd)
		<-exited
		cleanup()
		return fmt.Errorf("%w: %s", ErrLocked, reason)
	}
	postureTick := time.NewTicker(o.PostureEvery)
	renewTick := time.NewTicker(o.RenewEvery)
	defer postureTick.Stop()
	defer renewTick.Stop()
	lastOK := time.Now()
	for {
		select {
		case <-ctx.Done():
			killProcessGroup(cmd)
			<-exited
			return ctx.Err()
		case err := <-exited:
			o.Log("browser exited")
			return err
		case <-postureTick.C:
			probes := DefaultProbes()
			if o.Probes != nil {
				probes = *o.Probes
			}
			rep := Collect(probes)
			if bad := belowBaseline(&rep, o); bad != "" {
				return lock("device below the baseline: " + bad)
			}
			if c, err := a.liveConn(); err == nil {
				a.SendPosture(c) // keep the enforcement node's view fresh; best effort
			}
		case <-renewTick.C:
			err := a.Renew()
			switch {
			case err == nil:
				lastOK = time.Now()
			case isRefusal(err):
				return lock("the control plane refused the workspace credential (revoked or disabled)")
			case time.Since(lastOK) > o.Grace:
				return lock("the control plane has been unreachable for longer than the grace period")
			}
		}
	}
}

// belowBaseline applies only the checks the tenant requires. Unknown counts as failing.
func belowBaseline(r *posture.Report, o WorkspaceOptions) string {
	var bad []string
	if o.RequireDisk && (r.DiskEncrypted == nil || !*r.DiskEncrypted) {
		bad = append(bad, "disk encryption is off or could not be checked")
	}
	if o.RequireFirewall && (r.FirewallOn == nil || !*r.FirewallOn) {
		bad = append(bad, "the firewall is off or could not be checked")
	}
	return strings.Join(bad, " and ")
}

// isRefusal is true when the control plane answered and said no (as opposed to being unreachable).
func isRefusal(err error) bool {
	s := err.Error()
	return strings.Contains(s, "control plane said 403") || strings.Contains(s, "control plane said 401")
}
