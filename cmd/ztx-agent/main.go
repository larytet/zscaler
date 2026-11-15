// ztx-agent is the endpoint agent: enrol once, then run.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/larytet/zscaler/internal/agent"
	"github.com/larytet/zscaler/internal/cli"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ztx-agent [--config file] [--dir dir] enrol|enrol-service|enrol-workspace|workspace|run|status")
	os.Exit(2)
}

func openBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}

func main() {
	home, _ := os.UserHomeDir()
	dir := flag.String("dir", filepath.Join(home, ".ztx-agent"), "agent state directory")
	cfgPath := flag.String("config", "", "config file (default <dir>/config.json)")
	tokenFile := flag.String("token-file", "", "service token file for enrol-service (or ZTX_AGENT_TOKEN)")
	browser := flag.String("browser", "", "workspace: path of a Chromium-family browser (default: look for Chrome, Chromium or Edge)")
	postureEvery := flag.Duration("posture-every", 90*time.Second, "workspace: how often the device baseline is re-checked")
	renewEvery := flag.Duration("renew-every", 30*time.Second, "workspace: how often the credential is refreshed (and revocation noticed)")
	grace := flag.Duration("grace", 5*time.Minute, "workspace: how long the control plane may be unreachable before the workspace locks")
	needDisk := flag.Bool("require-disk-encryption", true, "workspace: lock when disk encryption is off or unknown")
	needFW := flag.Bool("require-firewall", true, "workspace: lock when the firewall is off or unknown")
	noBrowser := flag.Bool("no-browser", false, "print the sign-in URL instead of opening a browser")
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
	}
	cp := *cfgPath
	if cp == "" {
		cp = filepath.Join(*dir, "config.json")
	}
	b, err := os.ReadFile(cp)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}
	a, err := agent.New(*dir, cfg)
	if err != nil {
		log.Fatal(err)
	}
	switch flag.Arg(0) {
	case "enrol":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := a.Enrol(ctx, func(u string) error {
			fmt.Println("Sign in at:\n" + u)
			if !*noBrowser {
				if err := openBrowser(u); err != nil {
					fmt.Println("(could not open a browser automatically)")
				}
			}
			return nil
		}); err != nil {
			log.Fatal(err)
		}
		exp, _ := a.Expires()
		fmt.Println("Enrolled. Certificate valid until", exp.Format("2006-01-02 15:04 MST"))
	case "enrol-workspace":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := a.EnrolWorkspace(ctx, func(u string) error {
			fmt.Println("Sign in at:\n" + u)
			if !*noBrowser {
				openBrowser(u)
			}
			return nil
		}); err != nil {
			log.Fatal(err)
		}
		exp, _ := a.Expires()
		fmt.Println("Workspace enrolled. Credential valid until", exp.Format("2006-01-02 15:04 MST"))
	case "workspace":
		if err := agent.ValidateWorkspaceArgs(flag.Args()[1:]); err != nil {
			log.Fatal(err)
		}
		path := *browser
		if path == "" {
			path = findBrowser()
		}
		if path == "" {
			log.Fatal("no Chromium-family browser found; install Chrome, Chromium or Edge, or pass --browser")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		o := agent.WorkspaceOptions{Browser: path, PostureEvery: *postureEvery, RenewEvery: *renewEvery, Grace: *grace,
			RequireDisk: *needDisk, RequireFirewall: *needFW, Log: func(s string) { log.Println(s) }}
		if len(flag.Args()) > 1 {
			o.StartURL = flag.Arg(1)
		}
		if err := a.RunWorkspace(ctx, o); err != nil {
			log.Fatal(err)
		}
	case "enrol-service":
		tok, err := cli.Secret(*tokenFile, "ZTX_AGENT_TOKEN")
		if err != nil || tok == "" {
			log.Fatal("a service token is required (--token-file or ZTX_AGENT_TOKEN)")
		}
		if err := a.EnrolService(tok); err != nil {
			log.Fatal(err)
		}
		exp, _ := a.Expires()
		fmt.Println("Enrolled as a service identity. Certificate valid until", exp.Format("2006-01-02 15:04 MST"))
	case "run":
		if err := a.Load(); err != nil {
			log.Fatalf("%v (run `ztx-agent enrol` first)", err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		log.Println("agent running; PAC at http://127.0.0.1:9100/proxy.pac")
		if err := a.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "status":
		if err := a.Load(); err != nil {
			fmt.Println("not enrolled")
			return
		}
		j, _ := json.MarshalIndent(a.Status(), "", " ")
		fmt.Println(string(j))
	default:
		usage()
	}
}

// findBrowser looks for an installed Chromium-family browser.
func findBrowser() string {
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "chrome"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
