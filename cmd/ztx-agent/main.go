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

	"github.com/larytet/zscaler/internal/agent"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ztx-agent [--config file] [--dir dir] enrol|run|status")
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
