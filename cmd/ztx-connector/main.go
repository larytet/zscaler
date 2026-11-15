// ztx-connector runs inside the customer network and only dials out.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/cli"
	"github.com/larytet/zscaler/internal/logx"
	"github.com/larytet/zscaler/internal/versions"
)

// version is stamped by the release build (ztx-release); a build from the source tree says dev.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	cpURL := flag.String("cp", "https://127.0.0.1:8444", "control plane enrolment URL")
	cpCA := flag.String("cp-ca", "cp-data/ca.pem", "CA certificate file (trust root)")
	data := flag.String("data", "connector-data", "data directory")
	tokFile := flag.String("token-file", "", "one-time enrolment token file (or ZTX_CONNECTOR_TOKEN); only needed the first time")
	name := flag.String("name", "connector1", "connector name")
	ens := flag.String("en", "127.0.0.1:9443", "comma-separated enforcement node broker addresses")
	enName := flag.String("en-name", "localhost", "TLS server name of the enforcement nodes")
	targetsEvery := flag.Duration("targets-every", 30*time.Second, "how often to refresh the target allow-list")
	flag.Parse()
	logx.Setup("ztx-connector")
	if *showVersion {
		fmt.Println("ztx-connector", version)
		return
	}

	caPEM, err := os.ReadFile(*cpCA)
	if err != nil {
		logx.Die(err)
	}
	tok, _ := cli.Secret(*tokFile, "ZTX_CONNECTOR_TOKEN")
	id, err := cli.LoadOrEnrol(*data, *cpURL, caPEM, "/enrol/connector", tok, *name)
	if err != nil {
		logx.Die(err)
	}

	// The allow-list comes from the control plane and is refreshed every 30 s.
	var allow atomic.Pointer[map[string]bool]
	empty := map[string]bool{}
	allow.Store(&empty)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: id.TLS(cli.HostOf(*cpURL))}}
	refresh := func() {
		req, _ := http.NewRequest("GET", strings.TrimSuffix(*cpURL, "/")+"/enrol/targets", nil)
		req.Header.Set(versions.Header, version)
		resp, err := cl.Do(req)
		if err != nil {
			slog.Warn("targets", "err", err)
			return
		}
		defer resp.Body.Close()
		var ts []broker.Target
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&ts) != nil {
			slog.Warn("targets: unexpected response", "status", resp.StatusCode)
			return
		}
		m := map[string]bool{}
		for _, t := range ts {
			for _, p := range t.Ports {
				m[strings.ToLower(t.Host)+":"+itoa(p)] = true
			}
		}
		allow.Store(&m)
	}
	refresh()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		t := time.NewTicker(*targetsEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	// Connect to every listed enforcement node at once, so losing one does not cut the apps
	// behind this connector (ZPA-044). Each link reconnects on its own.
	allowFn := func(h string, p int) bool { return (*allow.Load())[strings.ToLower(h)+":"+itoa(p)] }
	var wg sync.WaitGroup
	for _, addr := range strings.Split(*ens, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			c := &broker.Connector{Addr: addr, TLS: tlsFor(id, *enName), Allow: allowFn,
				Events: func(s string) { slog.Info(s, "enforcement_node", addr) }}
			c.Run(ctx)
		}(addr)
	}
	slog.Info("connector running", "name", *name, "enforcement_nodes", len(strings.Split(*ens, ",")))
	wg.Wait()
}

func tlsFor(id *cli.Identity, serverName string) *tls.Config { return id.TLS(serverName) }

func itoa(n int) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
