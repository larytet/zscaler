// ztx-connector runs inside the customer network and only dials out.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/cli"
)

func main() {
	cpURL := flag.String("cp", "https://127.0.0.1:8444", "control plane enrolment URL")
	cpCA := flag.String("cp-ca", "cp-data/ca.pem", "CA certificate file (trust root)")
	data := flag.String("data", "connector-data", "data directory")
	tokFile := flag.String("token-file", "", "one-time enrolment token file (or ZTX_CONNECTOR_TOKEN); only needed the first time")
	name := flag.String("name", "connector1", "connector name")
	ens := flag.String("en", "127.0.0.1:9443", "comma-separated enforcement node broker addresses")
	enName := flag.String("en-name", "localhost", "TLS server name of the enforcement nodes")
	flag.Parse()

	caPEM, err := os.ReadFile(*cpCA)
	if err != nil {
		log.Fatal(err)
	}
	tok, _ := cli.Secret(*tokFile, "ZTX_CONNECTOR_TOKEN")
	id, err := cli.LoadOrEnrol(*data, *cpURL, caPEM, "/enrol/connector", tok, *name)
	if err != nil {
		log.Fatal(err)
	}

	// The allow-list comes from the control plane and is refreshed every 30 s.
	var allow atomic.Pointer[map[string]bool]
	empty := map[string]bool{}
	allow.Store(&empty)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: id.TLS(cli.HostOf(*cpURL))}}
	refresh := func() {
		resp, err := cl.Get(strings.TrimSuffix(*cpURL, "/") + "/enrol/targets")
		if err != nil {
			log.Printf("targets: %v", err)
			return
		}
		defer resp.Body.Close()
		var ts []broker.Target
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&ts) != nil {
			log.Printf("targets: unexpected response %d", resp.StatusCode)
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
		t := time.NewTicker(30 * time.Second)
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
	c := &broker.Connector{TLS: tlsFor(id, *enName),
		Allow:  func(h string, p int) bool { return (*allow.Load())[strings.ToLower(h)+":"+itoa(p)] },
		Events: func(s string) { log.Print(s) }}
	for _, a := range strings.Split(*ens, ",") {
		c.Addr = a // first address; failover across ENs is a later improvement
		break
	}
	log.Printf("connector %s running", *name)
	c.Run(ctx)
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
