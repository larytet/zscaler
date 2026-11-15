// ztx-en is an enforcement node: private-access broker and web proxy.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/cli"
	"github.com/larytet/zscaler/internal/en"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/store"
	"github.com/larytet/zscaler/internal/webproxy"
)

func main() {
	cpURL := flag.String("cp", "https://127.0.0.1:8444", "control plane enrolment URL")
	cpCA := flag.String("cp-ca", "cp-data/ca.pem", "CA certificate file (trust root)")
	data := flag.String("data", "en-data", "data directory")
	tokFile := flag.String("token-file", "", "one-time enrolment token file (or ZTX_EN_TOKEN); only needed the first time")
	name := flag.String("name", "en1", "node name used in decision logs")
	brokerL := flag.String("listen", "127.0.0.1:9443", "broker listen address (agents and connectors)")
	proxyL := flag.String("proxy-listen", "127.0.0.1:9444", "web proxy listen address")
	logPath := flag.String("decision-log", "", "decision log file (JSON lines); default <data>/decisions.jsonl")
	catFile := flag.String("categories", "", "JSON file mapping category to domain list")
	every := flag.Duration("sync-every", en.DefaultSyncEvery, "state poll interval")
	flag.Parse()

	caPEM, err := os.ReadFile(*cpCA)
	if err != nil {
		log.Fatal(err)
	}
	tok, _ := cli.Secret(*tokFile, "ZTX_EN_TOKEN")
	id, err := cli.LoadOrEnrol(*data, *cpURL, caPEM, "/enrol/en", tok, *name)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := pki.VerifierFromPEM(id.PEM, nil) // verify-only: the EN never holds the CA key
	if err != nil {
		log.Fatal(err)
	}

	state := en.NewSyncState()
	rev := pki.NewRevocations(nil)
	lp := *logPath
	if lp == "" {
		lp = filepath.Join(*data, "decisions.jsonl")
	}
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	var lmu sync.Mutex
	fwd := &en.Forwarder{URL: *cpURL, TLS: id.TLS(cli.HostOf(*cpURL))}
	logRec := func(r broker.Record) {
		lmu.Lock()
		b, _ := json.Marshal(r)
		lf.Write(append(b, '\n'))
		lmu.Unlock()
		fwd.Add(r)
	}

	node := &broker.EN{Name: *name, CA: verifier, Rev: rev, State: state, Log: logRec, Cert: id.Cert,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	state.OnChange = func(old, cur *store.Snapshot) {
		revs, dis := en.Diff(old, cur)
		for _, d := range revs {
			node.CloseDevice(d[0], d[1])
		}
		for _, u := range dis {
			node.DisableUser(u[0], u[1])
		}
		node.ReevalNow()
	}

	poller := &en.Poller{URL: *cpURL, TLS: id.TLS(cli.HostOf(*cpURL)), State: state}
	if err := poller.Once(); err != nil {
		log.Printf("initial sync failed (will keep trying, sessions are denied until it succeeds): %v", err)
	}
	stop := make(chan struct{})
	go poller.Run(*every, stop, func(err error) { log.Printf("sync: %v", err) })
	go fwd.Run(2*time.Second, stop, func(err error) { log.Printf("forward: %v", err) })

	var classifier *webproxy.Classifier
	lists := map[string][]string{}
	if *catFile != "" {
		b, err := os.ReadFile(*catFile)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.Unmarshal(b, &lists); err != nil {
			log.Fatal(err)
		}
	}
	classifier = webproxy.NewClassifier(lists)
	px := &webproxy.Proxy{CA: verifier, Rev: rev, State: state, Classifier: classifier, Log: logRec, Name: *name}
	srv := px.Server(id.Cert)
	pl, err := net.Listen("tcp", *proxyL)
	if err != nil {
		log.Fatal(err)
	}
	go func() { log.Fatal(srv.Serve(tls.NewListener(pl, srv.TLSConfig))) }()

	bl, err := net.Listen("tcp", *brokerL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("enforcement node %s up: broker %s, web proxy %s", *name, *brokerL, *proxyL)
	log.Fatal(node.Serve(bl))
}
