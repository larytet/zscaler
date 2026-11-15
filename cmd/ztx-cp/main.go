// ztx-cp is the control plane: admin API plus device, connector and EN enrolment.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/cli"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/store"
)

func main() {
	data := flag.String("data", "cp-data", "data directory (CA key, store, audit log)")
	adminL := flag.String("admin-listen", "127.0.0.1:8443", "admin API listen address")
	enrolL := flag.String("enrol-listen", "127.0.0.1:8444", "enrolment and sync listen address")
	names := flag.String("names", "localhost,127.0.0.1", "comma-separated DNS names or IPs for the server certificate")
	bootFile := flag.String("bootstrap-token-file", "", "file holding the bootstrap token (or set ZTX_BOOTSTRAP_TOKEN)")
	minAgent := flag.String("min-agent-version", "", "agents older than this refuse to start sessions")
	smtpAddr := flag.String("smtp-addr", "", "SMTP server host:port for alert emails (empty disables email)")
	smtpFrom := flag.String("smtp-from", "alerts@localhost", "From address for alert emails")
	smtpUser := flag.String("smtp-user", "", "SMTP username (password from ZTX_SMTP_PASSWORD)")
	flag.Parse()

	boot, err := cli.Secret(*bootFile, "ZTX_BOOTSTRAP_TOKEN")
	if err != nil || boot == "" {
		log.Fatal("a bootstrap token is required (--bootstrap-token-file or ZTX_BOOTSTRAP_TOKEN)")
	}
	ca, err := pki.LoadOrCreateCA(*data, "smb-ztx root", nil)
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(*data, "store.json"))
	if err != nil {
		log.Fatal(err)
	}
	ap := filepath.Join(*data, "audit.jsonl")
	al, err := audit.Open(ap, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer al.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := ca.Sign(&key.PublicKey, pki.Identity{Tenant: "platform", Subject: "cp", Device: "cp", Role: pki.RoleEN}, 7*24*time.Hour, strings.Split(*names, ",")...)
	if err != nil {
		log.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	eng := alerts.New()
	eng.Name = func(tenant, subject string) string {
		if u, ok := st.User(tenant, subject); ok && u.Email != "" {
			return u.Email
		}
		return subject
	}
	if *smtpAddr != "" {
		n := &alerts.SMTPNotifier{Addr: *smtpAddr, From: *smtpFrom, Username: *smtpUser, Password: os.Getenv("ZTX_SMTP_PASSWORD"),
			To: st.AlertEmails, Errf: func(err error) { log.Printf("alert email: %v", err) }}
		eng.OnOpen = n.Notify
	}
	go func() {
		for range time.Tick(30 * time.Second) {
			eng.Tick()
		}
	}()
	api := &cp.API{Store: st, Audit: al, AuditPath: ap, Tokens: pki.NewTokens(nil, time.Hour), BootstrapToken: boot, Alerts: eng, Decisions: decisions.New()}
	enrol := &cp.Enrol{API: api, CA: ca, Rev: pki.NewRevocations(nil), MinAgentVersion: *minAgent}

	admin := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	en := &http.Server{Handler: enrol.Handler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}}
	for _, s := range []struct {
		srv  *http.Server
		addr string
	}{{admin, *adminL}, {en, *enrolL}} {
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			log.Fatal(err)
		}
		go func(srv *http.Server, ln net.Listener) { log.Fatal(srv.ServeTLS(ln, "", "")) }(s.srv, ln)
	}
	log.Printf("control plane up: admin %s, enrolment %s, CA certificate for endpoints: %s", *adminL, *enrolL, filepath.Join(*data, "ca.pem"))
	select {}
}
