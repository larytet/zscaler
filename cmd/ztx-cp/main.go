// ztx-cp is the control plane: admin API plus device, connector and EN enrolment.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/larytet/zscaler/internal/siem"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/alerts"
	"github.com/larytet/zscaler/internal/approvals"
	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/captures"
	"github.com/larytet/zscaler/internal/cli"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

// version is stamped by the release build (ztx-release); a build from the source tree says dev.
var version = "dev"

func main() {
	if runBackupCommand(os.Args[1:]) {
		return
	}
	showVersion := flag.Bool("version", false, "print the version and exit")
	printOpenAPI := flag.Bool("print-openapi", false, "print the OpenAPI description of the admin API and exit")
	data := flag.String("data", "cp-data", "data directory (CA key, store, audit log)")
	adminL := flag.String("admin-listen", "127.0.0.1:8443", "admin API listen address")
	enrolL := flag.String("enrol-listen", "127.0.0.1:8444", "enrolment and sync listen address")
	names := flag.String("names", "localhost,127.0.0.1", "comma-separated DNS names or IPs for the server certificate")
	bootFile := flag.String("bootstrap-token-file", "", "file holding the bootstrap token (or set ZTX_BOOTSTRAP_TOKEN)")
	retentionDays := flag.Int("log-retention-days", 183, "how many days decision records are kept on disk (1 to 3650; the default is six months)")
	devTTL := flag.Duration("device-cert-ttl", 0, "lifetime of device certificates (default 12h); a shorter life ends a revoked or disabled user's access sooner but renews more often. At least 30s, at most 7 days")
	keyFile := flag.String("master-key-file", "", "file holding the master key that encrypts the CA key, the signing key and the store at rest (or set ZTX_MASTER_KEY); make one with `ztx-cp gen-master-key`, keep it off this disk, and keep a copy: without it the data cannot be read")
	minAgent := flag.String("min-agent-version", "", "agents older than this refuse to start sessions")
	smtpAddr := flag.String("smtp-addr", "", "SMTP server host:port for alert emails (empty disables email)")
	smtpFrom := flag.String("smtp-from", "alerts@localhost", "From address for alert emails")
	smtpUser := flag.String("smtp-user", "", "SMTP username (password from ZTX_SMTP_PASSWORD)")
	flag.Parse()
	if *showVersion {
		fmt.Println("ztx-cp", version)
		return
	}
	if *printOpenAPI {
		api := &cp.API{}
		api.Handler() // registers the routes, which is what the description is built from
		os.Stdout.Write(api.OpenAPI())
		return
	}

	boot, err := cli.Secret(*bootFile, "ZTX_BOOTSTRAP_TOKEN")
	if err != nil || boot == "" {
		log.Fatal("a bootstrap token is required (--bootstrap-token-file or ZTX_BOOTSTRAP_TOKEN)")
	}
	mk, err := masterKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if mk != nil { // encrypt what is still in clear, once; a sealed file is only checked against this key
		for _, f := range []string{"ca.key", "policy.key", "store.json"} {
			changed, err := seal.SealInPlace(filepath.Join(*data, f), mk)
			if err != nil {
				log.Fatal(err)
			}
			if changed {
				log.Printf("encrypted %s at rest with the master key (copies of the old clear file may remain on the disk: a disk image taken earlier still holds them)", f)
			}
		}
	} else if b, err := os.ReadFile(filepath.Join(*data, "ca.key")); err != nil || !seal.IsSealed(b) {
		log.Printf("WARNING: no master key: the CA key, the signing key and the tenant secrets are stored in clear in %s (see -master-key-file)", *data)
	}
	ca, err := pki.LoadOrCreateCAKey(*data, "smb-ztx root", nil, mk)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := pki.LoadOrCreateSignerKey(*data, mk)
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.OpenWithKey(filepath.Join(*data, "store.json"), mk)
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
	var notifier *alerts.SMTPNotifier
	if *smtpAddr != "" {
		n := &alerts.SMTPNotifier{Addr: *smtpAddr, From: *smtpFrom, Username: *smtpUser, Password: os.Getenv("ZTX_SMTP_PASSWORD"),
			To: st.AlertEmails, Errf: func(err error) { log.Printf("alert email: %v", err) }}
		eng.OnOpen = n.Notify
		notifier = n
	}
	go func() {
		for range time.Tick(30 * time.Second) {
			eng.Tick()
		}
	}()
	api := &cp.API{Store: st, Audit: al, AuditPath: ap, Tokens: pki.NewTokens(nil, time.Hour), BootstrapToken: boot, Alerts: eng, Decisions: decisions.New(), Approvals: approvals.New(), Health: devhealth.New(), Captures: captures.New()}
	if *retentionDays < 1 || *retentionDays > 3650 {
		log.Fatal("--log-retention-days must be between 1 and 3650")
	}
	archive, err := decisions.OpenArchive(filepath.Join(*data, "decisions"), time.Duration(*retentionDays)*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	api.Decisions.SetArchive(archive)
	log.Printf("%s; %d recent records reloaded", archive.Describe(), api.Decisions.Restore(50000))
	go func() {
		for {
			if n := archive.Purge(); n > 0 {
				log.Printf("decision archive: %d day files past their retention deleted", n)
			}
			time.Sleep(6 * time.Hour)
		}
	}()
	go func() {
		for {
			if n := st.PurgeExpiredAdmins(7 * 24 * time.Hour); n > 0 {
				log.Printf("%d expired administrator accounts deleted", n)
			}
			time.Sleep(6 * time.Hour)
		}
	}()
	api.SIEM = &siem.Streamer{AllowLoopback: os.Getenv("ZTX_SIEM_ALLOW_LOOPBACK") == "1"} // loopback targets are a lab-only switch
	for tenant, c := range st.SIEMConfigs() {
		c := c
		if err := api.SIEM.Configure(tenant, &c); err != nil {
			log.Printf("log sink of tenant %s not started: %v", tenant, err)
		}
	}
	if *devTTL != 0 && (*devTTL < 30*time.Second || *devTTL > 7*24*time.Hour) {
		log.Fatal("--device-cert-ttl must be between 30s and 7 days")
	}
	api.RootCACert, api.PolicyPub, api.AtRestSealed = ca.Cert, &signer.PublicKey, mk != nil
	enrol := &cp.Enrol{API: api, CA: ca, Rev: pki.NewRevocations(nil), MinAgentVersion: *minAgent, PolicyKey: signer, DeviceTTL: *devTTL}

	if notifier != nil {
		go weeklyDigest(api, st, notifier)
		api.OnApprovalRequest = func(r approvals.Request) {
			body := r.User + " asked for access to " + r.App + ".\r\n\r\nApprove or deny it in the console, or with POST /v1/approvals/" + strconv.Itoa(r.ID) + "/approve.\r\n"
			if err := notifier.SendText(r.Tenant, "[Access request] "+r.User+" wants "+r.App, body); err != nil {
				log.Printf("approval email: %v", err)
			}
		}
	}
	go func() {
		for range time.Tick(30 * time.Second) {
			api.RefreshRisk()
		}
	}()
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

// weeklyDigest emails each tenant's digest on Monday at 08:00 UTC, once per week.
func weeklyDigest(api *cp.API, st *store.Store, n *alerts.SMTPNotifier) {
	last := map[string]string{}
	for range time.Tick(time.Minute) {
		now := time.Now().UTC()
		if now.Weekday() != time.Monday || now.Hour() != 8 {
			continue
		}
		day := now.Format("2006-01-02")
		for _, t := range st.Tenants() {
			if last[t] == day {
				continue
			}
			last[t] = day
			if err := n.SendText(t, "Your weekly security summary", api.BuildDigest(t, 7).Text()); err != nil {
				log.Printf("digest email for %s: %v", t, err)
			}
		}
	}
}
