package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/posture"
)

const Version = "0.1.0"

// Config is stored in config.json in the agent directory.
type Config struct {
	Tenant     string   `json:"tenant"`
	Issuer     string   `json:"issuer"`
	ClientID   string   `json:"client_id"`
	EnrolURL   string   `json:"enrol_url"`   // control plane enrolment base URL
	ENAddrs    []string `json:"en_addrs"`    // enforcement node broker addresses
	ProxyAddrs []string `json:"proxy_addrs"` // enforcement node web proxy addresses
	ENName     string   `json:"en_name"`     // TLS server name of the ENs
	SocksAddr  string   `json:"socks_addr"`  // default 127.0.0.1:1080
	HTTPAddr   string   `json:"http_addr"`   // default 127.0.0.1:3129
	StatusAddr string   `json:"status_addr"`
	// Apps maps a virtual host name (name.ztx) to a segment ID.
	Apps map[string]string `json:"apps"`
	// TrustEnrolCA, when set, pins the HTTPS trust for the enrolment URL (tests, private CAs).
	EnrolCAPEM string `json:"enrol_ca_pem,omitempty"`
	// PostureEverySeconds is how often posture is re-sent (default 300).
	PostureEverySeconds int `json:"posture_every_seconds,omitempty"`
}

type Agent struct {
	Dir string
	Cfg Config

	mu       sync.Mutex
	key      *ecdsa.PrivateKey
	cert     tls.Certificate
	leaf     *x509.Certificate
	caPool   *x509.CertPool
	conn     *broker.Conn
	lastPos  *posture.Report
	deviceID string
	minAgent string
}

var errNotEnrolled = errors.New("agent: not enrolled")

func New(dir string, cfg Config) (*Agent, error) {
	if err := checkLoopback(cfg.SocksAddr, cfg.HTTPAddr, cfg.StatusAddr); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(dir, 0o700)
	return &Agent{Dir: dir, Cfg: cfg}, nil
}

// checkLoopback refuses to listen on anything but loopback (AG-009).
func checkLoopback(addrs ...string) error {
	for _, a := range addrs {
		if a == "" {
			continue
		}
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return fmt.Errorf("agent: bad listen address %q", a)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("agent: %q is not a loopback address", a)
		}
	}
	return nil
}

func (a *Agent) path(n string) string { return filepath.Join(a.Dir, n) }

func (a *Agent) loadKey() (*ecdsa.PrivateKey, error) {
	if a.key != nil {
		return a.key, nil
	}
	if b, err := os.ReadFile(a.path("device.key")); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				a.key = k
				return k, nil
			}
		}
		return nil, errors.New("agent: device.key is unreadable; re-enrol")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(a.path("device.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	a.key = k
	return k, nil
}

func (a *Agent) pubB64() (string, error) {
	k, err := a.loadKey()
	if err != nil {
		return "", err
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return base64.StdEncoding.EncodeToString(der), nil
}

type certResp struct {
	DeviceID string    `json:"device_id"`
	Cert     string    `json:"cert"`
	CA       string    `json:"ca"`
	Expires  time.Time `json:"expires"`
	MinAgent string    `json:"min_agent_version"`
}

func (a *Agent) enrolClient(withCert bool) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if a.Cfg.EnrolCAPEM != "" {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM([]byte(a.Cfg.EnrolCAPEM))
		cfg.RootCAs = p
	}
	if withCert {
		a.mu.Lock()
		cfg.Certificates = []tls.Certificate{a.cert}
		a.mu.Unlock()
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (a *Agent) post(withCert bool, path string, in any) (*certResp, error) {
	b, _ := json.Marshal(in)
	resp, err := a.enrolClient(withCert).Post(a.Cfg.EnrolURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("agent: control plane said %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	var out certResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *Agent) install(c *certResp) error {
	der, err := base64.StdEncoding.DecodeString(c.Cert)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.CA)) {
		return errors.New("agent: control plane returned no CA certificate")
	}
	k, err := a.loadKey()
	if err != nil {
		return err
	}
	if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pk.Equal(&k.PublicKey) {
		return errors.New("agent: certificate does not match the device key")
	}
	if err := os.WriteFile(a.path("device.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	os.WriteFile(a.path("ca.pem"), []byte(c.CA), 0o600)
	a.mu.Lock()
	a.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	a.leaf, a.caPool, a.deviceID = leaf, pool, c.DeviceID
	a.minAgent = c.MinAgent
	a.mu.Unlock()
	if c.MinAgent != "" {
		os.WriteFile(a.path("min_agent_version"), []byte(c.MinAgent), 0o600)
	}
	return nil
}

// Enrol logs the user in and obtains a device certificate.
func (a *Agent) Enrol(ctx context.Context, openURL func(string) error) error {
	return a.enrol(ctx, openURL, false)
}

// EnrolWorkspace is Enrol for the workspace browser: the control plane issues a credential
// with the workspace role, which lives only a few hours.
func (a *Agent) EnrolWorkspace(ctx context.Context, openURL func(string) error) error {
	return a.enrol(ctx, openURL, true)
}

func (a *Agent) enrol(ctx context.Context, openURL func(string) error, workspace bool) error {
	pub, err := a.pubB64()
	if err != nil {
		return err
	}
	lr, err := Login(ctx, a.Cfg.Issuer, a.Cfg.ClientID, openURL)
	if err != nil {
		return err
	}
	c, err := a.post(false, "/enrol/device", map[string]any{"tenant": a.Cfg.Tenant, "id_token": lr.IDToken, "nonce": lr.Nonce, "public_key": pub, "workspace": workspace})
	if err != nil {
		return err
	}
	return a.install(c)
}

// EnrolService enrols a non-interactive identity (an AI agent) with a one-time token from
// POST /v1/ai-agents. There is no login: the identity, its operator and the apps it may
// reach were fixed by an admin.
func (a *Agent) EnrolService(token string) error {
	pub, err := a.pubB64()
	if err != nil {
		return err
	}
	c, err := a.post(false, "/enrol/service", map[string]string{"token": token, "public_key": pub})
	if err != nil {
		return err
	}
	return a.install(c)
}

// InspectionSPKI asks the control plane for the hash of the key that signs this tenant's
// inspection certificates. It returns "" when inspection is off.
func (a *Agent) InspectionSPKI() (string, error) {
	resp, err := a.enrolClient(true).Get(a.Cfg.EnrolURL + "/enrol/inspection")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("agent: control plane said %d", resp.StatusCode)
	}
	var out struct {
		Enabled bool   `json:"enabled"`
		SPKI    string `json:"spki_sha256"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return "", err
	}
	if !out.Enabled {
		return "", nil
	}
	return out.SPKI, nil
}

// FetchInspectionCA downloads the tenant's inspection CA certificate. It returns nil, nil when
// inspection is off.
func (a *Agent) FetchInspectionCA() ([]byte, error) {
	resp, err := a.enrolClient(true).Get(a.Cfg.EnrolURL + "/enrol/inspection-ca")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("agent: control plane said %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(b, []byte("BEGIN CERTIFICATE")) || bytes.Contains(b, []byte("PRIVATE KEY")) {
		return nil, errors.New("agent: the control plane did not return a plain certificate")
	}
	return b, nil
}

// Load restores a previously issued certificate from disk.
func (a *Agent) Load() error {
	k, err := a.loadKey()
	if err != nil {
		return err
	}
	cb, err1 := os.ReadFile(a.path("device.crt"))
	pb, err2 := os.ReadFile(a.path("ca.pem"))
	if err1 != nil || err2 != nil {
		return errNotEnrolled
	}
	blk, _ := pem.Decode(cb)
	if blk == nil {
		return errors.New("agent: device.crt is unreadable; re-enrol")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return errors.New("agent: device.crt is unreadable; re-enrol")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pb)
	a.mu.Lock()
	a.cert = tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: k}
	a.leaf, a.caPool = leaf, pool
	a.mu.Unlock()
	return nil
}

// Renew exchanges the current certificate for a fresh one.
func (a *Agent) Renew() error {
	pub, err := a.pubB64()
	if err != nil {
		return err
	}
	c, err := a.post(true, "/enrol/renew", map[string]string{"public_key": pub})
	if err != nil {
		return err
	}
	return a.install(c)
}

// Expires reports when the current certificate ends.
func (a *Agent) Expires() (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.leaf == nil {
		return time.Time{}, false
	}
	return a.leaf.NotAfter, true
}

// RenewLoop renews one hour before expiry (DESIGN.md D4.2). lead is
// configurable for tests.
func (a *Agent) RenewLoop(ctx context.Context, lead time.Duration, onErr func(error)) {
	for ctx.Err() == nil {
		exp, ok := a.Expires()
		wait := time.Minute
		if ok {
			if wait = time.Until(exp.Add(-lead)); wait < 0 {
				wait = 0
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if !ok {
			continue
		}
		if err := a.Renew(); err != nil {
			if onErr != nil {
				onErr(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
	}
}

func (a *Agent) tlsConfig(serverName string) (*tls.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.leaf == nil {
		return nil, errNotEnrolled
	}
	return &tls.Config{Certificates: []tls.Certificate{a.cert}, RootCAs: a.caPool, ServerName: serverName, MinVersion: tls.VersionTLS13}, nil
}

// Connect dials the first reachable EN, returning to earlier ones when they recover.
func (a *Agent) Connect() (*broker.Conn, error) {
	cfg, err := a.tlsConfig(a.Cfg.ENName)
	if err != nil {
		return nil, err
	}
	var last error
	for _, addr := range a.Cfg.ENAddrs {
		c, err := broker.Dial(addr, cfg)
		if err == nil {
			a.mu.Lock()
			a.conn = c
			a.mu.Unlock()
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("agent: no EN addresses configured")
	}
	return nil, last
}

// conn returns a live connection, reconnecting if needed, and sends posture on connect.
// ErrTooOld is returned when the control plane requires a newer agent.
var ErrTooOld = errors.New("agent: this agent version is older than the minimum the control plane requires; update it")

func (a *Agent) tooOld() bool {
	a.mu.Lock()
	min := a.minAgent
	a.mu.Unlock()
	if min == "" {
		if b, err := os.ReadFile(a.path("min_agent_version")); err == nil {
			min = strings.TrimSpace(string(b))
		}
	}
	return min != "" && policy.CompareVersions(Version, min) < 0
}

func (a *Agent) liveConn() (*broker.Conn, error) {
	if a.tooOld() {
		return nil, ErrTooOld
	}
	a.mu.Lock()
	c := a.conn
	a.mu.Unlock()
	if c != nil {
		select {
		case <-c.Sess.Done():
		default:
			return c, nil
		}
	}
	c, err := a.Connect()
	if err != nil {
		return nil, err
	}
	a.SendPosture(c) // best effort: policy fails closed without it
	return c, nil
}

// SendPosture collects and sends a signed posture report.
func (a *Agent) SendPosture(c *broker.Conn) error {
	k, err := a.loadKey()
	if err != nil {
		return err
	}
	a.mu.Lock()
	id := a.deviceID
	if id == "" && a.leaf != nil {
		id = deviceFromCert(a.leaf)
	}
	a.mu.Unlock()
	rep := Collect(DefaultProbes())
	h := devhealth.Collect()
	rep.Health = &h
	rep.DeviceID, rep.TS, rep.Nonce, rep.AgentVersion = id, time.Now().UTC(), posture.NewNonce(), Version
	tok, err := posture.Sign(k, rep)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.lastPos = &rep
	a.mu.Unlock()
	return c.SendPosture(tok)
}

func deviceFromCert(c *x509.Certificate) string {
	parts := splitCN(c.Subject.CommonName)
	if len(parts) == 3 {
		return parts[2]
	}
	return ""
}

func splitCN(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '/' && len(out) < 2 {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

// PostureLoop reports every interval until ctx ends.
func (a *Agent) PostureLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c, err := a.liveConn(); err == nil {
				a.SendPosture(c)
			}
		}
	}
}
