// Package siem streams a tenant's decision records and admin audit events to the tenant's own log
// system (INT-004, ADM-006a): as newline-delimited JSON over HTTPS, or as syslog (RFC 5424) over TCP,
// TLS or UDP. Events are queued in memory with a bound, sent in batches, retried with back-off, and
// counted when they are dropped. The format is documented in SIEM-SCHEMA.md.
package siem

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Schema   = "smbztx.v1"
	QueueMax = 10000
	BatchMax = 100
)

// Config is one tenant's sink. Token and CAPEM are write-only: the API never returns them.
type Config struct {
	Kind   string `json:"kind"`             // "https" or "syslog"
	URL    string `json:"url,omitempty"`    // https: where to POST
	Header string `json:"header,omitempty"` // https: header that carries Token (default Authorization)
	Token  string `json:"token,omitempty"`  // https: the header value, for example "Bearer abc" or "Splunk abc"
	Addr   string `json:"addr,omitempty"`   // syslog: host:port
	Proto  string `json:"proto,omitempty"`  // syslog: tcp (default), tls or udp
	CAPEM  string `json:"ca_pem,omitempty"` // a private certificate authority for the receiver
	// What to send. Both default to true when the sink is created through the API.
	Decisions bool `json:"decisions"`
	Audit     bool `json:"audit"`
}

// Stats says how the sink is doing. Counts are since the control plane started.
type Stats struct {
	Sent        int       `json:"sent"`
	Failed      int       `json:"failed"`  // events dropped after the receiver refused them for good
	Dropped     int       `json:"dropped"` // events dropped because the queue was full
	Queued      int       `json:"queued"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

// Validate checks a config, and returns it with defaults filled in.
func Validate(c Config, allowLoopback bool) (Config, error) {
	switch c.Kind {
	case "https":
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || u.User != nil {
			return c, errors.New("url must be a plain https address such as https://siem.example.com/ingest")
		}
		if u.Scheme != "https" && !(allowLoopback && u.Scheme == "http") {
			return c, errors.New("url must use https")
		}
		if err := checkHost(u.Hostname(), allowLoopback); err != nil {
			return c, err
		}
		if c.Header == "" {
			c.Header = "Authorization"
		}
		if !headerName.MatchString(c.Header) || forbiddenHeader(c.Header) {
			return c, errors.New("header must be a plain header name such as Authorization or X-Api-Key")
		}
		if len(c.Token) > 2048 || strings.ContainsAny(c.Token, "\r\n\x00") {
			return c, errors.New("token must be one line of at most 2048 characters")
		}
		c.Addr, c.Proto = "", ""
	case "syslog":
		host, port, err := net.SplitHostPort(c.Addr)
		if err != nil || host == "" || port == "" {
			return c, errors.New("addr must be host:port")
		}
		if c.Proto == "" {
			c.Proto = "tcp"
		}
		if c.Proto != "tcp" && c.Proto != "tls" && c.Proto != "udp" {
			return c, errors.New("proto must be tcp, tls or udp")
		}
		if err := checkHost(host, allowLoopback); err != nil {
			return c, err
		}
		c.URL, c.Header, c.Token = "", "", ""
	default:
		return c, errors.New("kind must be https or syslog")
	}
	if c.CAPEM != "" {
		if len(c.CAPEM) > 64<<10 || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
			return c, errors.New("ca_pem is not a PEM certificate")
		}
	}
	if !c.Decisions && !c.Audit {
		return c, errors.New("send at least one of decisions and audit")
	}
	return c, nil
}

func forbiddenHeader(h string) bool {
	switch strings.ToLower(h) {
	case "host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "te", "trailer":
		return true
	}
	return false
}

// checkHost refuses addresses the control plane must never be made to call on someone's behalf: the
// cloud metadata service and other link-local addresses, the unspecified address, and loopback. A
// private address is fine: a SIEM often sits on the customer's own network.
func checkHost(h string, allowLoopback bool) error {
	if ip := net.ParseIP(h); ip != nil {
		return checkIP(ip, allowLoopback)
	}
	if strings.EqualFold(h, "localhost") && !allowLoopback {
		return errors.New("a loopback address is not allowed")
	}
	return nil // names are checked again when they are resolved, at connection time
}

func checkIP(ip net.IP, allowLoopback bool) error {
	switch {
	case ip.IsUnspecified(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return errors.New("that address is not allowed (unspecified, link-local or multicast, which includes the cloud metadata address)")
	case ip.IsLoopback() && !allowLoopback:
		return errors.New("a loopback address is not allowed")
	}
	return nil
}

// Event is one thing sent: a decision record or an audit event, with the fields of the original.
type Event map[string]any

// NewEvent builds an event from a JSON-encoded record, dropping the fields that must not leave the
// platform and adding the schema fields.
func NewEvent(kind string, record any, drop ...string) (Event, error) {
	b, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	e := Event{}
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	for _, k := range drop {
		delete(e, k)
	}
	e["schema"], e["type"] = Schema, kind
	return e, nil
}

// Streamer holds one worker per tenant.
type Streamer struct {
	AllowLoopback bool // lab only
	// Now and Backoff exist for tests; Backoff is the first retry delay (default one second).
	Now     func() time.Time
	Backoff time.Duration

	mu      sync.Mutex
	workers map[string]*worker
}

func (s *Streamer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Configure starts, replaces or (with nil) stops a tenant's sink.
func (s *Streamer) Configure(tenant string, c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workers == nil {
		s.workers = map[string]*worker{}
	}
	if old := s.workers[tenant]; old != nil {
		old.stop()
		delete(s.workers, tenant)
	}
	if c == nil {
		return nil
	}
	cfg, err := Validate(*c, s.AllowLoopback)
	if err != nil {
		return err
	}
	w := newWorker(s, cfg)
	s.workers[tenant] = w
	go w.run()
	return nil
}

// Emit queues an event for the tenant's sink, if it has one that wants this kind of event. It never blocks.
func (s *Streamer) Emit(tenant string, e Event) {
	s.mu.Lock()
	w := s.workers[tenant]
	s.mu.Unlock()
	if w == nil {
		return
	}
	if (e["type"] == "audit" && !w.cfg.Audit) || (e["type"] == "decision" && !w.cfg.Decisions) {
		return
	}
	w.push(e)
}

// Stats returns the tenant's sink statistics, and false if it has no sink.
func (s *Streamer) Stats(tenant string) (Stats, bool) {
	s.mu.Lock()
	w := s.workers[tenant]
	s.mu.Unlock()
	if w == nil {
		return Stats{}, false
	}
	return w.stats(), true
}

// Test sends one test event now and reports whether the receiver accepted it.
func (s *Streamer) Test(tenant string) error {
	s.mu.Lock()
	w := s.workers[tenant]
	s.mu.Unlock()
	if w == nil {
		return errors.New("no log sink is configured")
	}
	ev := Event{"schema": Schema, "type": "test", "time": s.now().UTC().Format(time.RFC3339Nano), "message": "test event from SMB-ZTX"}
	return w.send([]Event{ev})
}

type worker struct {
	s   *Streamer
	cfg Config

	mu    sync.Mutex
	q     []Event
	st    Stats
	wake  chan struct{}
	done  chan struct{}
	conn  net.Conn
	httpc *http.Client
	once  sync.Once
}

func newWorker(s *Streamer, cfg Config) *worker {
	return &worker{s: s, cfg: cfg, wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (w *worker) stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.mu.Lock()
	if w.conn != nil {
		w.conn.Close()
	}
	w.mu.Unlock()
}

func (w *worker) push(e Event) {
	w.mu.Lock()
	if len(w.q) >= QueueMax {
		w.q = w.q[1:]
		w.st.Dropped++
	}
	w.q = append(w.q, e)
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *worker) stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.st
	st.Queued = len(w.q)
	return st
}

func (w *worker) run() {
	base := time.Second
	if w.s.Backoff > 0 {
		base = w.s.Backoff
	}
	backoff := base
	for {
		w.mu.Lock()
		n := len(w.q)
		w.mu.Unlock()
		if n == 0 {
			select {
			case <-w.done:
				return
			case <-w.wake:
			}
			time.Sleep(50 * time.Millisecond) // let a burst gather into one batch
			continue
		}
		w.mu.Lock()
		if n > BatchMax {
			n = BatchMax
		}
		batch := append([]Event(nil), w.q[:n]...)
		w.mu.Unlock()
		err := w.send(batch)
		w.mu.Lock()
		switch {
		case err == nil:
			w.q = w.q[min(n, len(w.q)):]
			w.st.Sent += n
			w.st.LastSuccess = w.s.now()
			backoff = base
		case isPermanent(err):
			w.q = w.q[min(n, len(w.q)):]
			w.st.Failed += n
			w.st.LastError, w.st.LastErrorAt = err.Error(), w.s.now()
		default:
			w.st.LastError, w.st.LastErrorAt = err.Error(), w.s.now()
		}
		w.mu.Unlock()
		if err != nil && !isPermanent(err) {
			select {
			case <-w.done:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}
}

type permanentError struct{ error }

func isPermanent(err error) bool { var p permanentError; return errors.As(err, &p) }

func (w *worker) send(batch []Event) error {
	if w.cfg.Kind == "https" {
		return w.sendHTTPS(batch)
	}
	return w.sendSyslog(batch)
}

func (w *worker) tlsConfig(serverName string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if w.cfg.CAPEM != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(w.cfg.CAPEM))
		cfg.RootCAs = pool
	}
	return cfg
}

// dialer refuses forbidden addresses after the name has been resolved, so a name that points at the
// metadata address is refused too.
func (w *worker) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip != nil {
			return checkIP(ip, w.s.AllowLoopback)
		}
		return nil
	}}
}

// client builds the HTTP client once; the worker loop and a test request may both need it.
func (w *worker) client() *http.Client {
	w.once.Do(func() {
		u, _ := url.Parse(w.cfg.URL)
		w.httpc = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{TLSClientConfig: w.tlsConfig(u.Hostname()), DialContext: w.dialer().DialContext, MaxIdleConns: 2}}
	})
	return w.httpc
}

func (w *worker) sendHTTPS(batch []Event) error {
	var body bytes.Buffer
	for _, e := range batch {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		body.Write(b)
		body.WriteByte('\n')
	}
	req, err := http.NewRequest("POST", w.cfg.URL, &body)
	if err != nil {
		return permanentError{err}
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if w.cfg.Token != "" {
		req.Header.Set(w.cfg.Header, w.cfg.Token)
	}
	resp, err := w.client().Do(req)
	if err != nil {
		return scrub(err, w.cfg.Token)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500:
		return fmt.Errorf("the receiver answered %d", resp.StatusCode)
	default: // 3xx and the other 4xx: retrying will not help, and would block everything behind it
		return permanentError{fmt.Errorf("the receiver refused the events with %d", resp.StatusCode)}
	}
}

// scrub keeps a token out of an error message that is shown to the admin.
func scrub(err error, token string) error {
	if token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}

func (w *worker) sendSyslog(batch []Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		var c net.Conn
		var err error
		d := w.dialer()
		switch w.cfg.Proto {
		case "udp":
			c, err = d.Dial("udp", w.cfg.Addr)
		case "tls":
			host, _, _ := net.SplitHostPort(w.cfg.Addr)
			c, err = tls.DialWithDialer(d, "tcp", w.cfg.Addr, w.tlsConfig(host))
		default:
			c, err = d.Dial("tcp", w.cfg.Addr)
		}
		if err != nil {
			return err
		}
		w.conn = c
	}
	bw := bufio.NewWriter(w.conn)
	for _, e := range batch {
		msg := Syslog(e, w.s.now())
		if w.cfg.Proto == "udp" {
			w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := w.conn.Write([]byte(msg)); err != nil {
				w.conn.Close()
				w.conn = nil
				return err
			}
			continue
		}
		bw.WriteString(msg)
		bw.WriteByte('\n')
	}
	if w.cfg.Proto != "udp" {
		w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := bw.Flush(); err != nil {
			w.conn.Close()
			w.conn = nil
			return err
		}
	}
	return nil
}

// Syslog formats an event as an RFC 5424 message: facility local0, severity warning for a refusal,
// notice for an audit event, informational otherwise. The JSON is the message body.
func Syslog(e Event, at time.Time) string {
	sev := 6
	switch {
	case e["type"] == "audit":
		sev = 5
	case e["action"] == "deny":
		sev = 4
	}
	body, _ := json.Marshal(e)
	typ, _ := e["type"].(string)
	if typ == "" {
		typ = "-"
	}
	return fmt.Sprintf("<%d>1 %s smbztx smbztx - %s - %s", 16*8+sev, at.UTC().Format("2006-01-02T15:04:05.000Z"), typ, body)
}
