package agent

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Stream is the subset of a mux stream the listeners need.
type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Opener opens a brokered stream to a segment's port.
type Opener func(app string, port int) (Stream, error)

func (a *Agent) opener() Opener {
	return func(app string, port int) (Stream, error) {
		c, err := a.liveConn()
		if err != nil {
			return nil, err
		}
		started := time.Now()
		st, err := c.OpenApp(app, "", port)
		if err == nil {
			a.noteAppOpen(app, time.Since(started)) // only successful opens: a refusal says nothing about speed
		}
		return st, err
	}
}

// ServeSOCKS accepts SOCKS5 CONNECT requests for "<name>.ztx" hosts and maps
// them to segments. Everything else is refused: private apps are the only
// thing this listener carries.
func (a *Agent) ServeSOCKS(ctx context.Context, ln net.Listener, open Opener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go a.socksConn(c, open)
	}
}

func (a *Agent) segmentFor(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if app, ok := a.Cfg.Apps[host]; ok {
		return app, true
	}
	return "", false
}

func (a *Agent) socksConn(c net.Conn, open Opener) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if !strings.Contains(string(methods), "\x00") {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, 0})
	var rq [4]byte
	if _, err := io.ReadFull(c, rq[:]); err != nil || rq[0] != 5 {
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if rq[1] != 1 { // CONNECT only
		reply(7)
		return
	}
	var host string
	switch rq[3] {
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default: // raw IPs are never forwarded: apps are addressed by name only
		reply(8)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	app, ok := a.segmentFor(host)
	if !ok {
		reply(2) // not allowed by ruleset
		return
	}
	st, err := open(app, port)
	if err != nil {
		if strings.Contains(err.Error(), "policy") {
			reply(2)
		} else {
			reply(4)
		}
		return
	}
	reply(0)
	c.SetDeadline(time.Time{})
	splice(c, st)
}

func splice(c net.Conn, st Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(st, c)
		st.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(c, st)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
	st.Close()
}

// ServeHTTPProxy accepts proxy requests from the browser and splices them to
// an enforcement node web proxy over mTLS. Both ends speak the HTTP proxy
// protocol, so bytes are relayed untouched and the EN does the policy.
func (a *Agent) ServeHTTPProxy(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			up, err := a.dialProxy()
			if err != nil {
				io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
				return
			}
			defer up.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, c); up.CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(c, up); done <- struct{}{} }()
			<-done
		}()
	}
}

func (a *Agent) dialProxy() (*tls.Conn, error) {
	cfg, err := a.tlsConfig(a.Cfg.ENName)
	if err != nil {
		return nil, err
	}
	var last error
	for _, addr := range a.Cfg.ProxyAddrs {
		d := net.Dialer{Timeout: 5 * time.Second}
		raw, err := d.Dial("tcp", addr)
		if err != nil {
			last = err
			continue
		}
		tc := tls.Client(raw, cfg)
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			raw.Close()
			last = err
			continue
		}
		raw.SetDeadline(time.Time{})
		return tc, nil
	}
	if last == nil {
		last = errors.New("agent: no proxy addresses configured")
	}
	return nil, last
}

// PAC returns the proxy auto-config script: *.ztx to SOCKS, the rest to the HTTP proxy.
func (a *Agent) PAC() string {
	socks, httpA := a.Cfg.SocksAddr, a.Cfg.HTTPAddr
	if socks == "" {
		socks = "127.0.0.1:1080"
	}
	if httpA == "" {
		httpA = "127.0.0.1:3129"
	}
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, ".ztx")) return "SOCKS5 %s";
  if (isPlainHostName(host) || shExpMatch(host, "localhost") || shExpMatch(host, "127.*")) return "DIRECT";
  return "PROXY %s";
}
`, socks, httpA)
}

// Status is the local, loopback-only health view.
type Status struct {
	Enrolled  bool      `json:"enrolled"`
	Expires   time.Time `json:"cert_expires,omitempty"`
	Connected bool      `json:"connected"`
	Posture   any       `json:"posture,omitempty"`
	Apps      []string  `json:"apps"`
	Version   string    `json:"version"`
}

func (a *Agent) Status() Status {
	exp, ok := a.Expires()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{Enrolled: ok, Expires: exp, Version: Version}
	if a.conn != nil {
		select {
		case <-a.conn.Sess.Done():
		default:
			s.Connected = true
		}
	}
	if a.lastPos != nil {
		s.Posture = a.lastPos
	}
	for h := range a.Cfg.Apps {
		s.Apps = append(s.Apps, h)
	}
	sort.Strings(s.Apps)
	return s
}

// StatusHandler serves /status and /proxy.pac.
func (a *Agent) StatusHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a.Status())
	})
	m.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		io.WriteString(w, a.PAC())
	})
	return m
}

// Run starts all listeners. It returns when ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	socks, httpA, status := a.Cfg.SocksAddr, a.Cfg.HTTPAddr, a.Cfg.StatusAddr
	if socks == "" {
		socks = "127.0.0.1:1080"
	}
	if httpA == "" {
		httpA = "127.0.0.1:3129"
	}
	if status == "" {
		status = "127.0.0.1:9100"
	}
	if err := checkLoopback(socks, httpA, status); err != nil {
		return err
	}
	var lns []net.Listener
	for _, addr := range []string{socks, httpA, status} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}
	go a.ServeSOCKS(ctx, lns[0], a.opener())
	go a.ServeHTTPProxy(ctx, lns[1])
	srv := &http.Server{Handler: a.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(lns[2])
	every := 5 * time.Minute
	if a.Cfg.PostureEverySeconds > 0 {
		every = time.Duration(a.Cfg.PostureEverySeconds) * time.Second
	}
	go a.PostureLoop(ctx, every)
	go a.RenewLoop(ctx, time.Hour, nil)
	<-ctx.Done()
	srv.Close()
	return nil
}
