package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/larytet/zscaler/internal/mux"
)

// Conn is an agent-side session to an EN.
type Conn struct {
	Sess *mux.Session
}

// Dial connects to an EN over mTLS and starts a mux session.
func Dial(addr string, cfg *tls.Config) (*Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return &Conn{Sess: mux.New(tc, mux.Config{})}, nil
}

func (c *Conn) Close() error { return c.Sess.Close() }

// OpenApp asks the EN for a stitched session to a segment's target port.
// host may be empty when the segment has a single target.
func (c *Conn) OpenApp(app, host string, port int) (*mux.Stream, error) {
	meta, _ := json.Marshal(openReq{T: "open", App: app, Host: host, Port: port})
	return c.Sess.Open(meta, 10*time.Second)
}

// SendPosture sends a signed posture report token.
func (c *Conn) SendPosture(token string) error {
	meta, _ := json.Marshal(openReq{T: "posture", Tok: token})
	st, err := c.Sess.Open(meta, 5*time.Second)
	if err != nil {
		return err
	}
	return st.Close()
}

// Connector runs inside the customer network. It only dials out.
type Connector struct {
	Addr   string
	TLS    *tls.Config
	Allow  func(host string, port int) bool // target allow-list
	Dial   func(network, addr string, d time.Duration) (net.Conn, error)
	Events func(string)
}

func (c *Connector) event(s string) {
	if c.Events != nil {
		c.Events(s)
	}
}

// Run connects and serves until ctx ends, reconnecting with backoff and jitter.
func (c *Connector) Run(ctx context.Context) {
	delay := 100 * time.Millisecond
	for ctx.Err() == nil {
		conn, err := Dial(c.Addr, c.TLS)
		if err != nil {
			c.event("dial-failed")
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay + time.Duration(rand.Int63n(int64(delay/2+1)))):
			}
			if delay *= 2; delay > 30*time.Second {
				delay = 30 * time.Second
			}
			continue
		}
		delay = 100 * time.Millisecond
		c.event("connected")
		c.serve(ctx, conn.Sess)
		c.event("disconnected")
	}
}

func (c *Connector) serve(ctx context.Context, s *mux.Session) {
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.Done():
		}
	}()
	for {
		st, meta, err := s.Accept()
		if err != nil {
			return
		}
		go c.handle(st, meta)
	}
}

func (c *Connector) handle(st *mux.Stream, meta []byte) {
	var rq openReq
	if json.Unmarshal(meta, &rq) != nil || rq.Host == "" || rq.Port <= 0 || rq.Port > 65535 {
		st.Reject("bad-request")
		return
	}
	if c.Allow == nil || !c.Allow(rq.Host, rq.Port) {
		c.event(fmt.Sprintf("refused %s:%d", rq.Host, rq.Port))
		st.Reject("not-allowed")
		return
	}
	dial := c.Dial
	if dial == nil {
		dial = func(n, a string, d time.Duration) (net.Conn, error) { return net.DialTimeout(n, a, d) }
	}
	up, err := dial("tcp", net.JoinHostPort(rq.Host, itoa(rq.Port)), 3*time.Second)
	if err != nil {
		st.Reject("connect-failed")
		return
	}
	st.Accept()
	var wg = make(chan struct{}, 2)
	go func() { io.Copy(up, st); up.(interface{ CloseWrite() error }).CloseWrite(); wg <- struct{}{} }()
	go func() { io.Copy(st, up); st.CloseWrite(); wg <- struct{}{} }()
	<-wg
	<-wg
	up.Close()
	st.Close()
}
