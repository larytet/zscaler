// Package faults is a TCP proxy that injects delay and connection cuts, for
// resilience tests (TEST-PLAN.md T3.2). It cannot simulate packet loss; that
// needs kernel support (tc netem) and root.
package faults

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Proxy struct {
	Target string
	// Delay is added to every chunk in each direction.
	Delay time.Duration
	// CutAfter closes a connection once this many bytes went client-to-target (0 = never).
	CutAfter int64

	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	Cuts  atomic.Int64
}

func New(target string) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{Target: target, ln: ln}
	go p.serve()
	return p, nil
}

func (p *Proxy) Addr() string { return p.ln.Addr().String() }

func (p *Proxy) Close() {
	p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
}

// CutAll drops every open connection now.
func (p *Proxy) CutAll() {
	p.mu.Lock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", p.Target)
		if err != nil {
			c.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, c, up)
		p.mu.Unlock()
		go p.pipe(up, c, true)
		go p.pipe(c, up, false)
	}
}

func (p *Proxy) pipe(dst, src net.Conn, clientToTarget bool) {
	defer dst.Close()
	defer src.Close()
	buf := make([]byte, 16<<10)
	var sent int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if p.Delay > 0 {
				time.Sleep(p.Delay)
			}
			if clientToTarget && p.CutAfter > 0 && sent+int64(n) > p.CutAfter {
				keep := p.CutAfter - sent
				if keep > 0 {
					dst.Write(buf[:keep]) // cut in the middle of a frame
				}
				p.Cuts.Add(1)
				return
			}
			sent += int64(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}
