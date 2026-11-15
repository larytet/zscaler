// Package mux multiplexes many flow-controlled streams over one connection
// (DESIGN.md D3.1). Frame: type(1) | stream_id(4) | length(4) | payload.
package mux

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	tOpen byte = iota + 1
	tAccept
	tReject
	tData
	tFin
	tRst
	tWindow
	tPing
	tPong

	MaxFrame      = 64 * 1024
	chunk         = 16 * 1024
	InitialWindow = 256 * 1024
)

var (
	ErrClosed   = errors.New("mux: session closed")
	ErrRejected = errors.New("mux: stream rejected")
	ErrReset    = errors.New("mux: stream reset")
	ErrTooMany  = errors.New("mux: too many streams")
)

type Config struct {
	PingInterval time.Duration // default 15s
	DeadAfter    time.Duration // default 45s
	MaxStreams   int           // default 1024
	// Server picks odd stream IDs, client even, so both sides can open.
	Server bool
}

type Session struct {
	cfg  Config
	conn io.ReadWriteCloser
	br   *bufio.Reader

	wmu sync.Mutex

	mu       sync.Mutex
	streams  map[uint32]*Stream
	next     uint32
	acceptCh chan *Stream
	closed   chan struct{}
	err      error
	lastRecv time.Time
}

func New(conn io.ReadWriteCloser, cfg Config) *Session {
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 15 * time.Second
	}
	if cfg.DeadAfter == 0 {
		cfg.DeadAfter = 45 * time.Second
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 1024
	}
	s := &Session{cfg: cfg, conn: conn, br: bufio.NewReaderSize(conn, 64*1024),
		streams: map[uint32]*Stream{}, acceptCh: make(chan *Stream, 64),
		closed: make(chan struct{}), lastRecv: time.Now()}
	if cfg.Server {
		s.next = 1
	} else {
		s.next = 2
	}
	go s.readLoop()
	go s.keepalive()
	return s
}

func (s *Session) Close() error { s.fail(ErrClosed); return nil }

func (s *Session) Done() <-chan struct{} { return s.closed }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *Session) fail(err error) {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		return
	default:
	}
	s.err = err
	close(s.closed)
	streams := s.streams
	s.streams = map[uint32]*Stream{}
	s.mu.Unlock()
	s.conn.Close()
	for _, st := range streams {
		st.abort(err)
	}
}

func (s *Session) writeFrame(t byte, id uint32, p []byte) error {
	if len(p) > MaxFrame {
		return fmt.Errorf("mux: frame too large")
	}
	var h [9]byte
	h[0] = t
	binary.BigEndian.PutUint32(h[1:], id)
	binary.BigEndian.PutUint32(h[5:], uint32(len(p)))
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.conn.Write(h[:]); err != nil {
		s.fail(err)
		return err
	}
	if len(p) > 0 {
		if _, err := s.conn.Write(p); err != nil {
			s.fail(err)
			return err
		}
	}
	return nil
}

// Open starts a stream carrying meta and waits for the peer to accept it.
func (s *Session) Open(meta []byte, timeout time.Duration) (*Stream, error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.streams) >= s.cfg.MaxStreams {
		s.mu.Unlock()
		return nil, ErrTooMany
	}
	id := s.next
	s.next += 2
	st := newStream(s, id)
	st.answer = make(chan string, 1)
	s.streams[id] = st
	s.mu.Unlock()
	if err := s.writeFrame(tOpen, id, meta); err != nil {
		return nil, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case code := <-st.answer:
		if code != "" {
			s.removeStream(id)
			return nil, fmt.Errorf("%w: %s", ErrRejected, code)
		}
		return st, nil
	case <-t.C:
		st.reset()
		return nil, errors.New("mux: open timeout")
	case <-s.closed:
		return nil, ErrClosed
	}
}

// Accept returns the next peer-opened stream and its metadata. The caller
// must call Accept or Reject on the stream.
func (s *Session) Accept() (*Stream, []byte, error) {
	select {
	case st := <-s.acceptCh:
		return st, st.meta, nil
	case <-s.closed:
		return nil, nil, ErrClosed
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) readLoop() {
	var h [9]byte
	for {
		if _, err := io.ReadFull(s.br, h[:]); err != nil {
			s.fail(err)
			return
		}
		t, id, n := h[0], binary.BigEndian.Uint32(h[1:]), binary.BigEndian.Uint32(h[5:])
		if n > MaxFrame {
			s.fail(fmt.Errorf("mux: frame length %d exceeds cap", n))
			return
		}
		var p []byte
		if n > 0 {
			p = make([]byte, n)
			if _, err := io.ReadFull(s.br, p); err != nil {
				s.fail(err)
				return
			}
		}
		s.mu.Lock()
		s.lastRecv = time.Now()
		st := s.streams[id]
		s.mu.Unlock()
		switch t {
		case tPing:
			s.writeFrame(tPong, 0, nil)
		case tPong:
		case tOpen:
			s.onOpen(id, p)
		case tAccept, tReject:
			if st != nil && st.answer != nil {
				code := ""
				if t == tReject {
					code = string(p)
					if code == "" {
						code = "rejected"
					}
				}
				select {
				case st.answer <- code:
				default:
				}
			}
		case tData:
			if st == nil {
				continue // late data for a closed stream
			}
			if !st.onData(p) {
				st.reset()
			}
		case tFin:
			if st != nil {
				st.onFin()
			}
		case tRst:
			if st != nil {
				st.abort(ErrReset)
				s.removeStream(id)
			}
		case tWindow:
			if st != nil && len(p) == 4 {
				st.addCredit(int(binary.BigEndian.Uint32(p)))
			}
		default:
			s.fail(fmt.Errorf("mux: unknown frame type %d", t))
			return
		}
	}
}

func (s *Session) onOpen(id uint32, meta []byte) {
	isServerID := id%2 == 1
	s.mu.Lock()
	_, dup := s.streams[id]
	bad := isServerID == s.cfg.Server || dup || len(s.streams) >= s.cfg.MaxStreams
	var st *Stream
	if !bad {
		st = newStream(s, id)
		st.meta = meta
		s.streams[id] = st
	}
	s.mu.Unlock()
	if bad {
		s.writeFrame(tReject, id, []byte("protocol"))
		return
	}
	select {
	case s.acceptCh <- st:
	default:
		s.removeStream(id)
		s.writeFrame(tReject, id, []byte("busy"))
	}
}

func (s *Session) keepalive() {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.lastRecv)
			s.mu.Unlock()
			if idle > s.cfg.DeadAfter {
				s.fail(errors.New("mux: peer silent"))
				return
			}
			s.writeFrame(tPing, 0, nil)
		case <-s.closed:
			return
		}
	}
}

// Stream is a bidirectional byte stream. It implements io.ReadWriteCloser.
type Stream struct {
	s      *Session
	id     uint32
	meta   []byte
	answer chan string

	mu         sync.Mutex
	cond       *sync.Cond
	buf        []byte
	consumed   int
	credit     int
	remoteFin  bool
	localFin   bool
	localClose bool
	err        error
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{s: s, id: id, credit: InitialWindow}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (st *Stream) ID() uint32 { return st.id }

// Accept confirms a peer-opened stream.
func (st *Stream) Accept() error { return st.s.writeFrame(tAccept, st.id, nil) }

// Reject refuses a peer-opened stream with a short code.
func (st *Stream) Reject(code string) error {
	st.s.removeStream(st.id)
	return st.s.writeFrame(tReject, st.id, []byte(code))
}

func (st *Stream) onData(p []byte) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.localClose { // discard but return credit
		go st.s.writeFrame(tWindow, st.id, win(len(p)))
		return true
	}
	if len(st.buf)+len(p) > InitialWindow {
		return false // peer ignored flow control
	}
	st.buf = append(st.buf, p...)
	st.cond.Broadcast()
	return true
}

func (st *Stream) onFin() {
	st.mu.Lock()
	st.remoteFin = true
	st.cond.Broadcast()
	done := st.localFin
	st.mu.Unlock()
	if done {
		st.s.removeStream(st.id)
	}
}

func (st *Stream) addCredit(n int) {
	st.mu.Lock()
	st.credit += n
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) abort(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) reset() {
	st.abort(ErrReset)
	st.s.removeStream(st.id)
	st.s.writeFrame(tRst, st.id, nil)
}

func win(n int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b[:]
}

func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for len(st.buf) == 0 && !st.remoteFin && st.err == nil && !st.localClose {
		st.cond.Wait()
	}
	if len(st.buf) == 0 {
		defer st.mu.Unlock()
		switch {
		case st.err != nil:
			return 0, st.err
		case st.localClose:
			return 0, io.ErrClosedPipe
		}
		return 0, io.EOF
	}
	n := copy(p, st.buf)
	st.buf = st.buf[n:]
	st.consumed += n
	var give int
	if st.consumed >= InitialWindow/2 {
		give, st.consumed = st.consumed, 0
	}
	st.mu.Unlock()
	if give > 0 {
		st.s.writeFrame(tWindow, st.id, win(give))
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.credit == 0 && st.err == nil && !st.localFin {
			st.cond.Wait()
		}
		if st.err != nil {
			defer st.mu.Unlock()
			return total, st.err
		}
		if st.localFin {
			st.mu.Unlock()
			return total, io.ErrClosedPipe
		}
		n := len(p)
		if n > chunk {
			n = chunk
		}
		if n > st.credit {
			n = st.credit
		}
		st.credit -= n
		st.mu.Unlock()
		if err := st.s.writeFrame(tData, st.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite half-closes: the peer reads EOF but can still send.
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.localFin || st.err != nil {
		st.mu.Unlock()
		return nil
	}
	st.localFin = true
	st.cond.Broadcast()
	done := st.remoteFin
	st.mu.Unlock()
	err := st.s.writeFrame(tFin, st.id, nil)
	if done {
		st.s.removeStream(st.id)
	}
	return err
}

// Close ends both directions. Unread data is discarded.
func (st *Stream) Close() error {
	st.mu.Lock()
	st.localClose = true
	st.buf = nil
	st.cond.Broadcast()
	st.mu.Unlock()
	err := st.CloseWrite()
	st.mu.Lock()
	done := st.remoteFin || st.err != nil
	st.mu.Unlock()
	if !done {
		// peer has not closed: tear down so the stream does not linger
		st.reset()
	}
	return err
}
