package mux

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func pair(t *testing.T, cfg Config) (*Session, *Session) {
	t.Helper()
	a, b := net.Pipe()
	c, s := cfg, cfg
	c.Server, s.Server = false, true
	cl, sv := New(a, c), New(b, s)
	t.Cleanup(func() { cl.Close(); sv.Close() })
	return cl, sv
}

func echoServer(sv *Session) {
	for {
		st, _, err := sv.Accept()
		if err != nil {
			return
		}
		go func() {
			st.Accept()
			io.Copy(st, st)
			st.Close()
		}()
	}
}

func TestRoundTripAndMeta(t *testing.T) { // MUX-001
	cl, sv := pair(t, Config{})
	go func() {
		st, meta, _ := sv.Accept()
		if string(meta) != "hello" {
			t.Errorf("meta %q", meta)
		}
		st.Accept()
		io.Copy(st, st)
		st.CloseWrite()
	}()
	st, err := cl.Open([]byte("hello"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("ping"))
	st.CloseWrite()
	got, _ := io.ReadAll(st)
	if string(got) != "ping" {
		t.Fatalf("got %q", got)
	}
}

func TestReject(t *testing.T) {
	cl, sv := pair(t, Config{})
	go func() { st, _, _ := sv.Accept(); st.Reject("policy") }()
	if _, err := cl.Open(nil, time.Second); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("err %v", err)
	}
}

func TestManyStreamsIntegrity(t *testing.T) { // MUX-002
	cl, sv := pair(t, Config{MaxStreams: 2000})
	go echoServer(sv)
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := cl.Open(nil, 20*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			data := make([]byte, 40*1024)
			rand.Read(data)
			go func() { st.Write(data); st.CloseWrite() }()
			got, err := io.ReadAll(st)
			if err != nil || sha256.Sum256(got) != sha256.Sum256(data) {
				t.Errorf("mismatch err=%v len=%d", err, len(got))
			}
			st.Close()
		}()
	}
	wg.Wait()
}

func TestLargeTransferFlowControl(t *testing.T) {
	cl, sv := pair(t, Config{})
	go echoServer(sv)
	st, _ := cl.Open(nil, time.Second)
	data := make([]byte, 8<<20)
	rand.Read(data)
	go func() { st.Write(data); st.CloseWrite() }()
	got, err := io.ReadAll(st)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("err %v len %d", err, len(got))
	}
}

func TestStalledReaderDoesNotBlockOthers(t *testing.T) { // MUX-003
	cl, sv := pair(t, Config{})
	go func() {
		for {
			st, meta, err := sv.Accept()
			if err != nil {
				return
			}
			st.Accept()
			if string(meta) == "stall" {
				continue // never read
			}
			go func() { io.Copy(st, st); st.Close() }()
		}
	}()
	slow, _ := cl.Open([]byte("stall"), time.Second)
	go slow.Write(make([]byte, 4<<20)) // blocks once the window is used up
	fast, _ := cl.Open(nil, time.Second)
	done := make(chan bool)
	go func() {
		fast.Write([]byte("x"))
		b := make([]byte, 1)
		io.ReadFull(fast, b)
		done <- b[0] == 'x'
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("bad echo")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fast stream blocked by stalled stream")
	}
}

func TestResetIsolated(t *testing.T) { // MUX-004
	cl, sv := pair(t, Config{})
	go echoServer(sv)
	a, _ := cl.Open(nil, time.Second)
	b, _ := cl.Open(nil, time.Second)
	a.reset()
	b.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("b broken: %v", err)
	}
	if _, err := a.Read(buf); err == nil {
		t.Fatal("a should be reset")
	}
}

func TestDeadPeer(t *testing.T) { // MUX-005, real short timers
	a, b := net.Pipe()
	cl := New(a, Config{PingInterval: 20 * time.Millisecond, DeadAfter: 80 * time.Millisecond})
	go io.Copy(io.Discard, b) // peer reads but never answers
	select {
	case <-cl.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("session did not detect silent peer")
	}
}

func TestHalfClose(t *testing.T) { // PA-014 basis
	cl, sv := pair(t, Config{})
	go func() {
		st, _, _ := sv.Accept()
		st.Accept()
		io.ReadAll(st) // wait for client FIN
		st.Write([]byte("reply"))
		st.Close()
	}()
	st, _ := cl.Open(nil, time.Second)
	st.Write([]byte("req"))
	st.CloseWrite()
	got, _ := io.ReadAll(st)
	if string(got) != "reply" {
		t.Fatalf("got %q", got)
	}
}

func TestMaxStreams(t *testing.T) { // SEC-013
	cl, sv := pair(t, Config{MaxStreams: 3})
	go func() {
		for {
			st, _, err := sv.Accept()
			if err != nil {
				return
			}
			st.Accept()
		}
	}()
	for i := 0; i < 3; i++ {
		if _, err := cl.Open(nil, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cl.Open(nil, time.Second); err != ErrTooMany {
		t.Fatalf("got %v", err)
	}
}

func TestBadFramesCloseSession(t *testing.T) { // MUX-006
	for name, frame := range map[string][]byte{
		"oversize":     {tData, 0, 0, 0, 2, 0xff, 0xff, 0xff, 0xff},
		"unknown-type": {99, 0, 0, 0, 2, 0, 0, 0, 0},
		"truncated":    {tData, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			s := New(a, Config{})
			go func() { b.Write(frame); b.Close() }()
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("session survived a bad frame")
			}
		})
	}
}

func TestWrongParityOpenRejected(t *testing.T) {
	a, b := net.Pipe()
	s := New(a, Config{Server: true})
	defer s.Close()
	go b.Write([]byte{tOpen, 0, 0, 0, 1, 0, 0, 0, 0}) // odd id belongs to the server itself
	var h [9]byte
	if _, err := io.ReadFull(b, h[:]); err != nil || h[0] != tReject {
		t.Fatalf("type %d err %v", h[0], err)
	}
}

func FuzzFrames(f *testing.F) {
	f.Add([]byte{tOpen, 0, 0, 0, 2, 0, 0, 0, 1, 'x'})
	f.Add([]byte{tData, 0, 0, 0, 2, 0, 0, 0, 3, 'a', 'b', 'c'})
	f.Fuzz(func(t *testing.T, in []byte) {
		a, b := net.Pipe()
		s := New(a, Config{Server: true, PingInterval: time.Hour})
		go func() { b.Write(in); b.Close() }()
		go io.Copy(io.Discard, b)
		select {
		case <-s.Done():
		case <-time.After(200 * time.Millisecond):
			s.Close()
		}
	})
}
