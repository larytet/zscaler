package siem

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	events []Event
	auth   []string
	status atomic.Int32 // 0 means 200
	hits   atomic.Int32
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.hits.Add(1)
		if st := int(r.status.Load()); st != 0 {
			w.WriteHeader(st)
			return
		}
		sc := bufio.NewScanner(q.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.auth = append(r.auth, q.Header.Get("Authorization")+"|"+q.Header.Get("X-Key")+"|"+q.Header.Get("Content-Type"))
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				r.events = append(r.events, e)
			}
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) ca() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.srv.Certificate().Raw}))
}
func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.events) }

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func stream(t *testing.T, c Config) *Streamer {
	s := &Streamer{AllowLoopback: true, Backoff: 20 * time.Millisecond}
	if err := s.Configure("t1", &c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Configure("t1", nil) })
	return s
}

func dec(user, action string) Event {
	e, _ := NewEvent("decision", map[string]any{"ts": "2026-11-15T10:00:00Z", "user": user, "action": action, "kind": "web", "capture": map[string]string{"secret": "no"}}, "capture", "health")
	return e
}

func TestHTTPSDeliveryCarriesTheSchemaAndTheToken(t *testing.T) { // AGT-023 (INT-004)
	r := newReceiver(t)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL + "/ingest", Header: "X-Key", Token: "tok-123", CAPEM: r.ca(), Decisions: true, Audit: true})
	for i := 0; i < 5; i++ {
		s.Emit("t1", dec("alice", "allow"))
	}
	s.Emit("t1", Event{"schema": Schema, "type": "audit", "action": "policy.put"})
	waitFor(t, "six events", func() bool { return r.count() == 6 })
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.auth {
		if a != "|tok-123|application/x-ndjson" {
			t.Fatalf("headers: %q", a)
		}
	}
	e := r.events[0]
	if e["schema"] != Schema || e["type"] != "decision" || e["user"] != "alice" {
		t.Fatalf("%v", e)
	}
	if _, has := e["capture"]; has {
		t.Fatal("a capture field left the platform")
	}
	waitFor(t, "the sent count", func() bool { st, _ := s.Stats("t1"); return st.Sent == 6 })
	if st, _ := s.Stats("t1"); st.Failed != 0 || st.Dropped != 0 || st.Queued != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestRetryDeliversAfterTransientFailures(t *testing.T) { // AGT-023
	r := newReceiver(t)
	r.status.Store(503)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, CAPEM: r.ca(), Decisions: true, Audit: true})
	s.Emit("t1", dec("bob", "deny"))
	waitFor(t, "failed attempts", func() bool { return r.hits.Load() >= 3 })
	if st, _ := s.Stats("t1"); st.Sent != 0 || st.LastError == "" || st.Queued != 1 {
		t.Fatalf("the event must stay queued while the receiver is down: %+v", st)
	}
	r.status.Store(0)
	waitFor(t, "delivery after recovery", func() bool { return r.count() >= 1 })
	waitFor(t, "the sent count", func() bool { st, _ := s.Stats("t1"); return st.Sent == 1 })
	if st, _ := s.Stats("t1"); st.Failed != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestRefusalIsNotRetriedForeverAndDoesNotBlockTheQueue(t *testing.T) { // AGT-023
	r := newReceiver(t)
	r.status.Store(401)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, Token: "wrong", CAPEM: r.ca(), Decisions: true, Audit: true})
	s.Emit("t1", dec("a", "allow"))
	waitFor(t, "the refusal to be counted", func() bool { st, _ := s.Stats("t1"); return st.Failed == 1 })
	st, _ := s.Stats("t1")
	if st.Queued != 0 || !strings.Contains(st.LastError, "401") || strings.Contains(st.LastError, "wrong") {
		t.Fatalf("%+v", st)
	}
	r.status.Store(0)
	s.Emit("t1", dec("b", "allow"))
	waitFor(t, "the next event to go through", func() bool { return r.count() == 1 })
}

func TestQueueIsBoundedAndCountsWhatItDrops(t *testing.T) { // AGT-023
	r := newReceiver(t)
	r.status.Store(503)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, CAPEM: r.ca(), Decisions: true, Audit: true})
	for i := 0; i < QueueMax+250; i++ {
		s.Emit("t1", dec("x", "allow"))
	}
	st, _ := s.Stats("t1")
	if st.Queued > QueueMax || st.Dropped < 250-BatchMax {
		t.Fatalf("the queue must be bounded and the loss counted: %+v", st)
	}
}

func TestSyslogOverTCPAndUDP(t *testing.T) { // AGT-023 (ADM-006a)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 20)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					lines <- sc.Text()
				}
			}()
		}
	}()
	s := stream(t, Config{Kind: "syslog", Addr: ln.Addr().String(), Decisions: true, Audit: true})
	s.Emit("t1", dec("alice", "deny"))
	s.Emit("t1", dec("alice", "allow"))
	s.Emit("t1", Event{"schema": Schema, "type": "audit", "action": "policy.put"})
	var got []string
	for len(got) < 3 {
		select {
		case l := <-lines:
			got = append(got, l)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d lines: %v", len(got), got)
		}
	}
	for i, want := range []string{"<132>1 ", "<134>1 ", "<133>1 "} {
		if !strings.HasPrefix(got[i], want) || !strings.Contains(got[i], " smbztx smbztx - ") {
			t.Errorf("line %d: %s", i, got[i])
		}
	}
	if !strings.Contains(got[0], ` - decision - {`) || !strings.Contains(got[0], `"user":"alice"`) || strings.Contains(got[0], "capture") {
		t.Errorf("%s", got[0])
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u := &Streamer{AllowLoopback: true, Backoff: 20 * time.Millisecond}
	if err := u.Configure("t2", &Config{Kind: "syslog", Proto: "udp", Addr: pc.LocalAddr().String(), Decisions: true, Audit: true}); err != nil {
		t.Fatal(err)
	}
	defer u.Configure("t2", nil)
	u.Emit("t2", dec("carol", "allow"))
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), `"user":"carol"`) {
		t.Fatalf("udp: %v %q", err, buf[:n])
	}
}

func TestOnlyWhatTheTenantAskedForIsSent(t *testing.T) { // AGT-023
	r := newReceiver(t)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, CAPEM: r.ca(), Decisions: true})
	s.Emit("t1", Event{"schema": Schema, "type": "audit", "action": "x"})
	s.Emit("t1", dec("a", "allow"))
	s.Emit("other", dec("zzz", "allow")) // a tenant with no sink
	waitFor(t, "the decision", func() bool { return r.count() == 1 })
	time.Sleep(200 * time.Millisecond)
	if r.count() != 1 || r.events[0]["type"] != "decision" {
		t.Fatalf("%v", r.events)
	}
	if _, ok := s.Stats("other"); ok {
		t.Fatal("a tenant without a sink has statistics")
	}
}

func TestValidation(t *testing.T) { // AGT-023
	ok := Config{Kind: "https", URL: "https://siem.example.com/in", Decisions: true, Audit: true}
	if c, err := Validate(ok, false); err != nil || c.Header != "Authorization" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Validate(Config{Kind: "syslog", Addr: "10.1.2.3:514", Decisions: true}, false); err != nil {
		t.Fatalf("a private address is fine: %v", err)
	}
	bad := map[string]Config{
		"http":               {Kind: "https", URL: "http://siem.example.com", Decisions: true},
		"metadata address":   {Kind: "https", URL: "https://169.254.169.254/latest", Decisions: true},
		"link-local syslog":  {Kind: "syslog", Addr: "169.254.1.1:514", Decisions: true},
		"loopback":           {Kind: "https", URL: "https://127.0.0.1/x", Decisions: true},
		"localhost":          {Kind: "https", URL: "https://localhost/x", Decisions: true},
		"unspecified":        {Kind: "syslog", Addr: "0.0.0.0:514", Decisions: true},
		"credentials in url": {Kind: "https", URL: "https://u:p@siem.example.com", Decisions: true},
		"bad header":         {Kind: "https", URL: "https://siem.example.com", Header: "Host", Decisions: true},
		"header injection":   {Kind: "https", URL: "https://siem.example.com", Header: "X-A\r\nB", Decisions: true},
		"multi-line token":   {Kind: "https", URL: "https://siem.example.com", Token: "a\nb", Decisions: true},
		"bad CA":             {Kind: "https", URL: "https://siem.example.com", CAPEM: "not a certificate", Decisions: true},
		"syslog no port":     {Kind: "syslog", Addr: "siem.example.com", Decisions: true},
		"syslog bad proto":   {Kind: "syslog", Addr: "siem.example.com:514", Proto: "icmp", Decisions: true},
		"nothing to send":    {Kind: "https", URL: "https://siem.example.com"},
		"no kind":            {URL: "https://siem.example.com", Decisions: true},
	}
	for name, c := range bad {
		if _, err := Validate(c, false); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := Validate(Config{Kind: "https", URL: "https://127.0.0.1:9/x", Decisions: true}, true); err != nil {
		t.Errorf("loopback must be allowed in the lab mode: %v", err)
	}
	for _, ip := range []string{"169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1"} {
		if checkIP(net.ParseIP(ip), true) == nil {
			t.Errorf("%s must be refused even in the lab mode", ip)
		}
	}
}

func TestTokenIsScrubbedFromErrors(t *testing.T) { // AGT-023
	if got := scrub(&net.OpError{Op: "dial", Err: net.UnknownNetworkError("secret-token-9 unreachable")}, "secret-token-9").Error(); strings.Contains(got, "secret-token-9") {
		t.Fatalf("%s", got)
	}
}

func TestConfigureNilStopsTheSink(t *testing.T) { // AGT-023
	r := newReceiver(t)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, CAPEM: r.ca(), Decisions: true, Audit: true})
	s.Emit("t1", dec("a", "allow"))
	waitFor(t, "one event", func() bool { return r.count() == 1 })
	s.Configure("t1", nil)
	s.Emit("t1", dec("b", "allow"))
	time.Sleep(300 * time.Millisecond)
	if r.count() != 1 {
		t.Fatal("events were sent after the sink was removed")
	}
	if err := s.Test("t1"); err == nil {
		t.Fatal("a test with no sink must say so")
	}
}

func TestTestEvent(t *testing.T) { // AGT-023
	r := newReceiver(t)
	s := stream(t, Config{Kind: "https", URL: r.srv.URL, CAPEM: r.ca(), Decisions: true, Audit: true})
	if err := s.Test("t1"); err != nil {
		t.Fatal(err)
	}
	if r.count() != 1 || r.events[0]["type"] != "test" {
		t.Fatalf("%v", r.events)
	}
	r.status.Store(500)
	if err := s.Test("t1"); err == nil {
		t.Fatal("a receiver error must be reported by the test")
	}
}
