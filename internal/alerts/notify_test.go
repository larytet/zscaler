package alerts

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

// fakeSMTP accepts one message at a time and records it.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
	rcpt [][]string
}

func newSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	var rcpts []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			rcpts = append(rcpts, strings.Trim(strings.TrimSpace(line)[len("RCPT TO:"):], "<> "))
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, b.String())
			f.rcpt = append(f.rcpt, rcpts)
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeSMTP) wait(t *testing.T, n int) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.msgs)
		f.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d messages, got %d", n, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEmailOnNewAlert(t *testing.T) { // ALR-004
	f := newSMTP(t)
	e, _ := newEngine()
	n := &SMTPNotifier{Addr: f.ln.Addr().String(), From: "alerts@example.com", BaseURL: "https://console.example.com",
		To: func(tenant string) []string {
			if tenant == "t1" {
				return []string{"owner@example.com", "it@example.com"}
			}
			return nil
		}, Errf: func(err error) { t.Error(err) }}
	e.OnOpen = n.Notify
	for i := 0; i < 15; i++ { // only the 10th deny opens an alert, later ones add nothing
		e.Ingest(deny("u1", "erp"))
	}
	f.wait(t, 1)
	time.Sleep(200 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) != 1 {
		t.Fatalf("want exactly one email, got %d", len(f.msgs))
	}
	m := f.msgs[0]
	for _, want := range []string{"Subject: [Security alert] Alice was blocked", "What to do:", "https://console.example.com", "To: owner@example.com, it@example.com"} {
		if !strings.Contains(m, want) {
			t.Errorf("email lacks %q:\n%s", want, m)
		}
	}
	if len(f.rcpt[0]) != 2 {
		t.Errorf("recipients %v", f.rcpt[0])
	}
}

func TestNoRecipientsNoEmail(t *testing.T) {
	f := newSMTP(t)
	e, _ := newEngine()
	e.OnOpen = (&SMTPNotifier{Addr: f.ln.Addr().String(), From: "a@x", To: func(string) []string { return nil }}).Notify
	for i := 0; i < 12; i++ {
		e.Ingest(deny("u1", "erp"))
	}
	time.Sleep(300 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) != 0 {
		t.Fatal("email sent with no recipients")
	}
}

func TestHeaderInjectionBlocked(t *testing.T) {
	f := newSMTP(t)
	n := &SMTPNotifier{Addr: f.ln.Addr().String(), From: "a@x", To: func(string) []string { return []string{"o@example.com"} }}
	n.Notify(Alert{Tenant: "t1", Message: "evil\r\nBcc: attacker@example.com", Action: "x"})
	f.wait(t, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	headers := strings.SplitN(f.msgs[0], "\r\n\r\n", 2)[0]
	for _, l := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(l, "Bcc:") {
			t.Fatalf("header injection through the alert text:\n%s", headers)
		}
	}
}

func TestUnreachableSMTPReportsError(t *testing.T) {
	var got error
	n := &SMTPNotifier{Addr: "127.0.0.1:1", From: "a@x", To: func(string) []string { return []string{"o@example.com"} }, Errf: func(err error) { got = err }}
	n.Notify(Alert{Tenant: "t1", Message: "m", Action: "a"})
	if got == nil {
		t.Fatal("delivery failure was swallowed")
	}
}

var _ = broker.Record{}

func TestSendTextDigest(t *testing.T) {
	f := newSMTP(t)
	n := &SMTPNotifier{Addr: f.ln.Addr().String(), From: "alerts@example.com", To: func(tenant string) []string {
		if tenant == "t1" {
			return []string{"owner@example.com"}
		}
		return nil
	}}
	if err := n.SendText("t2", "Weekly", "body"); err != nil {
		t.Fatal(err) // no recipients is not an error
	}
	if err := n.SendText("t1", "Your weekly security summary", "Private apps: 3 allowed\r\n"); err != nil {
		t.Fatal(err)
	}
	f.wait(t, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) != 1 || !strings.Contains(f.msgs[0], "Subject: Your weekly security summary") || !strings.Contains(f.msgs[0], "Private apps: 3 allowed") {
		t.Fatalf("%v", f.msgs)
	}
}
