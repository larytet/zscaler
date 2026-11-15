package alerts

import (
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPNotifier emails new alerts. Recipients come from To, per tenant.
// Credentials are optional; with them set, PLAIN auth is used and Go refuses
// to send them over an unencrypted connection to a non-local server.
type SMTPNotifier struct {
	Addr     string // host:port
	From     string
	Username string
	Password string
	To       func(tenant string) []string
	BaseURL  string // optional link to the admin console
	Errf     func(error)
}

func clean(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// Notify is suitable for Engine.OnOpen.
func (n *SMTPNotifier) Notify(a Alert) {
	to := n.To(a.Tenant)
	if len(to) == 0 {
		return
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%s\r\n\r\nWhat to do: %s\r\n", a.Message, a.Action)
	if n.BaseURL != "" {
		fmt.Fprintf(&body, "\r\nSee all alerts: %s\r\n", n.BaseURL)
	}
	msg := "From: " + clean(n.From) + "\r\nTo: " + clean(strings.Join(to, ", ")) +
		"\r\nSubject: [Security alert] " + clean(a.Message) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body.String()
	var auth smtp.Auth
	if n.Username != "" {
		host := n.Addr
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		auth = smtp.PlainAuth("", n.Username, n.Password, host)
	}
	if err := smtp.SendMail(n.Addr, auth, n.From, to, []byte(msg)); err != nil && n.Errf != nil {
		n.Errf(err)
	}
}
