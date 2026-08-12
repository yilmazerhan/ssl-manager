package notify

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	Addr     string // host:port
	Username string
	Password string
	From     string
	To       []string
}

func (s *SMTPSender) Send(_ context.Context, e Event) error {
	to := e.Recipients
	if len(to) == 0 {
		to = s.To
	}
	if len(to) == 0 {
		return nil // nothing configured and no per-event override — not an error, just nowhere to send
	}

	subject := e.Subject
	if subject == "" {
		subject = fmt.Sprintf("[SSL Sentry] %s: %s", e.Kind, e.CommonName)
	}
	body := e.Body
	if body == "" {
		body = formatMessage(e)
	}
	msg := fmt.Appendf(nil, "To: %s\r\nSubject: %s\r\n\r\n%s\r\n", joinAddrs(to), subject, body)

	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, hostOnly(s.Addr))
	}

	if err := smtp.SendMail(s.Addr, auth, s.From, to, msg); err != nil {
		return fmt.Errorf("notify: send email: %w", err)
	}
	return nil
}

func joinAddrs(addrs []string) string {
	out := ""
	for i, a := range addrs {
		if i > 0 {
			out += ", "
		}
		out += a
	}
	return out
}

func hostOnly(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
