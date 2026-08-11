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
	subject := fmt.Sprintf("[SSL Sentry] %s: %s", e.Kind, e.CommonName)
	body := formatMessage(e)
	msg := fmt.Appendf(nil, "To: %s\r\nSubject: %s\r\n\r\n%s\r\n", joinAddrs(s.To), subject, body)

	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, hostOnly(s.Addr))
	}

	if err := smtp.SendMail(s.Addr, auth, s.From, s.To, msg); err != nil {
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
