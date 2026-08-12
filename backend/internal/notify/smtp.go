package notify

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
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

	// Recipients and the subject both ultimately trace back to
	// user-supplied data — a certificate's own notify_emails, or a domain
	// name rendered into the subject template — even though it's validated
	// closer to the source too. Strip CR/LF here as well, right before it
	// becomes a raw header line: a value containing "\r\nBcc: ..." would
	// otherwise inject an extra header into the message.
	sanitizedTo := make([]string, len(to))
	for i, addr := range to {
		sanitizedTo[i] = stripCRLF(addr)
	}
	subject = stripCRLF(subject)

	msg := fmt.Appendf(nil, "To: %s\r\nSubject: %s\r\n\r\n%s\r\n", joinAddrs(sanitizedTo), subject, body)

	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, hostOnly(s.Addr))
	}

	if err := smtp.SendMail(s.Addr, auth, s.From, sanitizedTo, msg); err != nil {
		return fmt.Errorf("notify: send email: %w", err)
	}
	return nil
}

func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
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
