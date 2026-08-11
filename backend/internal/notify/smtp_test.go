package notify

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// mockSMTPServer speaks just enough SMTP to let net/smtp.SendMail complete
// a plain, unauthenticated send, and records the DATA it received so the
// test can assert on it.
func mockSMTPServer(t *testing.T) (addr string, received chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	received = make(chan string, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		write := func(s string) { conn.Write([]byte(s + "\r\n")) }

		write("220 mock.smtp ready")
		var data strings.Builder
		inData := false

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			if inData {
				if line == "." {
					inData = false
					received <- data.String()
					write("250 OK")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}

			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				write("250 mock.smtp")
			case strings.HasPrefix(upper, "MAIL FROM"):
				write("250 OK")
			case strings.HasPrefix(upper, "RCPT TO"):
				write("250 OK")
			case upper == "DATA":
				inData = true
				write("354 send data")
			case upper == "QUIT":
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()

	return listener.Addr().String(), received
}

func TestSMTPSender_Send(t *testing.T) {
	addr, received := mockSMTPServer(t)

	sender := &SMTPSender{
		Addr: addr,
		From: "ssl-sentry@example.com",
		To:   []string{"platform-team@example.com"},
	}

	if err := sender.Send(context.Background(), Event{
		Kind:       KindRenewalSucceeded,
		CommonName: "app.example.com",
		OwningTeam: "platform",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case data := <-received:
		if !strings.Contains(data, "app.example.com") {
			t.Errorf("expected email body to mention the domain, got: %s", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the mock server to receive DATA")
	}
}
