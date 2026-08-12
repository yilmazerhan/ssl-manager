package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookSender posts to any Slack- or Teams-compatible incoming webhook
// URL, which both platforms satisfy with a JSON body carrying a "text"
// field.
type WebhookSender struct {
	URL    string
	Client *http.Client
}

func NewWebhookSender(url string) *WebhookSender {
	return &WebhookSender{URL: url, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (w *WebhookSender) Send(ctx context.Context, e Event) error {
	text := e.Body
	if text == "" {
		text = formatMessage(e)
	}
	if e.Subject != "" {
		text = e.Subject + "\n" + text
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return fmt.Errorf("notify: marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.Client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: send webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func formatMessage(e Event) string {
	switch e.Kind {
	case KindExpiryReminder:
		return fmt.Sprintf("⏳ %s (team %s) expires in %d day(s).", e.CommonName, e.OwningTeam, e.DaysRemaining)
	case KindRenewalSucceeded:
		return fmt.Sprintf("✅ %s (team %s) renewed successfully.", e.CommonName, e.OwningTeam)
	case KindRenewalFailed:
		return fmt.Sprintf("🚨 %s (team %s) failed to renew: %s", e.CommonName, e.OwningTeam, e.Message)
	default:
		return e.Message
	}
}
