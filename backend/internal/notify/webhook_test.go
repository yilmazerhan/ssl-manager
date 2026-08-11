package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookSender_Send(t *testing.T) {
	var received map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewWebhookSender(server.URL)
	err := sender.Send(context.Background(), Event{
		Kind:          KindRenewalFailed,
		CommonName:    "app.example.com",
		OwningTeam:    "platform",
		DaysRemaining: 0,
		Message:       "CA rate limited",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(received["text"], "app.example.com") {
		t.Errorf("expected message to mention the domain, got %q", received["text"])
	}
	if !strings.Contains(received["text"], "CA rate limited") {
		t.Errorf("expected message to include the failure reason, got %q", received["text"])
	}
}

func TestWebhookSender_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sender := NewWebhookSender(server.URL)
	if err := sender.Send(context.Background(), Event{Kind: KindExpiryReminder}); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}
