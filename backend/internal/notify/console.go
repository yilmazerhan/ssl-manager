package notify

import (
	"context"
	"log"
)

// ConsoleSender is the zero-config default: every event lands in the
// backend's own logs. It's what a fresh checkout notifies through until an
// operator configures SMTP or a webhook.
type ConsoleSender struct{}

func (ConsoleSender) Send(_ context.Context, e Event) error {
	log.Printf("[notify] %s cert=%s (%s) team=%s days_remaining=%d: %s",
		e.Kind, e.CommonName, e.CertificateID, e.OwningTeam, e.DaysRemaining, e.Message)
	return nil
}
