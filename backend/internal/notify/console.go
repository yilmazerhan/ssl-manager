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
	if e.Subject != "" || len(e.Recipients) > 0 {
		log.Printf("[notify] %s cert=%s to=%v subject=%q: %s", e.Kind, e.CertificateID, e.Recipients, e.Subject, e.Body)
		return nil
	}
	log.Printf("[notify] %s cert=%s (%s) team=%s days_remaining=%d: %s",
		e.Kind, e.CommonName, e.CertificateID, e.OwningTeam, e.DaysRemaining, e.Message)
	return nil
}
