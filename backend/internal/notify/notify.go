// Package notify sends the expiry/renewal alerts docs/plan.html describes
// in section 10, through whichever channels an operator has configured.
// Sending is best-effort and fans out to every configured channel — one
// channel's failure doesn't block the others.
package notify

import (
	"context"
	"errors"
)

type Kind string

const (
	KindExpiryReminder   Kind = "expiry_reminder"
	KindRenewalSucceeded Kind = "renewal_succeeded"
	KindRenewalFailed    Kind = "renewal_failed"
)

type Event struct {
	Kind          Kind
	CertificateID string
	CommonName    string
	OwningTeam    string
	DaysRemaining int
	Message       string
	// Subject and Body, when set, override each Sender's own default
	// formatting — the templated expiry-reminder path renders these from
	// notification_settings rather than the fixed per-Kind message every
	// other event still uses.
	Subject string
	Body    string
	// Recipients, when set, overrides SMTPSender's own static To list —
	// each certificate's distribution list can differ, unlike the
	// renewal-succeeded/failed events every channel is configured for
	// uniformly.
	Recipients []string
}

type Sender interface {
	Send(ctx context.Context, event Event) error
}

// MultiSender fans an event out to every sender and reports every failure
// together, rather than stopping at the first one.
type MultiSender []Sender

func (m MultiSender) Send(ctx context.Context, event Event) error {
	var errs []error
	for _, s := range m {
		if err := s.Send(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
