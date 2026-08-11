// Package renewal implements the scheduled worker from docs/plan.html
// section 06: scan for certificates due for renewal, drive each through
// the same order pipeline used for first-time issuance (reusing the
// existing key and validation method), retry with backoff, and notify
// either way. It also sends the expiry reminders from section 10.
package renewal

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/notify"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
)

// ReminderThresholds mirrors the escalation schedule in docs/plan.html
// section 10.
var ReminderThresholds = []int{30, 14, 7, 1}

type Config struct {
	Interval           time.Duration
	ValidateAttempts   int
	ValidateRetryDelay time.Duration
	SystemUserID       string
}

func (c Config) withDefaults() Config {
	if c.Interval == 0 {
		c.Interval = 24 * time.Hour
	}
	if c.ValidateAttempts == 0 {
		c.ValidateAttempts = 3
	}
	if c.ValidateRetryDelay == 0 {
		c.ValidateRetryDelay = 5 * time.Second
	}
	return c
}

type Engine struct {
	certs    certificate.Store
	orders   *order.Service
	audit    audit.Store
	notifier notify.Sender
	cfg      Config
}

func NewEngine(certs certificate.Store, orders *order.Service, auditStore audit.Store, notifier notify.Sender, cfg Config) *Engine {
	return &Engine{certs: certs, orders: orders, audit: auditStore, notifier: notifier, cfg: cfg.withDefaults()}
}

// Run blocks, ticking immediately and then on cfg.Interval, until ctx is
// canceled.
func (e *Engine) Run(ctx context.Context) {
	e.Tick(ctx)
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Tick(ctx)
		}
	}
}

func (e *Engine) Tick(ctx context.Context) {
	e.sendExpiryReminders(ctx)
	e.renewDueCertificates(ctx)
}

func (e *Engine) renewDueCertificates(ctx context.Context) {
	due, err := e.certs.DueForRenewal(ctx, time.Now())
	if err != nil {
		log.Printf("renewal: scan for due certificates: %v", err)
		return
	}
	for _, cert := range due {
		e.renewOne(ctx, cert)
	}
}

func (e *Engine) renewOne(ctx context.Context, cert certificate.Certificate) {
	o, err := e.RenewNow(ctx, cert, e.cfg.SystemUserID)
	if err != nil {
		e.reportFailure(ctx, cert, fmt.Sprintf("start renewal: %v", err))
		return
	}

	for attempt := 1; attempt < e.cfg.ValidateAttempts; attempt++ {
		if o.Status != order.StatusAwaitingValidation {
			break
		}
		time.Sleep(e.cfg.ValidateRetryDelay)
		o, err = e.orders.Validate(ctx, o.ID)
		if err != nil {
			e.reportFailure(ctx, cert, fmt.Sprintf("validate renewal: %v", err))
			return
		}
	}

	switch o.Status {
	case order.StatusIssued:
		e.reportSuccess(ctx, cert)
	case order.StatusFailed:
		e.reportFailure(ctx, cert, o.Error)
	default:
		e.reportFailure(ctx, cert, "validation did not complete within the retry window")
	}
}

// RenewNow starts a renewal order for cert and makes one immediate attempt
// to validate and issue it, then returns whatever state the order is in —
// issued, failed, or still awaiting_validation if domain-control proof
// hasn't been observed yet. It's what both the manual "renew now" API
// endpoint and the scheduled sweep call.
func (e *Engine) RenewNow(ctx context.Context, cert certificate.Certificate, requestedBy string) (order.Order, error) {
	o, err := e.orders.CreateRenewal(ctx, cert, requestedBy)
	if err != nil {
		return order.Order{}, err
	}
	return e.orders.Validate(ctx, o.ID)
}

func (e *Engine) reportSuccess(ctx context.Context, cert certificate.Certificate) {
	_ = e.audit.Write(ctx, audit.Entry{
		Actor: "system:renewal-engine", Action: "renewal_succeeded",
		Resource: "certificate", ResourceID: cert.ID,
	})
	_ = e.notifier.Send(ctx, notify.Event{
		Kind: notify.KindRenewalSucceeded, CertificateID: cert.ID,
		CommonName: cert.CommonName, OwningTeam: cert.OwningTeam,
	})
}

func (e *Engine) reportFailure(ctx context.Context, cert certificate.Certificate, reason string) {
	_ = e.audit.Write(ctx, audit.Entry{
		Actor: "system:renewal-engine", Action: "renewal_failed",
		Resource: "certificate", ResourceID: cert.ID,
		Metadata: map[string]interface{}{"reason": reason},
	})
	_ = e.notifier.Send(ctx, notify.Event{
		Kind: notify.KindRenewalFailed, CertificateID: cert.ID,
		CommonName: cert.CommonName, OwningTeam: cert.OwningTeam, Message: reason,
	})
}

func (e *Engine) sendExpiryReminders(ctx context.Context) {
	maxThreshold := 0
	for _, d := range ReminderThresholds {
		if d > maxThreshold {
			maxThreshold = d
		}
	}

	certs, err := e.certs.List(ctx, certificate.Filter{ExpiringWithinDays: maxThreshold})
	if err != nil {
		log.Printf("renewal: list expiring certificates: %v", err)
		return
	}

	for _, cert := range certs {
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		for _, threshold := range ReminderThresholds {
			if daysRemaining != threshold {
				continue
			}
			if err := e.notifier.Send(ctx, notify.Event{
				Kind: notify.KindExpiryReminder, CertificateID: cert.ID,
				CommonName: cert.CommonName, OwningTeam: cert.OwningTeam, DaysRemaining: daysRemaining,
			}); err != nil {
				log.Printf("renewal: send expiry reminder for %s: %v", cert.ID, err)
			}
		}
	}
}
