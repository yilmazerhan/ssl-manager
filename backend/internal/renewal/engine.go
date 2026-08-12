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
	certs     certificate.Store
	orders    *order.Service
	audit     audit.Store
	notifier  notify.Sender
	settings  SettingsStore
	notifyLog NotifyLogStore
	cfg       Config
}

func NewEngine(certs certificate.Store, orders *order.Service, auditStore audit.Store, notifier notify.Sender,
	settings SettingsStore, notifyLog NotifyLogStore, cfg Config) *Engine {
	return &Engine{
		certs: certs, orders: orders, audit: auditStore, notifier: notifier,
		settings: settings, notifyLog: notifyLog, cfg: cfg.withDefaults(),
	}
}

// Run blocks, ticking immediately and then on cfg.Interval, until ctx is
// canceled.
func (e *Engine) Run(ctx context.Context) {
	e.tickRecovered(ctx)
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tickRecovered(ctx)
		}
	}
}

// tickRecovered runs one Tick with a panic recovered rather than
// propagated — this is the only long-lived background goroutine most
// deployments run, so a single bad tick (a nil pointer on an edge case, an
// unexpected type assertion) would otherwise crash the whole process and
// take every user's request down with it, not just that tick's own work.
// The loop in Run keeps going on the next interval either way.
func (e *Engine) tickRecovered(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("renewal: recovered from panic in Tick: %v", r)
		}
	}()
	e.Tick(ctx)
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
	settings, err := e.settings.Get(ctx)
	if err != nil {
		log.Printf("renewal: load notification settings: %v", err)
		return
	}
	if len(settings.ThresholdDays) == 0 {
		return
	}

	maxThreshold, minThreshold := settings.ThresholdDays[0], settings.ThresholdDays[0]
	for _, d := range settings.ThresholdDays {
		if d > maxThreshold {
			maxThreshold = d
		}
		if d < minThreshold {
			minThreshold = d
		}
	}

	certs, err := e.certs.List(ctx, certificate.Filter{ExpiringWithinDays: maxThreshold})
	if err != nil {
		log.Printf("renewal: list expiring certificates: %v", err)
		return
	}

	for _, cert := range certs {
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		for _, threshold := range settings.ThresholdDays {
			if daysRemaining != threshold {
				continue
			}
			e.sendOneReminder(ctx, cert, threshold, threshold == minThreshold, settings)
		}
	}
}

func (e *Engine) sendOneReminder(ctx context.Context, cert certificate.Certificate, threshold int, escalate bool, settings ReminderSettings) {
	alreadySent, err := e.notifyLog.HasSent(ctx, cert.ID, threshold)
	if err != nil {
		log.Printf("renewal: check notification log for %s: %v", cert.ID, err)
		return
	}
	if alreadySent {
		return
	}

	recipients := settings.DefaultRecipients
	if len(cert.NotifyEmails) > 0 {
		recipients = cert.NotifyEmails
	}
	if escalate {
		recipients = append(append([]string{}, recipients...), settings.EscalationRecipients...)
	}

	subject, body, err := renderReminder(settings.EmailSubjectTemplate, settings.EmailBodyTemplate, cert, threshold)
	if err != nil {
		log.Printf("renewal: render expiry reminder for %s: %v", cert.ID, err)
		return
	}

	sendErr := e.notifier.Send(ctx, notify.Event{
		Kind: notify.KindExpiryReminder, CertificateID: cert.ID, CommonName: cert.CommonName,
		OwningTeam: cert.OwningTeam, DaysRemaining: threshold, Subject: subject, Body: body, Recipients: recipients,
	})

	entry := NotificationLogEntry{CertificateID: cert.ID, ThresholdDays: threshold, Status: "sent", Recipients: recipients}
	if sendErr != nil {
		entry.Status = "failed"
		entry.Error = sendErr.Error()
		log.Printf("renewal: send expiry reminder for %s: %v", cert.ID, sendErr)
	}
	if err := e.notifyLog.Record(ctx, entry); err != nil {
		log.Printf("renewal: record notification log for %s: %v", cert.ID, err)
	}
}
