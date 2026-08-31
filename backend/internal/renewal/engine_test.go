package renewal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/notify"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
)

// --- lightweight in-memory fakes, scoped to this test ---

type fakeCertStore struct {
	mu    sync.Mutex
	certs map[string]certificate.Certificate
	vers  map[string][]certificate.Version
	seq   int
}

func newFakeCertStore() *fakeCertStore {
	return &fakeCertStore{certs: map[string]certificate.Certificate{}, vers: map[string][]certificate.Version{}}
}

func (f *fakeCertStore) Create(_ context.Context, c certificate.Certificate) (certificate.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	c.ID = "cert-" + string(rune('a'+f.seq))
	f.certs[c.ID] = c
	return c, nil
}

func (f *fakeCertStore) Get(_ context.Context, id string) (certificate.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return certificate.Certificate{}, certificate.ErrNotFound
	}
	return c, nil
}

func (f *fakeCertStore) List(_ context.Context, filter certificate.Filter) ([]certificate.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []certificate.Certificate
	for _, c := range f.certs {
		if filter.ExpiringWithinDays > 0 && time.Until(c.NotAfter) > time.Duration(filter.ExpiringWithinDays)*24*time.Hour {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeCertStore) Stats(_ context.Context, team string) (certificate.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := certificate.Stats{ByStatus: map[string]int{}, ByCAProvider: map[string]int{}, ByTeam: map[string]int{}}
	for _, c := range f.certs {
		if team != "" && c.OwningTeam != team {
			continue
		}
		stats.Total++
		stats.ByStatus[string(c.Status)]++
		stats.ByCAProvider[c.CAProvider]++
		stats.ByTeam[c.OwningTeam]++
	}
	return stats, nil
}

func (f *fakeCertStore) UpdateAfterRenewal(_ context.Context, id string, notBefore, notAfter time.Time, caReference string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return certificate.ErrNotFound
	}
	c.NotBefore, c.NotAfter, c.Status, c.CAReference = notBefore, notAfter, certificate.StatusActive, caReference
	f.certs[id] = c
	return nil
}

func (f *fakeCertStore) UpdateNotifyEmails(_ context.Context, id string, emails []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return certificate.ErrNotFound
	}
	c.NotifyEmails = emails
	f.certs[id] = c
	return nil
}

func (f *fakeCertStore) Revoke(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return certificate.ErrNotFound
	}
	c.Status = certificate.StatusRevoked
	f.certs[id] = c
	return nil
}

func (f *fakeCertStore) DueForRenewal(_ context.Context, asOf time.Time) ([]certificate.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []certificate.Certificate
	for _, c := range f.certs {
		if c.AutoRenew && asOf.Add(time.Duration(c.RenewBeforeDays)*24*time.Hour).After(c.NotAfter) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeCertStore) AddVersion(_ context.Context, v certificate.Version) (certificate.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vers[v.CertificateID] = append(f.vers[v.CertificateID], v)
	return v, nil
}

func (f *fakeCertStore) Versions(_ context.Context, id string) ([]certificate.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vers[id], nil
}

func (f *fakeCertStore) LatestVersion(_ context.Context, id string) (certificate.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	vs := f.vers[id]
	if len(vs) == 0 {
		return certificate.Version{}, certificate.ErrNotFound
	}
	return vs[len(vs)-1], nil
}

func (f *fakeCertStore) FinalizeNewCertificate(ctx context.Context, c certificate.Certificate, v certificate.Version) (certificate.Certificate, certificate.Version, error) {
	created, err := f.Create(ctx, c)
	if err != nil {
		return certificate.Certificate{}, certificate.Version{}, err
	}
	v.CertificateID = created.ID
	createdVersion, err := f.AddVersion(ctx, v)
	if err != nil {
		return certificate.Certificate{}, certificate.Version{}, err
	}
	return created, createdVersion, nil
}

func (f *fakeCertStore) FinalizeRenewal(ctx context.Context, id string, notBefore, notAfter time.Time, caReference string, v certificate.Version) (certificate.Version, error) {
	if err := f.UpdateAfterRenewal(ctx, id, notBefore, notAfter, caReference); err != nil {
		return certificate.Version{}, err
	}
	v.CertificateID = id
	return f.AddVersion(ctx, v)
}

type fakeOrderStore struct {
	mu     sync.Mutex
	orders map[string]order.Order
	seq    int
}

func newFakeOrderStore() *fakeOrderStore {
	return &fakeOrderStore{orders: map[string]order.Order{}}
}

func (f *fakeOrderStore) Create(_ context.Context, o order.Order) (order.Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	o.ID = "order-" + string(rune('a'+f.seq))
	f.orders[o.ID] = o
	return o, nil
}

func (f *fakeOrderStore) Get(_ context.Context, id string) (order.Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orders[id]
	if !ok {
		return order.Order{}, order.ErrNotFound
	}
	return o, nil
}

func (f *fakeOrderStore) Update(_ context.Context, o order.Order) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orders[o.ID] = o
	return nil
}

func (f *fakeOrderStore) UpdateIfStatus(_ context.Context, o order.Order, expected order.Status) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.orders[o.ID]
	if !ok || existing.Status != expected {
		return false, nil
	}
	f.orders[o.ID] = o
	return true, nil
}

// fakeKeyManager signs with an in-memory RSA key — no Vault involved. It
// exists so this test exercises renewal *orchestration* in isolation from
// the (separately, and already) integration-tested Vault signing path.
type fakeKeyManager struct {
	key *rsa.PrivateKey
}

func newFakeKeyManager() *fakeKeyManager {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &fakeKeyManager{key: key}
}

func (f *fakeKeyManager) EnsureKey(_ context.Context, _, _ string, _ bool) error { return nil }
func (f *fakeKeyManager) Signer(_ context.Context, _ string) (crypto.Signer, error) {
	return f.key, nil
}

// instantAuthority verifies every challenge immediately and issues a
// deterministic fake certificate, so this test can drive many renewal
// ticks fast without touching a real CA.
type instantAuthority struct {
	failIssue bool
}

func (a *instantAuthority) Name() string                         { return "letsencrypt" }
func (a *instantAuthority) SupportedValidationMethods() []string { return []string{"http-01"} }

func (a *instantAuthority) RequestValidation(_ context.Context, domains []string, method, _ string) (ca.ProviderOrder, error) {
	return ca.ProviderOrder{Challenges: []ca.Challenge{{Domain: domains[0], Type: method, Verified: false}}}, nil
}

func (a *instantAuthority) CheckChallenge(_ context.Context, po ca.ProviderOrder) (ca.ProviderOrder, error) {
	for i := range po.Challenges {
		po.Challenges[i].Verified = true
	}
	return po, nil
}

func (a *instantAuthority) Issue(_ context.Context, _ ca.ProviderOrder, _ string, domains []string, _ crypto.Signer) (ca.IssuedCertificate, error) {
	if a.failIssue {
		return ca.IssuedCertificate{}, errors.New("simulated CA outage")
	}
	now := time.Now()
	return ca.IssuedCertificate{
		PEMCert: "fake", PEMChain: "fake", SerialNumber: "1", FingerprintSHA256: "abc",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
	}, nil
}

func (a *instantAuthority) Revoke(_ context.Context, _, _ string) error { return nil }

type fakeAuditStore struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (f *fakeAuditStore) Write(_ context.Context, e audit.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
	return nil
}
func (f *fakeAuditStore) ForResource(context.Context, string, string) ([]audit.Record, error) {
	return nil, nil
}
func (f *fakeAuditStore) List(context.Context, audit.ListFilter) ([]audit.Record, error) {
	return nil, nil
}

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
	fail   bool
}

func (f *fakeNotifier) Send(_ context.Context, e notify.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	if f.fail {
		return errors.New("simulated notifier outage")
	}
	return nil
}

// fakeSettingsStore is an in-memory ReminderSettings — the real store is
// separately covered by settings_test.go's Postgres round trip.
type fakeSettingsStore struct {
	settings ReminderSettings
}

func newFakeSettingsStore(thresholds ...int) *fakeSettingsStore {
	return &fakeSettingsStore{settings: ReminderSettings{
		ThresholdDays:        thresholds,
		EmailSubjectTemplate: "{{.CommonName}} expires in {{.DaysRemaining}}d",
		EmailBodyTemplate:    "{{.CommonName}} ({{.OwningTeam}}) expires {{.NotAfter}}",
	}}
}

func (f *fakeSettingsStore) Get(context.Context) (ReminderSettings, error) { return f.settings, nil }
func (f *fakeSettingsStore) Update(_ context.Context, s ReminderSettings) error {
	f.settings = s
	return nil
}

// fakeNotifyLogStore is an in-memory NotifyLogStore.
type fakeNotifyLogStore struct {
	mu      sync.Mutex
	entries []NotificationLogEntry
}

func (f *fakeNotifyLogStore) HasSent(_ context.Context, certificateID string, thresholdDays int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.CertificateID == certificateID && e.ThresholdDays == thresholdDays && e.Status == "sent" {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeNotifyLogStore) Record(_ context.Context, entry NotificationLogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if entry.SentAt.IsZero() {
		entry.SentAt = time.Now()
	}
	f.entries = append(f.entries, entry)
	return nil
}

func (f *fakeNotifyLogStore) ForCertificate(_ context.Context, certificateID string) ([]NotificationLogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []NotificationLogEntry
	for _, e := range f.entries {
		if e.CertificateID == certificateID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeNotifyLogStore) Recent(_ context.Context, limit int) ([]NotificationLogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]NotificationLogEntry{}, f.entries...), nil
}

func (f *fakeNotifyLogStore) Stats(_ context.Context, since time.Time) (sent, failed int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.SentAt.Before(since) {
			continue
		}
		switch e.Status {
		case "sent":
			sent++
		case "failed":
			failed++
		}
	}
	return sent, failed, nil
}

// --- tests ---

func TestEngine_RenewsExpiringCertificate(t *testing.T) {
	certs := newFakeCertStore()
	orders := newFakeOrderStore()
	authorities := ca.NewRegistry(&instantAuthority{})
	orderSvc := order.NewService(orders, certs, newFakeKeyManager(), authorities)
	auditStore := &fakeAuditStore{}
	notifier := &fakeNotifier{}

	created, _ := certs.Create(context.Background(), certificate.Certificate{
		CommonName: "app.example.com", SANs: []string{"app.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", KeyAlgorithm: "RSA-2048",
		Status: certificate.StatusActive, KeyRef: "key-1", OwningTeam: "platform",
		AutoRenew: true, RenewBeforeDays: 30,
		NotBefore: time.Now().Add(-60 * 24 * time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour),
	})

	engine := NewEngine(certs, orderSvc, auditStore, notifier, newFakeSettingsStore(30, 15, 7, 1), &fakeNotifyLogStore{}, Config{ValidateAttempts: 1})
	engine.Tick(context.Background())

	renewed, err := certs.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !renewed.NotAfter.After(time.Now().Add(80 * 24 * time.Hour)) {
		t.Errorf("expected NotAfter to be pushed out ~90 days, got %v", renewed.NotAfter)
	}

	found := false
	for _, e := range notifier.events {
		if e.Kind == notify.KindRenewalSucceeded && e.CertificateID == created.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a renewal_succeeded notification, got %+v", notifier.events)
	}
}

func TestEngine_ReportsRenewalFailure(t *testing.T) {
	certs := newFakeCertStore()
	orders := newFakeOrderStore()
	authorities := ca.NewRegistry(&instantAuthority{failIssue: true})
	orderSvc := order.NewService(orders, certs, newFakeKeyManager(), authorities)
	auditStore := &fakeAuditStore{}
	notifier := &fakeNotifier{}

	created, _ := certs.Create(context.Background(), certificate.Certificate{
		CommonName: "broken.example.com", SANs: []string{"broken.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", KeyAlgorithm: "RSA-2048",
		Status: certificate.StatusActive, KeyRef: "key-2", OwningTeam: "platform",
		AutoRenew: true, RenewBeforeDays: 30,
		NotBefore: time.Now().Add(-60 * 24 * time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour),
	})

	engine := NewEngine(certs, orderSvc, auditStore, notifier, newFakeSettingsStore(30, 15, 7, 1), &fakeNotifyLogStore{}, Config{ValidateAttempts: 1, ValidateRetryDelay: time.Millisecond})
	engine.Tick(context.Background())

	found := false
	for _, e := range notifier.events {
		if e.Kind == notify.KindRenewalFailed && e.CertificateID == created.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a renewal_failed notification, got %+v", notifier.events)
	}
}

func TestEngine_DoesNotRenewCertificateNotYetDue(t *testing.T) {
	certs := newFakeCertStore()
	orders := newFakeOrderStore()
	authorities := ca.NewRegistry(&instantAuthority{})
	orderSvc := order.NewService(orders, certs, newFakeKeyManager(), authorities)

	created, _ := certs.Create(context.Background(), certificate.Certificate{
		CommonName: "fresh.example.com", SANs: []string{"fresh.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", KeyAlgorithm: "RSA-2048",
		Status: certificate.StatusActive, KeyRef: "key-3", OwningTeam: "platform",
		AutoRenew: true, RenewBeforeDays: 30,
		NotBefore: time.Now(), NotAfter: time.Now().Add(89 * 24 * time.Hour),
	})

	engine := NewEngine(certs, orderSvc, &fakeAuditStore{}, &fakeNotifier{}, newFakeSettingsStore(30, 15, 7, 1), &fakeNotifyLogStore{}, Config{ValidateAttempts: 1})
	engine.Tick(context.Background())

	untouched, _ := certs.Get(context.Background(), created.ID)
	if !untouched.NotAfter.Equal(created.NotAfter) {
		t.Errorf("expected NotAfter to be unchanged, got %v (was %v)", untouched.NotAfter, created.NotAfter)
	}
}

func TestEngine_SendsTemplatedExpiryReminder_WithEscalationAndDedupe(t *testing.T) {
	certs := newFakeCertStore()
	orders := newFakeOrderStore()
	authorities := ca.NewRegistry(&instantAuthority{})
	orderSvc := order.NewService(orders, certs, newFakeKeyManager(), authorities)
	notifier := &fakeNotifier{}
	notifyLog := &fakeNotifyLogStore{}
	settings := newFakeSettingsStore(30, 15, 7, 1)
	settings.settings.DefaultRecipients = []string{"team@example.com"}
	settings.settings.EscalationRecipients = []string{"oncall@example.com"}

	created, _ := certs.Create(context.Background(), certificate.Certificate{
		CommonName: "urgent.example.com", SANs: []string{"urgent.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", KeyAlgorithm: "RSA-2048",
		Status: certificate.StatusActive, KeyRef: "key-urgent", OwningTeam: "platform",
		AutoRenew: false, // isolate the reminder path from the renewal path in this test
		NotBefore: time.Now().Add(-89 * 24 * time.Hour), NotAfter: time.Now().Add(24*time.Hour + 10*time.Minute),
	})

	engine := NewEngine(certs, orderSvc, &fakeAuditStore{}, notifier, settings, notifyLog, Config{ValidateAttempts: 1})
	engine.Tick(context.Background())

	var reminder *notify.Event
	for i := range notifier.events {
		if notifier.events[i].Kind == notify.KindExpiryReminder && notifier.events[i].CertificateID == created.ID {
			reminder = &notifier.events[i]
		}
	}
	if reminder == nil {
		t.Fatalf("expected an expiry reminder to be sent, got %+v", notifier.events)
	}
	if reminder.Subject != "urgent.example.com expires in 1d" {
		t.Errorf("expected the subject to be rendered from the template, got %q", reminder.Subject)
	}
	wantRecipients := []string{"team@example.com", "oncall@example.com"}
	if len(reminder.Recipients) != len(wantRecipients) {
		t.Fatalf("expected escalation recipients to be included at the most urgent threshold, got %v", reminder.Recipients)
	}
	for i, want := range wantRecipients {
		if reminder.Recipients[i] != want {
			t.Errorf("recipient[%d]: got %q want %q", i, reminder.Recipients[i], want)
		}
	}

	sent, err := notifyLog.HasSent(context.Background(), created.ID, 1)
	if err != nil || !sent {
		t.Fatalf("expected the notification log to record this send, HasSent=%v err=%v", sent, err)
	}

	// A second tick must not notify again for the same certificate+threshold.
	notifier.events = nil
	engine.Tick(context.Background())
	for _, e := range notifier.events {
		if e.Kind == notify.KindExpiryReminder && e.CertificateID == created.ID {
			t.Fatalf("expected no duplicate expiry reminder on a second tick, got %+v", e)
		}
	}
}
