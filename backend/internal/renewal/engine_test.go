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

func (f *fakeCertStore) UpdateAfterRenewal(_ context.Context, id string, notBefore, notAfter time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return certificate.ErrNotFound
	}
	c.NotBefore, c.NotAfter, c.Status = notBefore, notAfter, certificate.StatusActive
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

func (f *fakeKeyManager) EnsureKey(_ context.Context, _, _ string) error { return nil }
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

func (a *instantAuthority) Issue(_ context.Context, _ ca.ProviderOrder, _ string, domains []string) (ca.IssuedCertificate, error) {
	if a.failIssue {
		return ca.IssuedCertificate{}, errors.New("simulated CA outage")
	}
	now := time.Now()
	return ca.IssuedCertificate{
		PEMCert: "fake", PEMChain: "fake", SerialNumber: "1", FingerprintSHA256: "abc",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
	}, nil
}

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

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (f *fakeNotifier) Send(_ context.Context, e notify.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

// --- tests ---

func TestEngine_RenewsExpiringCertificate(t *testing.T) {
	certs := newFakeCertStore()
	orders := newFakeOrderStore()
	authorities := ca.Registry(&instantAuthority{})
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

	engine := NewEngine(certs, orderSvc, auditStore, notifier, Config{ValidateAttempts: 1})
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
	authorities := ca.Registry(&instantAuthority{failIssue: true})
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

	engine := NewEngine(certs, orderSvc, auditStore, notifier, Config{ValidateAttempts: 1, ValidateRetryDelay: time.Millisecond})
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
	authorities := ca.Registry(&instantAuthority{})
	orderSvc := order.NewService(orders, certs, newFakeKeyManager(), authorities)

	created, _ := certs.Create(context.Background(), certificate.Certificate{
		CommonName: "fresh.example.com", SANs: []string{"fresh.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", KeyAlgorithm: "RSA-2048",
		Status: certificate.StatusActive, KeyRef: "key-3", OwningTeam: "platform",
		AutoRenew: true, RenewBeforeDays: 30,
		NotBefore: time.Now(), NotAfter: time.Now().Add(89 * 24 * time.Hour),
	})

	engine := NewEngine(certs, orderSvc, &fakeAuditStore{}, &fakeNotifier{}, Config{ValidateAttempts: 1})
	engine.Tick(context.Background())

	untouched, _ := certs.Get(context.Background(), created.ID)
	if !untouched.NotAfter.Equal(created.NotAfter) {
		t.Errorf("expected NotAfter to be unchanged, got %v (was %v)", untouched.NotAfter, created.NotAfter)
	}
}
