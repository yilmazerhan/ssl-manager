package order

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

// Integration test against a real Postgres instance for the order <->
// certificate SQL round trip (jsonb challenge storage, array columns,
// foreign keys); skipped unless DATABASE_URL is set.
func testService(t *testing.T) (*Service, string) {
	svc, userID, _ := testServiceWithAuthority(t, &fakeInstantAuthority{})
	return svc, userID
}

func testServiceWithAuthority(t *testing.T, authority ca.Authority) (*Service, string, certificate.Store) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(pool.Close)

	var userID string
	email := "order-test-" + uuid.NewString() + "@example.com"
	if err := pool.QueryRow(ctx, `INSERT INTO app_user (email, role) VALUES ($1, 'cert_manager') RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	// Runs before pool.Close (t.Cleanup is LIFO): this is a real, possibly
	// shared Postgres instance, and a stray auto_renew=true certificate
	// left behind would have the live renewal engine trying (and failing)
	// to renew a fake certificate forever.
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM certificate_order WHERE requested_by = $1`, userID); err != nil {
			t.Logf("cleanup: delete certificate_order rows: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM certificate WHERE owning_team = 'platform-test'`); err != nil {
			t.Logf("cleanup: delete certificate rows: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM app_user WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup: delete test user: %v", err)
		}
	})

	certs := certificate.NewPostgresStore(pool)
	orders := NewPostgresStore(pool)
	authorities := ca.NewRegistry(authority)
	return NewService(orders, certs, &fakeKeyManager{key: mustGenerateRSAKey(t)}, authorities), userID, certs
}

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

type fakeKeyManager struct {
	key *rsa.PrivateKey
}

func (f *fakeKeyManager) EnsureKey(context.Context, string, string, bool) error { return nil }
func (f *fakeKeyManager) Signer(context.Context, string) (crypto.Signer, error) {
	return f.key, nil
}

// fakeInstantAuthority verifies every challenge immediately, so this test
// exercises the order/certificate persistence layer without depending on a
// real CA (that's what internal/ca's own tests are for).
type fakeInstantAuthority struct{}

func (a *fakeInstantAuthority) Name() string                         { return "letsencrypt" }
func (a *fakeInstantAuthority) SupportedValidationMethods() []string { return []string{"http-01"} }

func (a *fakeInstantAuthority) RequestValidation(_ context.Context, domains []string, method, _ string) (ca.ProviderOrder, error) {
	challenges := make([]ca.Challenge, len(domains))
	for i, d := range domains {
		challenges[i] = ca.Challenge{Domain: d, Type: method}
	}
	return ca.ProviderOrder{Challenges: challenges}, nil
}

func (a *fakeInstantAuthority) CheckChallenge(_ context.Context, po ca.ProviderOrder) (ca.ProviderOrder, error) {
	for i := range po.Challenges {
		po.Challenges[i].Verified = true
	}
	return po, nil
}

func (a *fakeInstantAuthority) Issue(_ context.Context, _ ca.ProviderOrder, _ string, domains []string, _ crypto.Signer) (ca.IssuedCertificate, error) {
	return ca.IssuedCertificate{
		PEMCert: "fake-cert", PEMChain: "fake-chain", SerialNumber: "42", FingerprintSHA256: "deadbeef",
	}, nil
}

func (a *fakeInstantAuthority) Revoke(_ context.Context, _, _ string) error { return nil }

// countingAuthority wraps fakeInstantAuthority to count real Issue() calls
// — the expensive, externally-visible CA operation that must never happen
// twice for one order, no matter how many concurrent Validate calls race
// each other.
type countingAuthority struct {
	fakeInstantAuthority
	issueCount int32
}

func (a *countingAuthority) Issue(ctx context.Context, po ca.ProviderOrder, csr string, domains []string, signer crypto.Signer) (ca.IssuedCertificate, error) {
	atomic.AddInt32(&a.issueCount, 1)
	return a.fakeInstantAuthority.Issue(ctx, po, csr, domains, signer)
}

func TestService_CreateAndValidate_IssuesCertificate(t *testing.T) {
	svc, userID := testService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateRequest{
		RequestedBy: userID, OwningTeam: "platform-test",
		Domains: []string{"order-svc-test.example.com"}, CAProvider: "letsencrypt", ValidationMethod: "http-01",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Status != StatusAwaitingValidation {
		t.Fatalf("expected awaiting_validation, got %s", created.Status)
	}
	if created.KeyRef == "" {
		t.Fatalf("expected a key ref to be assigned")
	}

	// Round-trip through Postgres: Get should return exactly what Create
	// persisted, including the jsonb challenge payload.
	reloaded, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(reloaded.Challenges.Challenges) != 1 {
		t.Fatalf("expected 1 challenge to round-trip through Postgres, got %d", len(reloaded.Challenges.Challenges))
	}

	validated, err := svc.Validate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.Status != StatusIssued {
		t.Fatalf("expected issued, got %s (%s)", validated.Status, validated.Error)
	}
	if validated.CertificateID == "" {
		t.Fatalf("expected a certificate ID to be set")
	}
}

// TestValidate_ConcurrentCallsIssueOnlyOnce proves two overlapping
// Validate calls on the same order — a double-click, a client retry
// racing the renewal engine's own retry loop — can't both pass the
// AllVerified() check and both submit the CSR to the CA. Before the
// UpdateIfStatus guard in Validate, both goroutines would observe
// status == awaiting_validation and both call authority.Issue().
func TestValidate_ConcurrentCallsIssueOnlyOnce(t *testing.T) {
	authority := &countingAuthority{}
	svc, userID, _ := testServiceWithAuthority(t, authority)
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateRequest{
		RequestedBy: userID, OwningTeam: "platform-test",
		Domains: []string{"race-svc-test.example.com"}, CAProvider: "letsencrypt", ValidationMethod: "http-01",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	results := make([]Order, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = svc.Validate(ctx, created.ID)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Validate[%d]: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&authority.issueCount); got != 1 {
		t.Fatalf("expected exactly 1 CA Issue() call across %d concurrent Validate calls, got %d", n, got)
	}

	issuedSeen := false
	for _, r := range results {
		if r.Status == StatusIssued {
			issuedSeen = true
		}
	}
	if !issuedSeen {
		t.Fatalf("expected at least one concurrent Validate call to observe the issued order")
	}
}

// TestValidateDomains_RejectsInjectionAttempts proves a domain carrying
// control characters or CRLF — which would otherwise flow through to
// certificate.CommonName and, eventually, a raw SMTP header in an expiry
// reminder email — is rejected before an order is ever created from it.
func TestValidateDomains_RejectsInjectionAttempts(t *testing.T) {
	bad := []string{
		"evil.com\r\nBcc: attacker@evil.com",
		"has spaces.example.com",
		"",
		"tab\there.com",
	}
	for _, d := range bad {
		if err := validateDomains([]string{d}); err == nil {
			t.Errorf("expected %q to be rejected", d)
		}
	}
}

func TestValidateDomains_AllowsRealisticHostnames(t *testing.T) {
	good := []string{"localhost", "app.example.com", "*.kron.com.tr", "internal-app.corp.test"}
	if err := validateDomains(good); err != nil {
		t.Errorf("expected realistic hostnames to be accepted, got: %v", err)
	}
}

func TestValidateDomains_RejectsTooManyDomains(t *testing.T) {
	domains := make([]string, maxDomainsPerOrder+1)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%d.example.com", i)
	}
	if err := validateDomains(domains); err == nil {
		t.Errorf("expected more than %d domains to be rejected", maxDomainsPerOrder)
	}
}

func TestValidateSubject_AllFieldsOptional(t *testing.T) {
	if err := validateSubject("", "", "", "", ""); err != nil {
		t.Errorf("expected an entirely empty subject to be accepted, got: %v", err)
	}
}

func TestValidateSubject_AcceptsRealisticValues(t *testing.T) {
	if err := validateSubject("US", "Acme Corp", "Platform Engineering", "California", "San Francisco"); err != nil {
		t.Errorf("expected realistic subject fields to be accepted, got: %v", err)
	}
}

func TestValidateSubject_RejectsMalformedCountryCode(t *testing.T) {
	bad := []string{"USA", "u", "United States", "12"}
	for _, c := range bad {
		if err := validateSubject(c, "", "", "", ""); err == nil {
			t.Errorf("expected country %q to be rejected as not a 2-letter ISO code", c)
		}
	}
}

func TestValidateSubject_RejectsOverlongFields(t *testing.T) {
	tooLong := strings.Repeat("a", maxSubjectFieldLength+1)
	if err := validateSubject("", tooLong, "", "", ""); err == nil {
		t.Errorf("expected an overlong organization to be rejected")
	}
	if err := validateSubject("", "", tooLong, "", ""); err == nil {
		t.Errorf("expected an overlong organizational unit to be rejected")
	}
	if err := validateSubject("", "", "", tooLong, ""); err == nil {
		t.Errorf("expected an overlong state to be rejected")
	}
	if err := validateSubject("", "", "", "", tooLong); err == nil {
		t.Errorf("expected an overlong locality to be rejected")
	}
}

func TestService_CreateRenewal_UpdatesExistingCertificate(t *testing.T) {
	svc, userID := testService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateRequest{
		RequestedBy: userID, OwningTeam: "platform-test",
		Domains: []string{"renewal-svc-test.example.com"}, CAProvider: "letsencrypt", ValidationMethod: "http-01",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	issued, err := svc.Validate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	cert, err := svc.certs.Get(ctx, issued.CertificateID)
	if err != nil {
		t.Fatalf("Get certificate: %v", err)
	}

	renewalOrder, err := svc.CreateRenewal(ctx, cert, userID)
	if err != nil {
		t.Fatalf("CreateRenewal: %v", err)
	}
	if renewalOrder.CertificateID != cert.ID {
		t.Fatalf("expected renewal order to target the existing certificate, got %s want %s", renewalOrder.CertificateID, cert.ID)
	}
	if renewalOrder.KeyRef != cert.KeyRef {
		t.Fatalf("expected renewal to reuse the existing key, got %s want %s", renewalOrder.KeyRef, cert.KeyRef)
	}

	renewed, err := svc.Validate(ctx, renewalOrder.ID)
	if err != nil {
		t.Fatalf("Validate renewal: %v", err)
	}
	if renewed.Status != StatusIssued {
		t.Fatalf("expected renewal to issue, got %s (%s)", renewed.Status, renewed.Error)
	}

	versions, err := svc.certs.Versions(ctx, cert.ID)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions after a renewal (initial + renewed), got %d", len(versions))
	}
}
