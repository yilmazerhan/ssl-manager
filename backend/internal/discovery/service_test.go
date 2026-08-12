package discovery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

func testDiscoveryService(t *testing.T) (*Service, *certificate.PostgresStore, *PostgresStore, string) {
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
	email := "discovery-test-" + uuid.NewString() + "@example.com"
	if err := pool.QueryRow(ctx, `INSERT INTO app_user (email, role) VALUES ($1, 'admin') RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM app_user WHERE id = $1`, userID)
	})

	certs := certificate.NewPostgresStore(pool)
	store := NewPostgresStore(pool)
	return NewService(store, certs), certs, store, userID
}

// listenerWithCert starts a real TLS listener presenting a certificate for
// domain, returning its address and the fingerprint a scan should observe.
func listenerWithCert(t *testing.T, domain string) (addr string, fingerprint string, closeFn func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	sum := sha256.Sum256(der)

	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				io := make([]byte, 1)
				conn.Read(io)
			}()
		}
	}()
	return listener.Addr().String(), hex.EncodeToString(sum[:]), func() { listener.Close() }
}

func mustPort(t *testing.T, addr string) (host string, port int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

func waitForTerminalStatus(t *testing.T, svc *Service, scanID string) Scan {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		sc, err := svc.GetScan(context.Background(), scanID)
		if err != nil {
			t.Fatalf("GetScan: %v", err)
		}
		switch sc.Status {
		case ScanStatusCompleted, ScanStatusPartiallyCompleted, ScanStatusFailed, ScanStatusCanceled:
			return sc
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for scan %s to finish, last status %s", scanID, sc.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestService_FullScan_ReconcilesAgainstInventory drives a real scan
// against three real local TLS listeners — one whose served certificate
// matches what's on file, one whose domain is tracked but is now serving a
// different certificate, and one this platform has never heard of — and
// checks the scan sorts them into exactly those three buckets.
func TestService_FullScan_ReconcilesAgainstInventory(t *testing.T) {
	svc, certs, store, userID := testDiscoveryService(t)
	ctx := context.Background()

	matchedAddr, matchedFingerprint, closeMatched := listenerWithCert(t, "discovery-matched.example.test")
	defer closeMatched()
	mismatchedAddr, actualFingerprint, closeMismatched := listenerWithCert(t, "discovery-mismatched.example.test")
	defer closeMismatched()
	orphanAddr, _, closeOrphan := listenerWithCert(t, "discovery-orphan.example.test")
	defer closeOrphan()

	matchedCert, err := certs.Create(ctx, certificate.Certificate{
		CommonName: "discovery-matched.example.test", SANs: []string{"discovery-matched.example.test"},
		CAProvider: "manual", ValidationMethod: "manual", Status: certificate.StatusActive,
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "discovery-test-key-1", OwningTeam: "platform-test",
	})
	if err != nil {
		t.Fatalf("create matched certificate: %v", err)
	}
	t.Cleanup(func() { store.pool.Exec(context.Background(), `DELETE FROM certificate WHERE id = $1`, matchedCert.ID) })
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: matchedCert.ID, SerialNumber: "1", FingerprintSHA256: matchedFingerprint,
		PEMCert: "n/a", PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("add matched version: %v", err)
	}

	mismatchedCert, err := certs.Create(ctx, certificate.Certificate{
		CommonName: "discovery-mismatched.example.test", SANs: []string{"discovery-mismatched.example.test"},
		CAProvider: "manual", ValidationMethod: "manual", Status: certificate.StatusActive,
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "discovery-test-key-2", OwningTeam: "platform-test",
	})
	if err != nil {
		t.Fatalf("create mismatched certificate: %v", err)
	}
	t.Cleanup(func() {
		store.pool.Exec(context.Background(), `DELETE FROM certificate WHERE id = $1`, mismatchedCert.ID)
	})
	// What's on file is deliberately NOT actualFingerprint — inventory
	// thinks a different certificate is serving this domain.
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: mismatchedCert.ID, SerialNumber: "2", FingerprintSHA256: "stale-fingerprint-on-file",
		PEMCert: "n/a", PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("add mismatched version: %v", err)
	}
	_ = actualFingerprint // documents intent: the listener serves a fingerprint that differs from the one above

	// All three listeners bind to 127.0.0.1 — one target host, three ports.
	loopback, matchedPort := mustPort(t, matchedAddr)
	_, mismatchedPort := mustPort(t, mismatchedAddr)
	_, orphanPort := mustPort(t, orphanAddr)

	sc, err := svc.CreateScan(ctx, CreateScanRequest{
		Name:    "test scan",
		Targets: []string{loopback},
		Ports:   []int{matchedPort, mismatchedPort, orphanPort},
	}, userID)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { store.pool.Exec(context.Background(), `DELETE FROM discovery_scan WHERE id = $1`, sc.ID) })

	final := waitForTerminalStatus(t, svc, sc.ID)
	if final.Status != ScanStatusCompleted {
		t.Fatalf("expected the scan to complete, got %s (%s)", final.Status, final.Error)
	}

	results, err := svc.ListResults(ctx, sc.ID)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	// 1 host x 3 ports = 3 probes; each listener only answers on its own port.
	byDomain := map[string]Result{}
	for _, r := range results {
		if r.MatchStatus != MatchStatusUnreachable && r.MatchStatus != MatchStatusNoTLS {
			for _, san := range r.SANs {
				byDomain[san] = r
			}
		}
	}

	if r, ok := byDomain["discovery-matched.example.test"]; !ok || r.MatchStatus != MatchStatusMatched {
		t.Errorf("expected discovery-matched to be MatchStatusMatched, got %+v", r)
	}
	if r, ok := byDomain["discovery-mismatched.example.test"]; !ok || r.MatchStatus != MatchStatusMismatched {
		t.Errorf("expected discovery-mismatched to be MatchStatusMismatched, got %+v", r)
	}
	if r, ok := byDomain["discovery-orphan.example.test"]; !ok || r.MatchStatus != MatchStatusNotInInventory {
		t.Errorf("expected discovery-orphan to be MatchStatusNotInInventory, got %+v", r)
	}
}

func TestService_CreateScan_RejectsEmptyTargets(t *testing.T) {
	svc, _, _, userID := testDiscoveryService(t)
	_, err := svc.CreateScan(context.Background(), CreateScanRequest{Name: "empty"}, userID)
	if err == nil {
		t.Fatal("expected an error for a scan with no targets")
	}
}

func TestService_CancelScan(t *testing.T) {
	svc, _, store, userID := testDiscoveryService(t)
	ctx := context.Background()

	// A listener that accepts the TCP connection but never speaks TLS holds
	// the probe in its handshake until its own timeout — a real in-flight
	// probe, not a fast failure, giving CancelScan an actual window to act
	// before the scan would finish on its own. (Dialing an address the
	// sandbox's network denies outright, like a documented non-routable
	// block, returns near-instantly and races the cancel instead.)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn // hold it open, never write anything
		}
	}()
	host, port := mustPort(t, listener.Addr().String())

	sc, err := svc.CreateScan(ctx, CreateScanRequest{
		Name: "cancel test", Targets: []string{host}, Ports: []int{port}, TimeoutMS: 5000,
	}, userID)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { store.pool.Exec(context.Background(), `DELETE FROM discovery_scan WHERE id = $1`, sc.ID) })

	time.Sleep(50 * time.Millisecond)
	if err := svc.CancelScan(ctx, sc.ID); err != nil {
		t.Fatalf("CancelScan: %v", err)
	}

	final := waitForTerminalStatus(t, svc, sc.ID)
	if final.Status != ScanStatusCanceled {
		t.Fatalf("expected the scan to be canceled, got %s", final.Status)
	}
}
