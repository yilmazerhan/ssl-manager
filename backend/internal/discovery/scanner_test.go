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
	"testing"
	"time"
)

func TestExpandTargets(t *testing.T) {
	out, err := expandTargets([]string{"host.example.test", "10.0.0.0/30"})
	if err != nil {
		t.Fatalf("expandTargets: %v", err)
	}
	// 10.0.0.0/30 has 4 addresses (.0-.3); plus the one hostname.
	if len(out) != 5 {
		t.Fatalf("expected 5 expanded targets, got %d: %v", len(out), out)
	}
}

func TestExpandTargets_RejectsOversizedRange(t *testing.T) {
	// A /8 expands to ~16.7 million addresses, far past MaxTargetsExpanded.
	_, err := expandTargets([]string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("expected an error for a range far exceeding the safety cap")
	}
}

// mustSelfSignedTLSListener starts a real TLS listener on 127.0.0.1
// presenting a known self-signed certificate, so probe() can be tested
// against a genuine TLS handshake rather than a mock.
func mustSelfSignedTLSListener(t *testing.T) (addr string, fingerprint string, close func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scanner-test.example.test"},
		DNSNames:     []string{"scanner-test.example.test"},
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
				buf := make([]byte, 1)
				conn.Read(buf) // complete the handshake, then drop
			}()
		}
	}()
	return listener.Addr().String(), hex.EncodeToString(sum[:]), func() { listener.Close() }
}

func TestProbe_LiveTLSHandshake(t *testing.T) {
	addr, wantFingerprint, closeFn := mustSelfSignedTLSListener(t)
	defer closeFn()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	result := probe(context.Background(), host, port, 2*time.Second)
	if !result.Reachable {
		t.Fatalf("expected the listener to be reachable, error: %s", result.Error)
	}
	if result.NoTLS {
		t.Fatalf("expected a completed TLS handshake, error: %s", result.Error)
	}
	if result.CommonName != "scanner-test.example.test" {
		t.Errorf("unexpected common name: %q", result.CommonName)
	}
	if result.FingerprintSHA256 != wantFingerprint {
		t.Errorf("fingerprint mismatch: got %s want %s", result.FingerprintSHA256, wantFingerprint)
	}
}

func TestProbe_Unreachable(t *testing.T) {
	// Port 1 on loopback should refuse immediately rather than time out,
	// keeping this test fast.
	result := probe(context.Background(), "127.0.0.1", 1, 500*time.Millisecond)
	if result.Reachable {
		t.Fatalf("expected an unreachable port to report Reachable=false")
	}
}
