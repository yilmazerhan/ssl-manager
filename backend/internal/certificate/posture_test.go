package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// mustSelfSignedCert generates a real self-signed cert/key pair and returns
// its PEM encoding alongside the parseable tls.Certificate, so tests can
// both feed ComputePosture real PEM bytes and serve the same cert over a
// real TLS listener.
func mustSelfSignedCert(t *testing.T) (pemCert string, tlsCert tls.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "posture-test.example.test"},
		DNSNames:     []string{"posture-test.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pemCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	tlsCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return pemCert, tlsCert
}

func mustTLSListener(t *testing.T, cert tls.Certificate, minVersion, maxVersion uint16) (addr string, close func()) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	})
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
	return listener.Addr().String(), func() { listener.Close() }
}

func TestComputePosture_ParsesSignatureAndKeyUsageFromPEM(t *testing.T) {
	pemCert, _ := mustSelfSignedCert(t)

	// Point at a definitely-closed port so the network probe fails fast
	// and predictably — this test only cares about the PEM-parsed fields.
	p, err := ComputePosture(context.Background(), pemCert, "127.0.0.1")
	if err != nil {
		t.Fatalf("ComputePosture: %v", err)
	}
	if p.SignatureAlgorithm == "" {
		t.Errorf("expected a non-empty signature algorithm")
	}
	found := false
	for _, u := range p.KeyUsage {
		if u == "Digital Signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Digital Signature in key usage, got %v", p.KeyUsage)
	}
	if len(p.ExtKeyUsage) != 1 || p.ExtKeyUsage[0] != "Server Auth" {
		t.Errorf("expected [Server Auth] extended key usage, got %v", p.ExtKeyUsage)
	}
}

func TestComputePosture_RejectsInvalidPEM(t *testing.T) {
	if _, err := ComputePosture(context.Background(), "not a pem", "127.0.0.1"); err == nil {
		t.Fatalf("expected an error for invalid PEM input")
	}
}

func TestProbeTLS_ReportsSupportedVersionsCipherAndReachability(t *testing.T) {
	_, tlsCert := mustSelfSignedCert(t)
	addr, closeFn := mustTLSListener(t, tlsCert, tls.VersionTLS12, tls.VersionTLS13)
	defer closeFn()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	var p Posture
	probeTLS(context.Background(), addr, host, &p)

	if !p.Reachable {
		t.Fatalf("expected the listener to be reported reachable")
	}
	if p.ProbeError != "" {
		t.Errorf("expected no probe error, got %q", p.ProbeError)
	}
	wantVersions := map[string]bool{"TLS 1.2": true, "TLS 1.3": true}
	for _, v := range p.TLSVersionsSupported {
		if !wantVersions[v] {
			t.Errorf("unexpected supported version %q", v)
		}
		delete(wantVersions, v)
	}
	if len(wantVersions) != 0 {
		t.Errorf("expected TLS 1.2 and TLS 1.3 both supported, missing %v", wantVersions)
	}
	// A listener restricted to MinVersion TLS 1.2 must refuse a TLS 1.0/1.1-only handshake.
	for _, v := range p.TLSVersionsSupported {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			t.Errorf("listener was restricted to TLS 1.2+, should not report %q as supported", v)
		}
	}
	if p.CipherSuite == "" {
		t.Errorf("expected a negotiated cipher suite to be recorded")
	}
}

func TestProbeTLS_UnreachableHostReportsNotReachable(t *testing.T) {
	var p Posture
	// Port 1 on loopback: nothing listens there, so every dial should fail fast (connection refused).
	probeTLS(context.Background(), "127.0.0.1:1", "127.0.0.1", &p)

	if p.Reachable {
		t.Fatalf("expected an unreachable address to be reported as such")
	}
	if p.ProbeError == "" {
		t.Errorf("expected a non-empty probe error explaining the failure")
	}
	if len(p.TLSVersionsSupported) != 0 {
		t.Errorf("expected no supported versions for an unreachable host, got %v", p.TLSVersionsSupported)
	}
}
