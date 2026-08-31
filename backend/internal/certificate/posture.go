package certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"
)

// Posture is the crypto/protocol detail shown on a certificate's detail
// page. SignatureAlgorithm/KeyUsage/ExtKeyUsage come straight out of the
// issued cert — no network call. The TLS/cipher/OCSP fields are a
// best-effort live handshake against the certificate's own primary domain,
// since a certificate's own metadata says nothing about which protocol
// versions the server actually serving it still accepts.
type Posture struct {
	SignatureAlgorithm   string    `json:"signature_algorithm"`
	KeyUsage             []string  `json:"key_usage"`
	ExtKeyUsage          []string  `json:"ext_key_usage"`
	TLSVersionsSupported []string  `json:"tls_versions_supported"`
	CipherSuite          string    `json:"cipher_suite,omitempty"`
	OCSPStapled          bool      `json:"ocsp_stapled"`
	Reachable            bool      `json:"reachable"`
	ProbeError           string    `json:"probe_error,omitempty"`
	ProbedAt             time.Time `json:"probed_at"`
}

var probeVersions = []struct {
	name    string
	version uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

const probeTimeout = 4 * time.Second

// ComputePosture parses pemCert for its crypto attributes and probes
// host:443 once per TLS protocol version to see which are still accepted.
// The probes run concurrently so an unreachable host (internal-only certs,
// a sandboxed environment) costs one timeout, not four in series.
func ComputePosture(ctx context.Context, pemCert string, host string) (Posture, error) {
	p := Posture{ProbedAt: time.Now()}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return p, fmt.Errorf("certificate: no PEM block found")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return p, fmt.Errorf("certificate: parse: %w", err)
	}
	p.SignatureAlgorithm = x509Cert.SignatureAlgorithm.String()
	p.KeyUsage = keyUsageStrings(x509Cert.KeyUsage)
	p.ExtKeyUsage = extKeyUsageStrings(x509Cert.ExtKeyUsage)

	probeTLS(ctx, net.JoinHostPort(host, "443"), host, &p)
	return p, nil
}

type probeResult struct {
	name  string
	state tls.ConnectionState
	ok    bool
}

// probeTLS is split out from ComputePosture (addr/serverName instead of
// baking in host:443) so tests can point it at an ephemeral local listener
// instead of a real port-443 endpoint.
func probeTLS(ctx context.Context, addr string, serverName string, p *Posture) {
	results := make([]probeResult, len(probeVersions))

	var wg sync.WaitGroup
	for i, v := range probeVersions {
		wg.Add(1)
		go func(i int, name string, version uint16) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{},
				Config:    &tls.Config{MinVersion: version, MaxVersion: version, InsecureSkipVerify: true, ServerName: serverName},
			}
			conn, err := dialer.DialContext(dctx, "tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return
			}
			results[i] = probeResult{name: name, state: tlsConn.ConnectionState(), ok: true}
		}(i, v.name, v.version)
	}
	wg.Wait()

	var supported []string
	var newest *tls.ConnectionState
	for i, r := range results {
		if !r.ok {
			continue
		}
		p.Reachable = true
		supported = append(supported, r.name)
		state := results[i].state
		newest = &state
	}
	p.TLSVersionsSupported = supported
	if !p.Reachable {
		p.ProbeError = "domain not reachable on :443 from this server"
		return
	}
	if newest != nil {
		p.CipherSuite = tls.CipherSuiteName(newest.CipherSuite)
		p.OCSPStapled = len(newest.OCSPResponse) > 0
	}
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	// Never nil: this is serialized straight into Posture.KeyUsage with no
	// omitempty, and a leaf with no KeyUsage extension bits set would
	// otherwise encode as JSON null and crash the frontend's
	// `.join(", ")` on it.
	out := []string{}
	add := func(flag x509.KeyUsage, name string) {
		if ku&flag != 0 {
			out = append(out, name)
		}
	}
	add(x509.KeyUsageDigitalSignature, "Digital Signature")
	add(x509.KeyUsageContentCommitment, "Content Commitment")
	add(x509.KeyUsageKeyEncipherment, "Key Encipherment")
	add(x509.KeyUsageDataEncipherment, "Data Encipherment")
	add(x509.KeyUsageKeyAgreement, "Key Agreement")
	add(x509.KeyUsageCertSign, "Cert Sign")
	add(x509.KeyUsageCRLSign, "CRL Sign")
	add(x509.KeyUsageEncipherOnly, "Encipher Only")
	add(x509.KeyUsageDecipherOnly, "Decipher Only")
	return out
}

func extKeyUsageStrings(eku []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "Server Auth",
		x509.ExtKeyUsageClientAuth:      "Client Auth",
		x509.ExtKeyUsageCodeSigning:     "Code Signing",
		x509.ExtKeyUsageEmailProtection: "Email Protection",
		x509.ExtKeyUsageTimeStamping:    "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
	}
	// Same reasoning as keyUsageStrings: never nil, since a leaf with no
	// ExtKeyUsage entries would otherwise encode as JSON null and crash
	// the frontend's `.length` check on it.
	out := []string{}
	for _, u := range eku {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, "Other")
		}
	}
	return out
}
