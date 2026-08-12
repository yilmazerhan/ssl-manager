package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Safety bounds. These exist so a scan can't be pointed at an unbounded
// range or turned into a network-hammering tool by accident — see the
// package doc comment. CreateScanRequest validation rejects anything that
// would exceed them; concurrency is clamped rather than rejected since it's
// a resource knob, not a scope one.
const (
	MaxTargetsExpanded = 20000
	MaxPortsPerScan    = 32
	MaxConcurrency     = 64
	DefaultConcurrency = 16
	MinTimeoutMS       = 200
	MaxTimeoutMS       = 30000
	DefaultTimeoutMS   = 3000
)

// expandTargets turns a mixed list of hostnames, bare IPs, and CIDR blocks
// into individual host strings to probe, enforcing MaxTargetsExpanded so a
// single wide CIDR can't blow the scan up unbounded.
func expandTargets(inputs []string) ([]string, error) {
	var out []string
	for _, in := range inputs {
		if in == "" {
			continue
		}
		if ip, ipNet, err := net.ParseCIDR(in); err == nil {
			for cur := ip.Mask(ipNet.Mask); ipNet.Contains(cur); incIP(cur) {
				out = append(out, cur.String())
				if len(out) > MaxTargetsExpanded {
					return nil, fmt.Errorf("target list expands past %d hosts (stopped at %q) — narrow the range", MaxTargetsExpanded, in)
				}
				cur = dupIP(cur)
			}
			continue
		}
		out = append(out, in)
		if len(out) > MaxTargetsExpanded {
			return nil, fmt.Errorf("target list exceeds %d hosts — narrow the range", MaxTargetsExpanded)
		}
	}
	return out, nil
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// probeResult is what dialing a single host:port produces, before it's
// reconciled against inventory (that's the caller's job — probe stays
// ignorant of the certificate store so it's trivially testable on its
// own).
type probeResult struct {
	Host              string
	Port              int
	Reachable         bool
	TLSVersion        string
	CommonName        string
	SANs              []string
	Issuer            string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         *time.Time
	NotAfter          *time.Time
	NoTLS             bool
	Error             string
}

// probe dials host:port and, if a TLS handshake completes, records the
// leaf certificate it presents. InsecureSkipVerify is intentional and
// correct here: this is a discovery tool reporting what's being served,
// not a client deciding whether to trust it.
func probe(ctx context.Context, host string, port int, timeout time.Duration) probeResult {
	result := probeResult{Host: host, Port: port}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	result.Reachable = true

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		result.NoTLS = true
		result.Error = err.Error()
		return result
	}

	state := tlsConn.ConnectionState()
	result.TLSVersion = tlsVersionName(state.Version)
	if len(state.PeerCertificates) == 0 {
		result.NoTLS = true
		result.Error = "TLS handshake completed but no certificate was presented"
		return result
	}

	leaf := state.PeerCertificates[0]
	result.CommonName = leaf.Subject.CommonName
	result.SANs = leaf.DNSNames
	result.Issuer = leaf.Issuer.CommonName
	result.SerialNumber = leaf.SerialNumber.String()
	sum := sha256.Sum256(leaf.Raw)
	result.FingerprintSHA256 = hex.EncodeToString(sum[:])
	notBefore, notAfter := leaf.NotBefore, leaf.NotAfter
	result.NotBefore = &notBefore
	result.NotAfter = &notAfter
	return result
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// runProbes fans host x port combinations out across concurrency workers
// and streams each probeResult to onResult as it completes — the caller
// persists/matches it, keeping this function ignorant of storage. It
// returns once every combination has been probed or ctx is canceled.
func runProbes(ctx context.Context, hosts []string, ports []int, timeout time.Duration, concurrency int, onResult func(probeResult)) {
	type target struct {
		host string
		port int
	}
	targets := make(chan target)
	go func() {
		defer close(targets)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					return
				case targets <- target{h, p}:
				}
			}
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				r := probe(ctx, t.host, t.port, timeout)
				mu.Lock()
				onResult(r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}
