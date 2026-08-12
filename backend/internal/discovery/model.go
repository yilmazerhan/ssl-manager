// Package discovery implements the network keşif (discovery) module: scan
// a bounded set of hosts/CIDRs/ports for live TLS endpoints, record what
// certificate each one presents, and reconcile that against the
// certificate inventory (matched / mismatched / not tracked at all).
//
// This is deliberately narrow: a TLS handshake and nothing else. It never
// sends an HTTP request, never probes for vulnerabilities, and never
// touches a port that doesn't answer TLS — it exists to find endpoints
// inventory doesn't know about, not to assess them. Every scan is
// admin-scoped and bounded (internal/discovery/scanner.go's limits) so it
// can't be pointed at an unbounded range or used as a DoS tool.
package discovery

import "time"

type ScanStatus string

const (
	ScanStatusPending            ScanStatus = "pending"
	ScanStatusRunning            ScanStatus = "running"
	ScanStatusCompleted          ScanStatus = "completed"
	ScanStatusPartiallyCompleted ScanStatus = "partially_completed"
	ScanStatusFailed             ScanStatus = "failed"
	ScanStatusCanceled           ScanStatus = "canceled"
)

// MatchStatus is how a discovered endpoint's certificate relates to the
// inventory this platform already tracks.
type MatchStatus string

const (
	// MatchStatusMatched means a tracked certificate claims this domain and
	// its fingerprint is exactly what's being served.
	MatchStatusMatched MatchStatus = "matched"
	// MatchStatusMismatched means a tracked certificate claims this domain,
	// but a different certificate is actually being served there — stale
	// inventory, a manual swap outside this platform, or a real problem.
	MatchStatusMismatched MatchStatus = "mismatched"
	// MatchStatusNotInInventory means no certificate this platform tracks
	// claims this domain at all.
	MatchStatusNotInInventory MatchStatus = "not_in_inventory"
	// MatchStatusNoTLS means the host:port accepted a TCP connection but
	// didn't complete a TLS handshake — not a certificate to reconcile.
	MatchStatusNoTLS MatchStatus = "no_tls"
	// MatchStatusUnreachable means the TCP connection itself failed.
	MatchStatusUnreachable MatchStatus = "unreachable"
)

type Scan struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Targets       []string   `json:"targets"`
	Ports         []int      `json:"ports"`
	TimeoutMS     int        `json:"timeout_ms"`
	Concurrency   int        `json:"concurrency"`
	Status        ScanStatus `json:"status"`
	CreatedBy     string     `json:"created_by"`
	TotalTargets  int        `json:"total_targets"`
	ScannedCount  int        `json:"scanned_count"`
	MatchedCount  int        `json:"matched_count"`
	MismatchCount int        `json:"mismatch_count"`
	NewCount      int        `json:"new_count"`
	Error         string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

type Result struct {
	ID                string      `json:"id"`
	ScanID            string      `json:"scan_id"`
	Host              string      `json:"host"`
	Port              int         `json:"port"`
	Reachable         bool        `json:"reachable"`
	TLSVersion        string      `json:"tls_version,omitempty"`
	CommonName        string      `json:"common_name,omitempty"`
	SANs              []string    `json:"sans,omitempty"`
	Issuer            string      `json:"issuer,omitempty"`
	SerialNumber      string      `json:"serial_number,omitempty"`
	FingerprintSHA256 string      `json:"fingerprint_sha256,omitempty"`
	NotBefore         *time.Time  `json:"not_before,omitempty"`
	NotAfter          *time.Time  `json:"not_after,omitempty"`
	MatchStatus       MatchStatus `json:"match_status"`
	MatchedCertID     string      `json:"matched_certificate_id,omitempty"`
	Error             string      `json:"error,omitempty"`
	DiscoveredAt      time.Time   `json:"discovered_at"`
}

type CreateScanRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Targets     []string `json:"targets"`
	Ports       []int    `json:"ports"`
	TimeoutMS   int      `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
}
