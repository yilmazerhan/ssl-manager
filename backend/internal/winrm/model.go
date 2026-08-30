package winrm

import "time"

// ServiceType names what a Target's bind script does after importing the
// certificate — see script.go.
type ServiceType string

const (
	// ServiceWinRMHTTPS rebinds the host's own WinRM HTTPS listener
	// (Secure WinRM) to the new certificate's thumbprint.
	ServiceWinRMHTTPS ServiceType = "winrm_https"
	// ServiceLDAPS only imports the certificate into the local machine
	// store — Active Directory Domain Services picks up a matching
	// Server-Authentication certificate for LDAPS automatically, there's
	// no separate bind step the way WinRM's listener needs one.
	ServiceLDAPS ServiceType = "ldaps"
)

// Target is one certificate -> Windows-host binding, reached over WinRM.
// A certificate can have several (e.g. the same cert bound to WinRM on
// one host and LDAPS on a domain controller); each syncs independently.
type Target struct {
	ID                 string      `json:"id"`
	CertificateID      string      `json:"certificate_id"`
	Name               string      `json:"name"`
	Host               string      `json:"host"`
	Port               int         `json:"port"`
	UseHTTPS           bool        `json:"use_https"`
	InsecureSkipVerify bool        `json:"insecure_skip_verify"`
	Username           string      `json:"username"`
	ServiceType        ServiceType `json:"service_type"`
	Enabled            bool        `json:"enabled"`
	LastSyncedAt       *time.Time  `json:"last_synced_at,omitempty"`
	LastSyncError      string      `json:"last_sync_error,omitempty"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

// TargetRequest is a Target's editable fields. Password is write-only —
// stored in Vault, never read back (see Service) — so, like k8s.
// TargetRequest's Token, it only ever appears on the way in.
type TargetRequest struct {
	Name               string      `json:"name"`
	Host               string      `json:"host"`
	Port               int         `json:"port"`
	UseHTTPS           bool        `json:"use_https"`
	InsecureSkipVerify bool        `json:"insecure_skip_verify"`
	Username           string      `json:"username"`
	Password           string      `json:"password,omitempty"`
	ServiceType        ServiceType `json:"service_type"`
	Enabled            bool        `json:"enabled"`
}
