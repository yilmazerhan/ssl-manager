package certificate

import "time"

type Status string

const (
	StatusActive   Status = "active"
	StatusExpiring Status = "expiring"
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked"
)

type Certificate struct {
	ID               string    `json:"id"`
	CommonName       string    `json:"common_name"`
	SANs             []string  `json:"sans"`
	CAProvider       string    `json:"ca_provider"`
	ValidationMethod string    `json:"validation_method"`
	Status           Status    `json:"status"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	KeyAlgorithm     string    `json:"key_algorithm"`
	KeyRef           string    `json:"key_ref"`
	// CAReference is provider-specific state needed to act on this
	// certificate at the CA again (e.g. ZeroSSL's certificate ID); empty
	// for providers that don't need one (Let's Encrypt) or for
	// manually-uploaded certificates.
	CAReference     string `json:"-"`
	OwningTeam      string `json:"owning_team"`
	AutoRenew       bool   `json:"auto_renew"`
	RenewBeforeDays int    `json:"renew_before_days"`
	// NotifyEmails overrides notification_settings.default_recipients for
	// this certificate's expiry reminders when non-empty.
	NotifyEmails []string  `json:"notify_emails,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Version is an immutable record of one issuance. The private key is never
// part of it: certificate.KeyRef names the Vault Transit key used to sign
// every version's CSR, and that key never leaves Vault.
type Version struct {
	ID                string    `json:"id"`
	CertificateID     string    `json:"certificate_id"`
	SerialNumber      string    `json:"serial_number"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	PEMCert           string    `json:"pem_cert"`
	PEMChain          string    `json:"pem_chain"`
	IssuedAt          time.Time `json:"issued_at"`
}

type Filter struct {
	Team               string
	Status             Status
	CAProvider         string
	ExpiringWithinDays int
}
