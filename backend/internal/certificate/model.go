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
	ID              string    `json:"id"`
	CommonName      string    `json:"common_name"`
	SANs            []string  `json:"sans"`
	CAProvider      string    `json:"ca_provider"`
	Status          Status    `json:"status"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	KeyAlgorithm    string    `json:"key_algorithm"`
	OwningTeam      string    `json:"owning_team"`
	AutoRenew       bool      `json:"auto_renew"`
	RenewBeforeDays int       `json:"renew_before_days"`
}

type Version struct {
	ID                string    `json:"id"`
	CertificateID     string    `json:"certificate_id"`
	SerialNumber      string    `json:"serial_number"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	PEMCert           string    `json:"pem_cert"`
	PEMChain          string    `json:"pem_chain"`
	PrivateKeyRef     string    `json:"private_key_ref"`
	IssuedAt          time.Time `json:"issued_at"`
}
