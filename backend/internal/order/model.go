package order

import (
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
)

type Status string

const (
	StatusDraft              Status = "draft"
	StatusAwaitingValidation Status = "awaiting_validation"
	StatusIssuing            Status = "issuing"
	StatusIssued             Status = "issued"
	StatusFailed             Status = "failed"
)

type Order struct {
	ID               string           `json:"id"`
	RequestedBy      string           `json:"requested_by"`
	OwningTeam       string           `json:"owning_team"`
	Domains          []string         `json:"domains"`
	CAProvider       string           `json:"ca_provider"`
	ValidationMethod string           `json:"validation_method"`
	KeyAlgorithm     string           `json:"key_algorithm"`
	Status           Status           `json:"status"`
	Challenges       ca.ProviderOrder `json:"challenges"`
	KeyRef           string           `json:"-"`
	CSRPEM           string           `json:"-"`
	CertificateID    string           `json:"certificate_id,omitempty"`
	Error            string           `json:"error,omitempty"`
	AttemptCount     int              `json:"attempt_count"`
	CreatedAt        time.Time        `json:"created_at"`
	CompletedAt      *time.Time       `json:"completed_at,omitempty"`

	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	State              string `json:"state,omitempty"`
	Locality           string `json:"locality,omitempty"`

	// KeyExportable carries the new certificate's chosen exportable
	// setting through from Create to Validate (a different HTTP request,
	// possibly much later) — it can't be recomputed later since Vault
	// Transit fixes exportable permanently at key creation.
	KeyExportable bool `json:"key_exportable,omitempty"`
}

// Public returns a copy safe to send to a client: the provider's internal
// bookkeeping (ACME order/authorization URLs, ZeroSSL certificate IDs) is
// dropped, leaving only the challenges a human or automation needs to act
// on.
func (o Order) Public() Order {
	sanitized := o
	sanitized.Challenges = ca.ProviderOrder{Challenges: o.Challenges.Challenges}
	return sanitized
}

type CreateRequest struct {
	RequestedBy      string   `json:"requested_by"`
	OwningTeam       string   `json:"owning_team"`
	Domains          []string `json:"domains"`
	CAProvider       string   `json:"ca_provider"`
	ValidationMethod string   `json:"validation_method"`
	KeyAlgorithm     string   `json:"key_algorithm"`
	// Subject fields beyond CommonName/SANs — all optional. See
	// validateSubject for the light format checks applied to them.
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
	// ExportableKey opts the new certificate's Vault key into being
	// exportable — see secrets.KeyManager.EnsureKey. It's a one-time,
	// irreversible choice: only a certificate created with this set can
	// ever get a Kubernetes Secret target (internal/k8s).
	ExportableKey bool `json:"exportable_key"`
}
