package order

import "time"

type Status string

const (
	StatusDraft              Status = "draft"
	StatusAwaitingValidation Status = "awaiting_validation"
	StatusIssuing            Status = "issuing"
	StatusIssued             Status = "issued"
	StatusFailed             Status = "failed"
)

type Order struct {
	ID               string    `json:"id"`
	RequestedBy      string    `json:"requested_by"`
	OwningTeam       string    `json:"owning_team"`
	Domains          []string  `json:"domains"`
	CAProvider       string    `json:"ca_provider"`
	ValidationMethod string    `json:"validation_method"`
	Status           Status    `json:"status"`
	Challenge        Challenge `json:"challenge,omitempty"`
	CertificateID    string    `json:"certificate_id,omitempty"`
	Error            string    `json:"error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
}

type Challenge struct {
	Type         string `json:"type"`
	ResourceName string `json:"resource_name"`
	Value        string `json:"value"`
	Verified     bool   `json:"verified"`
}

type CreateRequest struct {
	RequestedBy      string   `json:"requested_by"`
	OwningTeam       string   `json:"owning_team"`
	Domains          []string `json:"domains"`
	CAProvider       string   `json:"ca_provider"`
	ValidationMethod string   `json:"validation_method"`
	KeyAlgorithm     string   `json:"key_algorithm"`
}
