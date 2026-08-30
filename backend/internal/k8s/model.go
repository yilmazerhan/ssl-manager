package k8s

import "time"

// Target is one certificate -> Kubernetes Secret binding. A certificate
// can have several (the same cert deployed into multiple namespaces or
// clusters); each syncs independently.
type Target struct {
	ID                 string     `json:"id"`
	CertificateID      string     `json:"certificate_id"`
	Name               string     `json:"name"`
	ClusterURL         string     `json:"cluster_url"`
	Namespace          string     `json:"namespace"`
	SecretName         string     `json:"secret_name"`
	InsecureSkipVerify bool       `json:"insecure_skip_verify"`
	Enabled            bool       `json:"enabled"`
	LastSyncedAt       *time.Time `json:"last_synced_at,omitempty"`
	LastSyncError      string     `json:"last_sync_error,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// TargetRequest is a Target's editable fields. Token is write-only — it's
// stored in Vault (see Service), never read back — so it's absent from
// Target's own JSON shape and only ever appears here, on the way in.
type TargetRequest struct {
	Name               string `json:"name"`
	ClusterURL         string `json:"cluster_url"`
	Token              string `json:"token,omitempty"`
	Namespace          string `json:"namespace"`
	SecretName         string `json:"secret_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Enabled            bool   `json:"enabled"`
}
