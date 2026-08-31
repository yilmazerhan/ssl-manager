package k8s

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// KeyExporter is the one Vault capability this package needs — exporting
// an exportable Transit key's raw private key. Deliberately not part of
// secrets.KeyManager (every CA-issuance path also implements that
// interface and must not gain this capability just by being one) — see
// secrets.VaultKeyManager.ExportPrivateKey's own doc comment.
type KeyExporter interface {
	ExportPrivateKey(ctx context.Context, name string) ([]byte, error)
}

type Service struct {
	store   Store
	certs   certificate.Store
	secrets secrets.SecretStore
	keys    KeyExporter
}

func NewService(store Store, certs certificate.Store, secretStore secrets.SecretStore, keys KeyExporter) *Service {
	return &Service{store: store, certs: certs, secrets: secretStore, keys: keys}
}

func secretPath(targetID string) string { return "k8s-targets/" + targetID }

// CreateTarget attaches a new sync target to certificateID. It refuses a
// certificate whose key isn't exportable — see certificate.Certificate.
// KeyExportable's doc comment for why that can't be fixed after the fact.
func (s *Service) CreateTarget(ctx context.Context, certificateID string, req TargetRequest) (Target, error) {
	if req.Name == "" || req.ClusterURL == "" || req.Namespace == "" || req.SecretName == "" || req.Token == "" {
		return Target{}, fmt.Errorf("k8s: name, cluster_url, namespace, secret_name, and token are all required")
	}
	cert, err := s.certs.Get(ctx, certificateID)
	if err != nil {
		return Target{}, fmt.Errorf("k8s: certificate not found")
	}
	if !cert.KeyExportable {
		return Target{}, fmt.Errorf("k8s: this certificate's key isn't exportable — re-issue it with Kubernetes sync enabled before adding a target")
	}

	created, err := s.store.Create(ctx, Target{
		CertificateID: certificateID, Name: req.Name, ClusterURL: req.ClusterURL,
		Namespace: req.Namespace, SecretName: req.SecretName, InsecureSkipVerify: req.InsecureSkipVerify, Enabled: true,
	})
	if err != nil {
		return Target{}, err
	}
	if err := s.secrets.Put(ctx, secretPath(created.ID), map[string]interface{}{"token": req.Token}); err != nil {
		return Target{}, fmt.Errorf("k8s: store cluster token: %w", err)
	}

	// Push immediately rather than waiting for the certificate's next
	// issuance/renewal — a sync failure here (bad host, closed firewall)
	// must not fail target creation; the admin can fix it and retry via
	// SyncTarget ("Sync now" in the UI).
	certPEM, keyPEM, err := s.loadSyncMaterial(ctx, certificateID)
	if err != nil {
		log.Printf("k8s: initial sync for new target %s: %v", created.ID, err)
		return created, nil
	}
	s.syncOne(ctx, created, certPEM, keyPEM)
	synced, err := s.store.Get(ctx, created.ID)
	if err != nil {
		return created, nil
	}
	return synced, nil
}

// UpdateTarget edits everything except which certificate it belongs to.
// Token is optional here — omit it to keep the cluster token already on
// file, matching how every other editable-credential form in this app
// (see internal/api/integrations.go) treats a blank secret field as "leave
// it alone" rather than "clear it".
func (s *Service) UpdateTarget(ctx context.Context, id string, req TargetRequest) (Target, error) {
	if req.Name == "" || req.ClusterURL == "" || req.Namespace == "" || req.SecretName == "" {
		return Target{}, fmt.Errorf("k8s: name, cluster_url, namespace, and secret_name are all required")
	}
	existing, err := s.store.Get(ctx, id)
	if err != nil {
		return Target{}, err
	}
	existing.Name, existing.ClusterURL = req.Name, req.ClusterURL
	existing.Namespace, existing.SecretName = req.Namespace, req.SecretName
	existing.InsecureSkipVerify, existing.Enabled = req.InsecureSkipVerify, req.Enabled
	if err := s.store.Update(ctx, existing); err != nil {
		return Target{}, err
	}
	if req.Token != "" {
		if err := s.secrets.Put(ctx, secretPath(id), map[string]interface{}{"token": req.Token}); err != nil {
			return Target{}, fmt.Errorf("k8s: store cluster token: %w", err)
		}
	}
	return existing, nil
}

func (s *Service) ListTargets(ctx context.Context, certificateID string) ([]Target, error) {
	return s.store.ListByCertificate(ctx, certificateID)
}

func (s *Service) DeleteTarget(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// SyncCertificate pushes certificateID's current cert/chain/key to every
// enabled target attached to it. It's meant to run in the background (see
// order.Service.SetOnIssued's wiring in cmd/api/main.go) — every failure
// is logged and recorded per-target, never returned, so a slow or
// unreachable cluster can't hold up or fail the issuance/renewal that
// triggered it.
func (s *Service) SyncCertificate(ctx context.Context, certificateID string) {
	targets, err := s.store.ListByCertificate(ctx, certificateID)
	if err != nil {
		log.Printf("k8s: list targets for certificate %s: %v", certificateID, err)
		return
	}
	if len(targets) == 0 {
		return
	}

	certPEM, keyPEM, err := s.loadSyncMaterial(ctx, certificateID)
	if err != nil {
		log.Printf("k8s: %v", err)
		return
	}

	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		s.syncOne(ctx, target, certPEM, keyPEM)
	}
}

// SyncTarget re-pushes certificateID's current cert/chain/key to a single
// target on demand (the "Sync now" action), returning the failure as a
// real error instead of only logging and recording it, since this path
// always has an admin waiting on the result.
func (s *Service) SyncTarget(ctx context.Context, targetID string) error {
	target, err := s.store.Get(ctx, targetID)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := s.loadSyncMaterial(ctx, target.CertificateID)
	if err != nil {
		return err
	}
	s.syncOne(ctx, target, certPEM, keyPEM)
	updated, err := s.store.Get(ctx, targetID)
	if err != nil {
		return err
	}
	if updated.LastSyncError != "" {
		return fmt.Errorf("k8s: %s", updated.LastSyncError)
	}
	return nil
}

// loadSyncMaterial loads and exports everything needed to push
// certificateID to a target: the current cert+chain PEM and the
// certificate's private key PEM.
func (s *Service) loadSyncMaterial(ctx context.Context, certificateID string) (certPEM, keyPEM []byte, err error) {
	cert, err := s.certs.Get(ctx, certificateID)
	if err != nil {
		return nil, nil, fmt.Errorf("load certificate %s: %w", certificateID, err)
	}
	if !cert.KeyExportable {
		return nil, nil, fmt.Errorf("certificate %s's key isn't exportable", certificateID)
	}
	version, err := s.certs.LatestVersion(ctx, certificateID)
	if err != nil {
		return nil, nil, fmt.Errorf("load latest version for certificate %s: %w", certificateID, err)
	}
	keyPEM, err = s.keys.ExportPrivateKey(ctx, cert.KeyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("export private key for certificate %s: %w", certificateID, err)
	}
	return []byte(version.PEMCert + version.PEMChain), keyPEM, nil
}

func (s *Service) syncOne(ctx context.Context, target Target, certPEM, keyPEM []byte) {
	now := time.Now()
	target.LastSyncedAt = &now
	target.LastSyncError = ""

	if err := s.pushSecret(ctx, target, certPEM, keyPEM); err != nil {
		target.LastSyncError = err.Error()
		log.Printf("k8s: sync target %s (%s/%s): %v", target.ID, target.Namespace, target.SecretName, err)
	}
	if err := s.store.Update(ctx, target); err != nil {
		log.Printf("k8s: record sync result for target %s: %v", target.ID, err)
	}
}

func (s *Service) pushSecret(ctx context.Context, target Target, certPEM, keyPEM []byte) error {
	data, err := s.secrets.Get(ctx, secretPath(target.ID))
	if err != nil {
		return fmt.Errorf("load cluster token: %w", err)
	}
	token, ok := data["token"].(string)
	if !ok || token == "" {
		return fmt.Errorf("no cluster token stored for this target")
	}

	client := New(target.ClusterURL, token, target.InsecureSkipVerify)
	return client.UpsertTLSSecret(ctx, target.Namespace, target.SecretName, certPEM, keyPEM)
}
