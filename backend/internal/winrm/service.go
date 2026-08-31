package winrm

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// KeyExporter is the one Vault capability this package needs — exporting
// an exportable Transit key's raw private key. Deliberately not part of
// secrets.KeyManager, the same reasoning as k8s.KeyExporter (see its doc
// comment): every CA-issuance path also implements that interface and
// must not gain this capability just by being one.
type KeyExporter interface {
	ExportPrivateKey(ctx context.Context, name string) ([]byte, error)
}

type Service struct {
	store   Store
	certs   certificate.Store
	secrets secrets.SecretStore
	keys    KeyExporter
	audit   audit.Store
}

func NewService(store Store, certs certificate.Store, secretStore secrets.SecretStore, keys KeyExporter, auditStore audit.Store) *Service {
	return &Service{store: store, certs: certs, secrets: secretStore, keys: keys, audit: auditStore}
}

func secretPath(targetID string) string { return "winrm-targets/" + targetID }

// CreateTarget attaches a new WinRM sync target to certificateID. Refuses
// a certificate whose key isn't exportable, the same one-time-at-issuance
// gate internal/k8s.Service.CreateTarget enforces and for the same
// reason: binding a Windows service to this certificate needs the raw
// private key.
func (s *Service) CreateTarget(ctx context.Context, certificateID string, req TargetRequest) (Target, error) {
	if req.Name == "" || req.Host == "" || req.Port == 0 || req.Username == "" || req.Password == "" {
		return Target{}, fmt.Errorf("winrm: name, host, port, username, and password are all required")
	}
	if _, err := bindCommands(req.ServiceType); err != nil {
		return Target{}, err
	}
	cert, err := s.certs.Get(ctx, certificateID)
	if err != nil {
		return Target{}, fmt.Errorf("winrm: certificate not found")
	}
	if !cert.KeyExportable {
		return Target{}, fmt.Errorf("winrm: this certificate's key isn't exportable — re-issue it with the exportable-key option enabled before adding a WinRM target")
	}

	created, err := s.store.Create(ctx, Target{
		CertificateID: certificateID, Name: req.Name, Host: req.Host, Port: req.Port,
		UseHTTPS: req.UseHTTPS, InsecureSkipVerify: req.InsecureSkipVerify, Username: req.Username,
		ServiceType: req.ServiceType, Enabled: true,
	})
	if err != nil {
		return Target{}, err
	}
	if err := s.secrets.Put(ctx, secretPath(created.ID), map[string]interface{}{"password": req.Password}); err != nil {
		return Target{}, fmt.Errorf("winrm: store credential: %w", err)
	}

	// Push immediately rather than waiting for the certificate's next
	// issuance/renewal — a sync failure here (bad host, closed firewall,
	// WinRM auth failure) must not fail target creation; the admin can fix
	// it and retry via SyncTarget ("Sync now" in the UI).
	pfx, err := s.loadSyncMaterial(ctx, certificateID)
	if err != nil {
		log.Printf("winrm: initial sync for new target %s: %v", created.ID, err)
		return created, nil
	}
	s.syncOne(ctx, created, pfx)
	synced, err := s.store.Get(ctx, created.ID)
	if err != nil {
		return created, nil
	}
	return synced, nil
}

// UpdateTarget edits everything except which certificate it belongs to.
// Password is optional — omit it to keep the credential already on file,
// matching CreateTarget's sibling in internal/k8s and every editable-
// credential form in internal/api/integrations.go.
func (s *Service) UpdateTarget(ctx context.Context, id string, req TargetRequest) (Target, error) {
	if req.Name == "" || req.Host == "" || req.Port == 0 || req.Username == "" {
		return Target{}, fmt.Errorf("winrm: name, host, port, and username are all required")
	}
	if _, err := bindCommands(req.ServiceType); err != nil {
		return Target{}, err
	}
	existing, err := s.store.Get(ctx, id)
	if err != nil {
		return Target{}, err
	}
	existing.Name, existing.Host, existing.Port = req.Name, req.Host, req.Port
	existing.UseHTTPS, existing.InsecureSkipVerify = req.UseHTTPS, req.InsecureSkipVerify
	existing.Username, existing.ServiceType, existing.Enabled = req.Username, req.ServiceType, req.Enabled
	if err := s.store.Update(ctx, existing); err != nil {
		return Target{}, err
	}
	if req.Password != "" {
		if err := s.secrets.Put(ctx, secretPath(id), map[string]interface{}{"password": req.Password}); err != nil {
			return Target{}, fmt.Errorf("winrm: store credential: %w", err)
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
// enabled WinRM target attached to it. Like k8s.Service.SyncCertificate,
// it's meant to run in the background (see order.Service.SetOnIssued's
// wiring in cmd/api/main.go): every failure is logged and recorded
// per-target, never returned, so an unreachable host or a bad credential
// can't hold up or fail the issuance/renewal that triggered it.
func (s *Service) SyncCertificate(ctx context.Context, certificateID string) {
	targets, err := s.store.ListByCertificate(ctx, certificateID)
	if err != nil {
		log.Printf("winrm: list targets for certificate %s: %v", certificateID, err)
		return
	}
	if len(targets) == 0 {
		return
	}

	pfx, err := s.loadSyncMaterial(ctx, certificateID)
	if err != nil {
		log.Printf("winrm: %v", err)
		return
	}

	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		s.syncOne(ctx, target, pfx)
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
	pfx, err := s.loadSyncMaterial(ctx, target.CertificateID)
	if err != nil {
		return err
	}
	s.syncOne(ctx, target, pfx)
	updated, err := s.store.Get(ctx, targetID)
	if err != nil {
		return err
	}
	if updated.LastSyncError != "" {
		return fmt.Errorf("winrm: %s", updated.LastSyncError)
	}
	return nil
}

// loadSyncMaterial loads and exports everything needed to push
// certificateID to a target: a freshly built PFX containing the current
// cert, chain, and private key.
func (s *Service) loadSyncMaterial(ctx context.Context, certificateID string) ([]byte, error) {
	cert, err := s.certs.Get(ctx, certificateID)
	if err != nil {
		return nil, fmt.Errorf("load certificate %s: %w", certificateID, err)
	}
	if !cert.KeyExportable {
		return nil, fmt.Errorf("certificate %s's key isn't exportable", certificateID)
	}
	version, err := s.certs.LatestVersion(ctx, certificateID)
	if err != nil {
		return nil, fmt.Errorf("load latest version for certificate %s: %w", certificateID, err)
	}
	keyPEM, err := s.keys.ExportPrivateKey(ctx, cert.KeyRef)
	if err != nil {
		return nil, fmt.Errorf("export private key for certificate %s: %w", certificateID, err)
	}
	pfx, err := buildPFX([]byte(version.PEMCert+version.PEMChain), keyPEM, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("build PFX for certificate %s: %w", certificateID, err)
	}
	return pfx, nil
}

func (s *Service) syncOne(ctx context.Context, target Target, pfx []byte) {
	now := time.Now()
	target.LastSyncedAt = &now
	target.LastSyncError = ""

	pushErr := s.pushCertificate(ctx, target, pfx)
	if pushErr != nil {
		target.LastSyncError = pushErr.Error()
		log.Printf("winrm: sync target %s (%s@%s:%d): %v", target.ID, target.Username, target.Host, target.Port, pushErr)
	}
	if err := s.store.Update(ctx, target); err != nil {
		log.Printf("winrm: record sync result for target %s: %v", target.ID, err)
	}
	s.auditSync(ctx, target, pushErr)
}

// auditSync records the outcome of a single push attempt on the
// certificate's own audit trail — which host/service was touched and
// whether it succeeded — regardless of what triggered it: the immediate
// sync on target creation, the automatic post-issuance/renewal fan-out, or
// an admin's manual "Sync now".
func (s *Service) auditSync(ctx context.Context, target Target, pushErr error) {
	action := "winrm_sync_succeeded"
	metadata := map[string]interface{}{
		"target_id": target.ID, "target_name": target.Name,
		"host": target.Host, "port": target.Port, "service_type": string(target.ServiceType),
	}
	if pushErr != nil {
		action = "winrm_sync_failed"
		metadata["error"] = pushErr.Error()
	}
	_ = s.audit.Write(ctx, audit.Entry{
		Actor: "system:winrm-sync", Action: action, Resource: "certificate", ResourceID: target.CertificateID,
		Metadata: metadata,
	})
}

func (s *Service) pushCertificate(ctx context.Context, target Target, pfx []byte) error {
	data, err := s.secrets.Get(ctx, secretPath(target.ID))
	if err != nil {
		return fmt.Errorf("load credential: %w", err)
	}
	password, ok := data["password"].(string)
	if !ok || password == "" {
		return fmt.Errorf("no credential stored for this target")
	}

	script, err := buildScript(target.ServiceType, pfx)
	if err != nil {
		return err
	}

	client := &Client{
		Host: target.Host, Port: target.Port, Username: target.Username, Password: password,
		UseHTTPS: target.UseHTTPS, InsecureSkipVerify: target.InsecureSkipVerify,
	}
	_, err = client.RunPowerShell(ctx, script)
	return err
}
