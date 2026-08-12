package discovery

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
)

type Service struct {
	store   Store
	certs   certificate.Store
	cancels sync.Map // scan ID -> context.CancelFunc, only while a scan is actually running
}

func NewService(store Store, certs certificate.Store) *Service {
	return &Service{store: store, certs: certs}
}

// CreateScan validates and expands req, persists the scan row, and starts
// probing in the background — it returns as soon as the scan exists, not
// once it finishes; ListResults/GetScan is how a caller watches progress.
func (s *Service) CreateScan(ctx context.Context, req CreateScanRequest, createdBy string) (Scan, error) {
	if req.Name == "" {
		return Scan{}, fmt.Errorf("discovery: a scan name is required")
	}
	if len(req.Targets) == 0 {
		return Scan{}, fmt.Errorf("discovery: at least one target (host, IP, or CIDR) is required")
	}

	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{443}
	}
	if len(ports) > MaxPortsPerScan {
		return Scan{}, fmt.Errorf("discovery: %d ports requested, maximum is %d", len(ports), MaxPortsPerScan)
	}

	expanded, err := expandTargets(req.Targets)
	if err != nil {
		return Scan{}, err
	}
	if len(expanded) == 0 {
		return Scan{}, fmt.Errorf("discovery: no valid targets after expansion")
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = DefaultTimeoutMS
	}
	if timeoutMS < MinTimeoutMS || timeoutMS > MaxTimeoutMS {
		return Scan{}, fmt.Errorf("discovery: timeout_ms must be between %d and %d", MinTimeoutMS, MaxTimeoutMS)
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}

	sc, err := s.store.CreateScan(ctx, Scan{
		Name: req.Name, Description: req.Description, Targets: req.Targets, Ports: ports,
		TimeoutMS: timeoutMS, Concurrency: concurrency, Status: ScanStatusPending,
		CreatedBy: createdBy, TotalTargets: len(expanded) * len(ports),
	})
	if err != nil {
		return Scan{}, err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	s.cancels.Store(sc.ID, cancel)
	go s.run(runCtx, sc, expanded, ports)

	return sc, nil
}

func (s *Service) GetScan(ctx context.Context, id string) (Scan, error) {
	return s.store.GetScan(ctx, id)
}
func (s *Service) ListScans(ctx context.Context) ([]Scan, error) { return s.store.ListScans(ctx) }
func (s *Service) ListResults(ctx context.Context, scanID string) ([]Result, error) {
	return s.store.ListResults(ctx, scanID)
}

func (s *Service) ListMismatches(ctx context.Context, limit int) ([]Result, error) {
	return s.store.ListMismatches(ctx, limit)
}

// CancelScan asks a running scan to stop after its in-flight probes
// finish. It only works while this process is the one running it — a
// scan orphaned by a restart can't be canceled this way (it's already
// been marked failed by RecoverInterruptedScans instead).
func (s *Service) CancelScan(_ context.Context, id string) error {
	v, ok := s.cancels.Load(id)
	if !ok {
		return fmt.Errorf("discovery: scan %s is not currently running in this process (already finished, or the server restarted)", id)
	}
	v.(context.CancelFunc)()
	return nil
}

// RecoverInterruptedScans marks every scan left running/pending from a
// previous process lifetime as failed. Nothing survives a restart to
// finish them — leaving them "running" forever would be a silent lie the
// dashboard has no way to detect on its own.
func (s *Service) RecoverInterruptedScans(ctx context.Context) error {
	return s.store.MarkInterruptedScansFailed(ctx, "interrupted by a server restart")
}

func (s *Service) run(ctx context.Context, sc Scan, hosts []string, ports []int) {
	defer s.cancels.Delete(sc.ID)
	// This always runs as its own goroutine (the only call site is `go
	// s.run(...)`), so an unrecovered panic here would crash the whole
	// process, not just this scan. Recovering also means the scan record
	// itself doesn't get stuck reporting "running" forever with nothing
	// left alive to ever finish it.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("discovery: recovered from panic running scan %s: %v", sc.ID, r)
			completed := time.Now()
			sc.Status = ScanStatusFailed
			sc.Error = fmt.Sprintf("internal error: %v", r)
			sc.CompletedAt = &completed
			if err := s.store.UpdateScan(context.Background(), sc); err != nil {
				log.Printf("discovery: mark panicked scan %s failed: %v", sc.ID, err)
			}
		}
	}()

	now := time.Now()
	sc.Status = ScanStatusRunning
	sc.StartedAt = &now
	if err := s.store.UpdateScan(ctx, sc); err != nil {
		log.Printf("discovery: mark scan %s running: %v", sc.ID, err)
		return
	}

	index, err := s.buildInventoryIndex(ctx)
	if err != nil {
		log.Printf("discovery: build inventory index for scan %s: %v", sc.ID, err)
		index = map[string]inventoryEntry{}
	}

	storeCtx := context.Background() // results must persist even if the scan itself is canceled mid-run
	timeout := time.Duration(sc.TimeoutMS) * time.Millisecond
	runProbes(ctx, hosts, ports, timeout, sc.Concurrency, func(pr probeResult) {
		result := s.reconcile(pr, index)
		result.ScanID = sc.ID
		if _, err := s.store.AddResult(storeCtx, result); err != nil {
			log.Printf("discovery: store result for scan %s (%s:%d): %v", sc.ID, pr.Host, pr.Port, err)
			return
		}
		sc.ScannedCount++
		switch result.MatchStatus {
		case MatchStatusMatched:
			sc.MatchedCount++
		case MatchStatusMismatched:
			sc.MismatchCount++
		case MatchStatusNotInInventory:
			sc.NewCount++
		}
	})

	completed := time.Now()
	sc.CompletedAt = &completed
	switch {
	case ctx.Err() != nil:
		sc.Status = ScanStatusCanceled
	case sc.ScannedCount >= sc.TotalTargets:
		sc.Status = ScanStatusCompleted
	default:
		sc.Status = ScanStatusPartiallyCompleted
	}
	if err := s.store.UpdateScan(storeCtx, sc); err != nil {
		log.Printf("discovery: mark scan %s complete: %v", sc.ID, err)
	}
}

type inventoryEntry struct {
	certificateID string
	fingerprint   string
}

// buildInventoryIndex maps every domain any non-revoked tracked
// certificate claims to that certificate's id and current fingerprint,
// built once per scan rather than once per probed host — the certificate
// count, not the scan's target count, bounds its cost.
func (s *Service) buildInventoryIndex(ctx context.Context) (map[string]inventoryEntry, error) {
	certs, err := s.certs.List(ctx, certificate.Filter{})
	if err != nil {
		return nil, err
	}
	index := map[string]inventoryEntry{}
	for _, c := range certs {
		if c.Status == certificate.StatusRevoked {
			continue
		}
		fingerprint := ""
		if version, err := s.certs.LatestVersion(ctx, c.ID); err == nil {
			fingerprint = version.FingerprintSHA256
		}
		entry := inventoryEntry{certificateID: c.ID, fingerprint: fingerprint}
		for _, san := range c.SANs {
			index[strings.ToLower(san)] = entry
		}
	}
	return index, nil
}

func (s *Service) reconcile(pr probeResult, index map[string]inventoryEntry) Result {
	r := Result{
		Host: pr.Host, Port: pr.Port, Reachable: pr.Reachable, TLSVersion: pr.TLSVersion,
		CommonName: pr.CommonName, SANs: pr.SANs, Issuer: pr.Issuer, SerialNumber: pr.SerialNumber,
		FingerprintSHA256: pr.FingerprintSHA256, NotBefore: pr.NotBefore, NotAfter: pr.NotAfter, Error: pr.Error,
	}
	switch {
	case !pr.Reachable:
		r.MatchStatus = MatchStatusUnreachable
		return r
	case pr.NoTLS:
		r.MatchStatus = MatchStatusNoTLS
		return r
	}

	entry, ok := index[strings.ToLower(pr.Host)]
	if !ok {
		for _, san := range pr.SANs {
			if e, found := index[strings.ToLower(san)]; found {
				entry, ok = e, true
				break
			}
		}
	}
	if !ok {
		r.MatchStatus = MatchStatusNotInInventory
		return r
	}

	r.MatchedCertID = entry.certificateID
	if entry.fingerprint != "" && entry.fingerprint == pr.FingerprintSHA256 {
		r.MatchStatus = MatchStatusMatched
	} else {
		r.MatchStatus = MatchStatusMismatched
	}
	return r
}
