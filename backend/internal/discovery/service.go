package discovery

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
)

type Service struct {
	store   Store
	certs   certificate.Store
	audit   audit.Store
	cancels sync.Map // scan ID -> context.CancelFunc, only while a scan is actually running
}

func NewService(store Store, certs certificate.Store, auditStore audit.Store) *Service {
	return &Service{store: store, certs: certs, audit: auditStore}
}

// scanParams is what every field of CreateScanRequest/ScheduleRequest
// resolves to once defaults are applied and bounds are checked — shared by
// CreateScan and CreateSchedule/UpdateSchedule so a schedule can't be used
// to bypass the safety bounds a one-off scan is subject to.
type scanParams struct {
	ports       []int
	expanded    []string
	timeoutMS   int
	concurrency int
}

func validateScanParams(name string, targets []string, reqPorts []int, reqTimeoutMS, reqConcurrency int) (scanParams, error) {
	if name == "" {
		return scanParams{}, fmt.Errorf("discovery: a name is required")
	}
	if len(targets) == 0 {
		return scanParams{}, fmt.Errorf("discovery: at least one target (host, IP, or CIDR) is required")
	}

	ports := reqPorts
	if len(ports) == 0 {
		ports = []int{443}
	}
	if len(ports) > MaxPortsPerScan {
		return scanParams{}, fmt.Errorf("discovery: %d ports requested, maximum is %d", len(ports), MaxPortsPerScan)
	}

	expanded, err := expandTargets(targets)
	if err != nil {
		return scanParams{}, err
	}
	if len(expanded) == 0 {
		return scanParams{}, fmt.Errorf("discovery: no valid targets after expansion")
	}

	timeoutMS := reqTimeoutMS
	if timeoutMS == 0 {
		timeoutMS = DefaultTimeoutMS
	}
	if timeoutMS < MinTimeoutMS || timeoutMS > MaxTimeoutMS {
		return scanParams{}, fmt.Errorf("discovery: timeout_ms must be between %d and %d", MinTimeoutMS, MaxTimeoutMS)
	}

	concurrency := reqConcurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}

	return scanParams{ports: ports, expanded: expanded, timeoutMS: timeoutMS, concurrency: concurrency}, nil
}

// CreateScan validates and expands req, persists the scan row, and starts
// probing in the background — it returns as soon as the scan exists, not
// once it finishes; ListResults/GetScan is how a caller watches progress.
func (s *Service) CreateScan(ctx context.Context, req CreateScanRequest, createdBy string) (Scan, error) {
	p, err := validateScanParams(req.Name, req.Targets, req.Ports, req.TimeoutMS, req.Concurrency)
	if err != nil {
		return Scan{}, err
	}

	sc, err := s.store.CreateScan(ctx, Scan{
		Name: req.Name, Description: req.Description, Targets: req.Targets, Ports: p.ports,
		TimeoutMS: p.timeoutMS, Concurrency: p.concurrency, Status: ScanStatusPending,
		CreatedBy: createdBy, TotalTargets: len(p.expanded) * len(p.ports),
	})
	if err != nil {
		return Scan{}, err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	s.cancels.Store(sc.ID, cancel)
	go s.run(runCtx, sc, p.expanded, p.ports)

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

// CreateSchedule validates req exactly like CreateScan (via
// validateScanParams) so a schedule can't fire scans a one-off request
// couldn't. The first run is interval_minutes from now, not immediate —
// an admin who wants an immediate look still has CreateScan for that.
func (s *Service) CreateSchedule(ctx context.Context, req ScheduleRequest, createdBy string) (Schedule, error) {
	p, err := validateScanParams(req.Name, req.Targets, req.Ports, req.TimeoutMS, req.Concurrency)
	if err != nil {
		return Schedule{}, err
	}
	if req.IntervalMinutes < MinIntervalMinutes || req.IntervalMinutes > MaxIntervalMinutes {
		return Schedule{}, fmt.Errorf("discovery: interval_minutes must be between %d and %d", MinIntervalMinutes, MaxIntervalMinutes)
	}
	return s.store.CreateSchedule(ctx, Schedule{
		Name: req.Name, Description: req.Description, Targets: req.Targets, Ports: p.ports,
		TimeoutMS: p.timeoutMS, Concurrency: p.concurrency, IntervalMinutes: req.IntervalMinutes,
		Enabled: true, CreatedBy: createdBy, NextRunAt: time.Now().Add(time.Duration(req.IntervalMinutes) * time.Minute),
	})
}

// UpdateSchedule reschedules NextRunAt from now, not from the old
// NextRunAt — so shortening the interval during an incident takes effect
// on the very next tick, not up to the old interval later.
func (s *Service) UpdateSchedule(ctx context.Context, id string, req ScheduleRequest) (Schedule, error) {
	existing, err := s.store.GetSchedule(ctx, id)
	if err != nil {
		return Schedule{}, err
	}
	p, err := validateScanParams(req.Name, req.Targets, req.Ports, req.TimeoutMS, req.Concurrency)
	if err != nil {
		return Schedule{}, err
	}
	if req.IntervalMinutes < MinIntervalMinutes || req.IntervalMinutes > MaxIntervalMinutes {
		return Schedule{}, fmt.Errorf("discovery: interval_minutes must be between %d and %d", MinIntervalMinutes, MaxIntervalMinutes)
	}
	existing.Name, existing.Description = req.Name, req.Description
	existing.Targets, existing.Ports = req.Targets, p.ports
	existing.TimeoutMS, existing.Concurrency = p.timeoutMS, p.concurrency
	existing.IntervalMinutes, existing.Enabled = req.IntervalMinutes, req.Enabled
	existing.NextRunAt = time.Now().Add(time.Duration(req.IntervalMinutes) * time.Minute)
	if err := s.store.UpdateSchedule(ctx, existing); err != nil {
		return Schedule{}, err
	}
	return existing, nil
}

func (s *Service) ListSchedules(ctx context.Context) ([]Schedule, error) {
	return s.store.ListSchedules(ctx)
}
func (s *Service) DeleteSchedule(ctx context.Context, id string) error {
	return s.store.DeleteSchedule(ctx, id)
}

// Run blocks, sweeping for due schedules immediately and then once a
// minute, until ctx is canceled — the same Run+ticker+panic-recovered-tick
// shape as renewal.Engine.Run.
func (s *Service) Run(ctx context.Context) {
	s.runDueSchedulesRecovered(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueSchedulesRecovered(ctx)
		}
	}
}

func (s *Service) runDueSchedulesRecovered(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("discovery: recovered from panic running due schedules: %v", r)
		}
	}()
	s.runDueSchedules(ctx)
}

func (s *Service) runDueSchedules(ctx context.Context) {
	due, err := s.store.DueSchedules(ctx, time.Now())
	if err != nil {
		log.Printf("discovery: list due schedules: %v", err)
		return
	}
	for _, sch := range due {
		s.fireSchedule(ctx, sch)
	}
}

// fireSchedule always reschedules NextRunAt, whether or not starting the
// scan succeeded — a schedule with a target that's since become invalid
// (e.g. expandTargets now rejects it) would otherwise fire on every single
// one-minute tick forever instead of just failing once per interval.
//
// It writes back only through RecordScheduleRun (last_run_at/last_scan_id/
// next_run_at), never a full UpdateSchedule of the in-memory sch this
// method received from DueSchedules — that snapshot can be stale by the
// time CreateScan returns (a slow scan-start), and a full-row rewrite
// would silently clobber a concurrent admin edit (e.g. PUT .../schedules/
// {id} disabling it) with this stale copy's old name/targets/enabled.
func (s *Service) fireSchedule(ctx context.Context, sch Schedule) {
	now := time.Now()
	nextRunAt := now.Add(time.Duration(sch.IntervalMinutes) * time.Minute)

	sc, err := s.CreateScan(ctx, CreateScanRequest{
		Name: sch.Name, Description: sch.Description, Targets: sch.Targets,
		Ports: sch.Ports, TimeoutMS: sch.TimeoutMS, Concurrency: sch.Concurrency,
	}, sch.CreatedBy)
	var lastScanID string
	if err != nil {
		log.Printf("discovery: fire schedule %s (%s): %v", sch.ID, sch.Name, err)
	} else {
		lastScanID = sc.ID
		// A manually created scan is audited by the HTTP handler (it has
		// the requesting admin's identity); a scheduled one has no request
		// to attribute it to, so it's audited here instead — otherwise
		// every automatic scan this platform runs would be invisible in
		// the audit trail.
		_ = s.audit.Write(ctx, audit.Entry{
			Actor: "system:discovery-scheduler", Action: "discovery_scan_started", Resource: "discovery_scan", ResourceID: sc.ID,
			Metadata: map[string]interface{}{
				"schedule_id": sch.ID, "schedule_name": sch.Name,
				"targets": sch.Targets, "ports": sc.Ports, "total_targets": sc.TotalTargets,
			},
		})
	}
	if err := s.store.RecordScheduleRun(ctx, sch.ID, now, nextRunAt, lastScanID); err != nil {
		log.Printf("discovery: update schedule %s after firing: %v", sch.ID, err)
	}
}

// VulnerabilitySummary aggregates the fleet-wide crypto/TLS posture
// dashboard from what discovery scans have already stored — see
// classifyVulnerabilities.
func (s *Service) VulnerabilitySummary(ctx context.Context) (VulnerabilitySummary, error) {
	return s.store.VulnerabilitySummary(ctx)
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
			s.auditScanCompletion(context.Background(), sc, 0)
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
	vulnCount := 0
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
		if len(result.Vulnerabilities) > 0 {
			vulnCount++
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
	s.auditScanCompletion(storeCtx, sc, vulnCount)
}

// auditScanCompletion records a scan's outcome on the audit trail —
// scanned/matched/mismatched/new-endpoint counts and how many endpoints
// came back with a classified vulnerability — regardless of whether the
// scan was started manually, by a schedule, or crashed outright. Manual
// and scheduled starts are each audited separately at the point they're
// created (the HTTP handler and fireSchedule, respectively), since only
// there is who or what started it known.
func (s *Service) auditScanCompletion(ctx context.Context, sc Scan, vulnCount int) {
	_ = s.audit.Write(ctx, audit.Entry{
		Actor: "system:discovery-scan", Action: "discovery_scan_completed", Resource: "discovery_scan", ResourceID: sc.ID,
		Metadata: map[string]interface{}{
			"name": sc.Name, "status": string(sc.Status), "error": sc.Error,
			"total_targets": sc.TotalTargets, "scanned_count": sc.ScannedCount,
			"matched_count": sc.MatchedCount, "mismatch_count": sc.MismatchCount, "new_count": sc.NewCount,
			"vulnerable_count": vulnCount,
		},
	})
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
		FingerprintSHA256: pr.FingerprintSHA256, SignatureAlgorithm: pr.SignatureAlgorithm, CipherSuite: pr.CipherSuite,
		Vulnerabilities: classifyVulnerabilities(pr), NotBefore: pr.NotBefore, NotAfter: pr.NotAfter, Error: pr.Error,
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
