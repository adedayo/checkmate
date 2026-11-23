package triage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// ProgressFunc receives coalesced scan progress updates.
type ProgressFunc func(progress, total int64, message string)

// Service orchestrates agent-driven scanning, finding clustering, dry-run
// suppression previews, triage verdict write-back, rule suppression, and
// sanitised report export. It is transport-agnostic and shared by both pkg/mcp
// and pkg/api.
type Service struct {
	store store.PlatformStore

	mu               sync.RWMutex
	activeScans      map[string]*activeScanState
	trackedCheckouts map[string]trackedCheckout
}

type activeScanState struct {
	scanID       string
	projectID    string
	status       string
	filesScanned int
	totalFiles   int
	currentFile  string
	overview     *ScanOverview
	errMsg       string
}

type trackedCheckout struct {
	scanID    string
	dirs      []string
	createdAt time.Time
}

// NewService creates a new triage Service backed by PlatformStore.
func NewService(s store.PlatformStore) *Service {
	return &Service{
		store:            s,
		activeScans:      make(map[string]*activeScanState),
		trackedCheckouts: make(map[string]trackedCheckout),
	}
}

// ScanRequest configures a scan triggered by an AI agent or API client.
type ScanRequest struct {
	Targets       []string `json:"targets,omitempty"`
	ProjectID     string   `json:"projectId,omitempty"`
	GitDiffBase   string   `json:"gitDiffBase,omitempty"`
	ExcludeTests  bool     `json:"excludeTests,omitempty"`
	ExclusionFile string   `json:"exclusionFile,omitempty"`
	Async         bool     `json:"async,omitempty"`
	KeepCheckout  bool     `json:"keepCheckout,omitempty"`
}

// ScanClusters summarises how untriaged findings group so an agent can pick
// the highest-leverage triage strategy first.
type ScanClusters struct {
	UniqueChecksums int            `json:"uniqueChecksums"`
	UniqueFiles     int            `json:"uniqueFiles"`
	UniqueDirs      int            `json:"uniqueDirectories"`
	ByRule          map[string]int `json:"byRule"`
}

// ScanOverview is the compact response returned by Scan (never a raw finding dump).
type ScanOverview struct {
	ScanID                string                      `json:"scanId"`
	ProjectID             string                      `json:"projectId"`
	Status                string                      `json:"status"`
	FilesScanned          int                         `json:"filesScanned"`
	GitDiffBase           string                      `json:"gitDiffBase,omitempty"`
	ScannedTargets        []string                    `json:"scannedTargets,omitempty"`
	RawFindings           int                         `json:"rawFindings"`
	AlreadySuppressed     int                         `json:"alreadySuppressed"`
	CarriedForwardTriaged int                         `json:"carriedForwardTriaged"`
	UntriagedFindings     int                         `json:"untriagedFindings"`
	Clusters              ScanClusters                `json:"clusters"`
	SanitisedSummary      *store.SanitisedSummary     `json:"sanitisedSummary"`
	Acquisition           *gitutils.AcquisitionReport `json:"acquisition,omitempty"`
	RetainedCheckouts     map[string]string           `json:"retainedCheckouts,omitempty"`
	LocalCheckoutPath     string                      `json:"localCheckoutPath,omitempty"`
}

// AcquisitionFailureError wraps a failed ScanOverview when every target failed
// to acquire so callers (e.g. MCP) can return both isError=true and structured details.
type AcquisitionFailureError struct {
	Overview *ScanOverview
	Message  string
}

func (e *AcquisitionFailureError) Error() string {
	return e.Message
}

// ScanStatus reports live or final status for an async or historical scan.
type ScanStatus struct {
	ScanID       string        `json:"scanId"`
	ProjectID    string        `json:"projectId,omitempty"`
	Status       string        `json:"status"`
	FilesScanned int           `json:"filesScanned"`
	TotalFiles   int           `json:"totalFiles"`
	CurrentFile  string        `json:"currentFile,omitempty"`
	Overview     *ScanOverview `json:"overview,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// Scan runs a deterministic scan, persists results to SQLite, reconciles active
// exceptions, and returns a compact clustered overview.
func (s *Service) Scan(ctx context.Context, req ScanRequest) (*ScanOverview, error) {
	return s.ScanWithProgress(ctx, req, nil)
}

// ScanWithProgress runs a synchronous scan while forwarding coalesced progress
// updates to progressFn when non-nil.
func (s *Service) ScanWithProgress(ctx context.Context, req ScanRequest, progressFn ProgressFunc) (*ScanOverview, error) {
	if s.store == nil {
		return nil, fmt.Errorf("store not initialised")
	}

	s.cleanupExpiredCheckouts()

	projectID, _, policy, scannedTargets, emptyDiffOverview, err := s.prepareScan(req)
	if err != nil {
		return nil, err
	}
	if emptyDiffOverview != nil {
		return emptyDiffOverview, nil
	}

	var monitor func(diagnostics.Progress)
	if progressFn != nil {
		monitor = func(p diagnostics.Progress) {
			progressFn(p.Position, p.Total, p.CurrentFile)
		}
	}

	var scanID string
	s.store.RunScan(
		ctx,
		projectID,
		policy,
		nil,
		func(id string) { scanID = id },
		nil,
		monitor,
		nil,
		nil,
	)

	if scanID == "" {
		return nil, fmt.Errorf("scan failed to start")
	}

	return s.finalizeScanOverview(scanID, projectID, req.GitDiffBase, scannedTargets)
}

// StartScanAsync launches a scan in the background, waits up to 5 seconds for
// its scanId to be created, and returns an initial running ScanStatus.
func (s *Service) StartScanAsync(_ context.Context, req ScanRequest, progressFn ProgressFunc) (*ScanStatus, error) {
	if s.store == nil {
		return nil, fmt.Errorf("store not initialised")
	}

	s.cleanupExpiredCheckouts()

	projectID, _, policy, scannedTargets, emptyDiffOverview, err := s.prepareScan(req)
	if err != nil {
		return nil, err
	}
	if emptyDiffOverview != nil {
		return &ScanStatus{
			ScanID:    emptyDiffOverview.ScanID,
			ProjectID: emptyDiffOverview.ProjectID,
			Status:    "complete",
			Overview:  emptyDiffOverview,
		}, nil
	}

	scanIDReady := make(chan string, 1)
	var mu sync.Mutex
	var capturedScanID string

	monitor := func(p diagnostics.Progress) {
		mu.Lock()
		sid := capturedScanID
		mu.Unlock()
		if sid != "" {
			s.mu.Lock()
			if st, ok := s.activeScans[sid]; ok {
				st.filesScanned = int(p.Position)
				st.totalFiles = int(p.Total)
				st.currentFile = p.CurrentFile
			}
			s.mu.Unlock()
		}
		if progressFn != nil {
			progressFn(p.Position, p.Total, p.CurrentFile)
		}
	}

	go func() {
		bgCtx := context.Background()
		s.store.RunScan(
			bgCtx,
			projectID,
			policy,
			nil,
			func(id string) {
				mu.Lock()
				capturedScanID = id
				mu.Unlock()

				s.mu.Lock()
				s.activeScans[id] = &activeScanState{
					scanID:    id,
					projectID: projectID,
					status:    "running",
				}
				s.mu.Unlock()

				select {
				case scanIDReady <- id:
				default:
				}
			},
			nil,
			monitor,
			nil,
			nil,
		)

		mu.Lock()
		sid := capturedScanID
		mu.Unlock()
		if sid == "" {
			select {
			case scanIDReady <- "":
			default:
			}
			return
		}

		overview, finErr := s.finalizeScanOverview(sid, projectID, req.GitDiffBase, scannedTargets)
		s.mu.Lock()
		if st, ok := s.activeScans[sid]; ok {
			if finErr != nil {
				st.status = "failed"
				st.errMsg = finErr.Error()
				if acqErr, ok := finErr.(*AcquisitionFailureError); ok {
					st.overview = acqErr.Overview
				}
			} else {
				st.status = overview.Status
				st.filesScanned = overview.FilesScanned
				st.overview = overview
			}
		}
		s.mu.Unlock()
	}()

	select {
	case sid := <-scanIDReady:
		if sid == "" {
			return nil, fmt.Errorf("async scan failed to start")
		}
		return &ScanStatus{
			ScanID:    sid,
			ProjectID: projectID,
			Status:    "running",
		}, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timed out waiting for async scan to initialise")
	}
}

// GetScanStatus returns live progress for an active scan or persisted status
// and overview for a completed/failed historical scan.
func (s *Service) GetScanStatus(_ context.Context, scanID string) (*ScanStatus, error) {
	if scanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}

	s.mu.RLock()
	if st, ok := s.activeScans[scanID]; ok {
		out := &ScanStatus{
			ScanID:       st.scanID,
			ProjectID:    st.projectID,
			Status:       st.status,
			FilesScanned: st.filesScanned,
			TotalFiles:   st.totalFiles,
			CurrentFile:  st.currentFile,
			Overview:     st.overview,
			Error:        st.errMsg,
		}
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	rec, err := s.store.GetScanRecord(scanID)
	if err != nil {
		return nil, err
	}
	filesScanned, _ := s.store.GetScanFileCount(scanID)
	status := &ScanStatus{
		ScanID:       rec.ID,
		ProjectID:    rec.ProjectID,
		Status:       rec.Status,
		FilesScanned: filesScanned,
		TotalFiles:   filesScanned,
	}

	switch rec.Status {
	case "complete":
		ov, err := s.BuildScanOverview(rec.ID, rec.ProjectID, "", nil)
		if err == nil {
			status.Overview = ov
		}
	case "failed":
		if acq, err := s.store.GetScanAcquisitionReport(rec.ID); err == nil && acq != nil && len(acq.Failures) > 0 {
			f := acq.Failures[0]
			status.Error = fmt.Sprintf("acquisition failed for %s (%s): %s", f.Target, f.ErrorKind, f.Message)
		} else {
			status.Error = "scan failed"
		}
		if ov, err := s.BuildScanOverview(rec.ID, rec.ProjectID, "", nil); err == nil {
			ov.Status = "failed"
			status.Overview = ov
		}
	}

	return status, nil
}

func (s *Service) prepareScan(req ScanRequest) (string, []string, projects.ScanPolicy, []string, *ScanOverview, error) {
	projectID, targets, err := s.resolveProjectAndTargets(req)
	if err != nil {
		return "", nil, projects.ScanPolicy{}, nil, nil, err
	}

	policy := projects.ScanPolicy{
		Config: map[string]interface{}{
			"secret-search-options": secrets.SecretSearchOptions{
				ShowSource:        true,
				CalculateChecksum: true,
				ExcludeTestFiles:  req.ExcludeTests,
				KeepCheckouts:     req.KeepCheckout,
				Exclusions:        diagnostics.MakeEmptyExcludes(),
			},
		},
	}

	if req.ExclusionFile != "" {
		data, err := os.ReadFile(req.ExclusionFile)
		if err != nil {
			return "", nil, projects.ScanPolicy{}, nil, nil, fmt.Errorf("read exclusion file %s: %w", req.ExclusionFile, err)
		}
		var excl diagnostics.ExcludeDefinition
		if err := yaml.Unmarshal(data, &excl); err != nil {
			return "", nil, projects.ScanPolicy{}, nil, nil, fmt.Errorf("parse exclusion file %s: %w", req.ExclusionFile, err)
		}
		policy.Config["extra-exclusions"] = &excl
	}

	scannedTargets := targets
	if req.GitDiffBase != "" {
		changed, err := resolveGitDiffFiles(targets, req.GitDiffBase)
		if err != nil {
			return "", nil, projects.ScanPolicy{}, nil, nil, err
		}
		if len(changed) == 0 {
			return projectID, targets, policy, []string{}, &ScanOverview{
				ScanID:         "",
				ProjectID:      projectID,
				Status:         "complete",
				GitDiffBase:    req.GitDiffBase,
				ScannedTargets: []string{},
				Clusters:       ScanClusters{ByRule: map[string]int{}},
				SanitisedSummary: &store.SanitisedSummary{
					ActiveFindingsBySeverity: map[string]int{},
				},
			}, nil
		}
		scannedTargets = changed
		policy.Config["target-override"] = changed
	}

	return projectID, targets, policy, scannedTargets, nil, nil
}

func (s *Service) finalizeScanOverview(scanID, projectID, gitDiffBase string, scannedTargets []string) (*ScanOverview, error) {
	ov, err := s.BuildScanOverview(scanID, projectID, gitDiffBase, scannedTargets)
	if err != nil {
		return nil, err
	}

	if len(ov.RetainedCheckouts) > 0 {
		dirs := make([]string, 0, len(ov.RetainedCheckouts))
		for _, d := range ov.RetainedCheckouts {
			dirs = append(dirs, d)
		}
		s.mu.Lock()
		s.trackedCheckouts[scanID] = trackedCheckout{
			scanID:    scanID,
			dirs:      dirs,
			createdAt: time.Now(),
		}
		s.mu.Unlock()
	}

	if rec, err := s.store.GetScanRecord(scanID); err == nil && rec != nil && rec.Status == "failed" {
		ov.Status = "failed"
		msg := "all scan targets failed to acquire"
		if ov.Acquisition != nil && len(ov.Acquisition.Failures) > 0 {
			f := ov.Acquisition.Failures[0]
			msg = fmt.Sprintf("failed to acquire %s (%s): %s", f.Target, f.ErrorKind, f.Message)
		}
		return ov, &AcquisitionFailureError{Overview: ov, Message: msg}
	}
	if ov.Acquisition != nil && ov.Acquisition.Succeeded == 0 && ov.Acquisition.Failed > 0 {
		ov.Status = "failed"
		msg := "all scan targets failed to acquire"
		if len(ov.Acquisition.Failures) > 0 {
			f := ov.Acquisition.Failures[0]
			msg = fmt.Sprintf("failed to acquire %s (%s): %s", f.Target, f.ErrorKind, f.Message)
		}
		return ov, &AcquisitionFailureError{Overview: ov, Message: msg}
	}

	return ov, nil
}

// BuildScanOverview computes a compact ScanOverview for an existing scanID.
func (s *Service) BuildScanOverview(scanID, projectID, gitDiffBase string, scannedTargets []string) (*ScanOverview, error) {
	if projectID == "" {
		var err error
		projectID, err = s.store.GetScanProjectID(scanID)
		if err != nil {
			return nil, err
		}
	}

	findings, err := s.store.GetScanFindings(scanID)
	if err != nil {
		return nil, err
	}
	summary, err := s.store.GetSanitisedSummary(scanID)
	if err != nil {
		return nil, err
	}
	filesScanned, _ := s.store.GetScanFileCount(scanID)
	acqReport, _ := s.store.GetScanAcquisitionReport(scanID)
	retained, _ := s.store.GetScanRetainedCheckouts(scanID)

	status := "complete"
	if rec, err := s.store.GetScanRecord(scanID); err == nil && rec != nil && rec.Status != "" {
		status = rec.Status
	}

	checksums := map[string]struct{}{}
	files := map[string]struct{}{}
	dirs := map[string]struct{}{}
	byRule := map[string]int{}

	suppressed := 0
	carriedForward := 0
	untriaged := 0

	for _, f := range findings {
		if f.Suppressed {
			suppressed++
			continue
		}
		if f.TriageStatus != sdk.TriageStatusUntriaged && f.TriageStatus != "" {
			carriedForward++
			continue
		}
		untriaged++
		if f.SecretChecksum != "" {
			checksums[f.SecretChecksum] = struct{}{}
		}
		files[f.File] = struct{}{}
		dirs[filepath.Dir(f.File)] = struct{}{}
		byRule[f.RuleID]++
	}

	localCheckoutPath := ""
	if len(retained) == 1 {
		for _, v := range retained {
			localCheckoutPath = v
		}
	}

	return &ScanOverview{
		ScanID:                scanID,
		ProjectID:             projectID,
		Status:                status,
		FilesScanned:          filesScanned,
		GitDiffBase:           gitDiffBase,
		ScannedTargets:        scannedTargets,
		RawFindings:           len(findings),
		AlreadySuppressed:     suppressed,
		CarriedForwardTriaged: carriedForward,
		UntriagedFindings:     untriaged,
		Clusters: ScanClusters{
			UniqueChecksums: len(checksums),
			UniqueFiles:     len(files),
			UniqueDirs:      len(dirs),
			ByRule:          byRule,
		},
		SanitisedSummary:  summary,
		Acquisition:       acqReport,
		RetainedCheckouts: retained,
		LocalCheckoutPath: localCheckoutPath,
	}, nil
}

func (s *Service) resolveProjectAndTargets(req ScanRequest) (string, []string, error) {
	if req.ProjectID != "" {
		proj, err := s.store.GetProject(req.ProjectID)
		if err != nil {
			return "", nil, fmt.Errorf("project %s not found: %w", req.ProjectID, err)
		}
		targets := make([]string, 0, len(proj.Repositories))
		for _, r := range proj.Repositories {
			targets = append(targets, r.Location)
		}
		return proj.ID, targets, nil
	}

	if len(req.Targets) == 0 {
		return "", nil, fmt.Errorf("either projectId or at least one target path/URL is required")
	}

	normalized := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !isGitURL(t) {
			if abs, err := filepath.Abs(t); err == nil {
				t = abs
			}
		}
		normalized = append(normalized, t)
	}
	if len(normalized) == 0 {
		return "", nil, fmt.Errorf("no valid targets supplied")
	}
	sort.Strings(normalized)

	// Reuse an existing project whose repository locations match exactly so
	// persisted exceptions and drift-aware triage carry forward across rescans.
	for _, ps := range s.store.ListProjectSummaries() {
		proj, err := s.store.GetProject(ps.ID)
		if err != nil {
			continue
		}
		if repoLocationsMatch(proj.Repositories, normalized) {
			return proj.ID, normalized, nil
		}
	}

	name := filepath.Base(normalized[0])
	if name == "" || name == "." || name == "/" {
		name = "agent-scan"
	}
	repos := make([]projects.Repository, 0, len(normalized))
	for _, t := range normalized {
		locType := "local"
		if isGitURL(t) {
			locType = "git"
		}
		repos = append(repos, projects.Repository{
			Location:     t,
			LocationType: locType,
		})
	}

	proj, err := s.store.CreateProject(projects.ProjectDescription{
		Name:         name,
		Workspace:    "default",
		Repositories: repos,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create project for targets: %w", err)
	}
	return proj.ID, normalized, nil
}

func repoLocationsMatch(repos []projects.Repository, sortedTargets []string) bool {
	if len(repos) != len(sortedTargets) {
		return false
	}
	locs := make([]string, 0, len(repos))
	for _, r := range repos {
		loc := r.Location
		if !isGitURL(loc) {
			if abs, err := filepath.Abs(loc); err == nil {
				loc = abs
			}
		}
		locs = append(locs, loc)
	}
	sort.Strings(locs)
	for i := range locs {
		if locs[i] != sortedTargets[i] {
			return false
		}
	}
	return true
}

func isGitURL(s string) bool {
	trimmed := strings.TrimSpace(s)
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "git://") ||
		strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "git+ssh://") ||
		gitutils.IsSSHURL(trimmed)
}

func resolveGitDiffFiles(targets []string, baseRef string) ([]string, error) {
	seen := map[string]struct{}{}
	var files []string

	for _, target := range targets {
		if isGitURL(target) {
			return nil, fmt.Errorf("gitDiffBase is only supported for local repository paths, not %s", target)
		}
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			continue
		}

		// Diff against baseRef
		diffCmd := exec.Command("git", "-C", target, "diff", "--name-only", "--diff-filter=ACMRTUXB", baseRef)
		out, err := diffCmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff %s in %s: %w", baseRef, target, err)
		}

		// Untracked non-ignored files
		untrackedOut, _ := exec.Command("git", "-C", target, "ls-files", "--others", "--exclude-standard").Output()

		combined := strings.Split(string(out)+"\n"+string(untrackedOut), "\n")
		for _, rel := range combined {
			rel = strings.TrimSpace(rel)
			if rel == "" {
				continue
			}
			full := filepath.Join(target, rel)
			if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
				if _, ok := seen[full]; !ok {
					seen[full] = struct{}{}
					files = append(files, full)
				}
			}
		}
	}

	sort.Strings(files)
	return files, nil
}

// WorklistRequest configures how findings are grouped and paged for an agent.
type WorklistRequest struct {
	ScanID            string `json:"scanId"`
	GroupBy           string `json:"groupBy,omitempty"` // "checksum" (default) | "directory" | "file" | "rule"
	OnlyUntriaged     *bool  `json:"onlyUntriaged,omitempty"`
	IncludeSuppressed bool   `json:"includeSuppressed,omitempty"`
	Severity          string `json:"severity,omitempty"`
	SamplesPerGroup   int    `json:"samplesPerGroup,omitempty"` // default 5, max 50
	Limit             int    `json:"limit,omitempty"`
	Offset            int    `json:"offset,omitempty"`
}

// WorklistLocation is a lightweight coordinate pointer guiding the agent to the exact file/line.
type WorklistLocation struct {
	FindingID      string           `json:"findingId"`
	File           string           `json:"file"`
	LocalFile      string           `json:"localFile,omitempty"`
	Line           int              `json:"line"`
	Column         int              `json:"column"`
	EndLine        int              `json:"endLine,omitempty"`
	EndColumn      int              `json:"endColumn,omitempty"`
	RuleID         string           `json:"ruleId"`
	SecretType     sdk.SecretType   `json:"secretType"`
	Severity       sdk.Severity     `json:"severity"`
	SecretChecksum string           `json:"secretChecksum"`
	TriageStatus   sdk.TriageStatus `json:"triageStatus"`
	Suppressed     bool             `json:"suppressed"`
}

// WorklistGroup clusters findings sharing a checksum, directory, file, or rule.
type WorklistGroup struct {
	GroupBy           string             `json:"groupBy"`
	GroupKey          string             `json:"groupKey"`
	RuleID            string             `json:"ruleId,omitempty"`
	SecretType        sdk.SecretType     `json:"secretType,omitempty"`
	HighestSeverity   sdk.Severity       `json:"highestSeverity"`
	OccurrenceCount   int                `json:"occurrenceCount"`
	DistinctFileCount int                `json:"distinctFileCount"`
	DistinctFiles     []string           `json:"distinctFiles"`
	SampleLocations   []WorklistLocation `json:"sampleLocations"`
}

// WorklistResult is a deterministically ordered, paginated work queue for an AI agent.
type WorklistResult struct {
	ScanID           string          `json:"scanId"`
	GroupBy          string          `json:"groupBy"`
	TotalMatching    int             `json:"totalMatchingFindings"`
	TotalGroups      int             `json:"totalGroups"`
	Offset           int             `json:"offset"`
	Limit            int             `json:"limit"`
	HasMore          bool            `json:"hasMore"`
	NextOffset       int             `json:"nextOffset,omitempty"`
	Groups           []WorklistGroup `json:"groups"`
}

// GetWorklist returns clustered, deterministically sorted pointers for a scan.
func (s *Service) GetWorklist(_ context.Context, req WorklistRequest) (*WorklistResult, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}

	groupBy := strings.ToLower(strings.TrimSpace(req.GroupBy))
	if groupBy == "" {
		groupBy = "checksum"
	}
	switch groupBy {
	case "checksum", "directory", "file", "rule":
	default:
		return nil, fmt.Errorf("unsupported groupBy %q: expected checksum, directory, file, or rule", req.GroupBy)
	}

	onlyUntriaged := true
	if req.OnlyUntriaged != nil {
		onlyUntriaged = *req.OnlyUntriaged
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	samplesPerGroup := req.SamplesPerGroup
	if samplesPerGroup <= 0 {
		samplesPerGroup = 5
	}
	if samplesPerGroup > 50 {
		samplesPerGroup = 50
	}

	findings, err := s.store.GetScanFindings(req.ScanID)
	if err != nil {
		return nil, err
	}
	retained, _ := s.store.GetScanRetainedCheckouts(req.ScanID)

	type acc struct {
		group     WorklistGroup
		fileSet   map[string]struct{}
		ruleSet   map[string]struct{}
		sevRank   int
	}

	groupsByKey := map[string]*acc{}
	totalMatching := 0

	for _, f := range findings {
		if f.Suppressed && !req.IncludeSuppressed {
			continue
		}
		if onlyUntriaged && f.TriageStatus != sdk.TriageStatusUntriaged && f.TriageStatus != "" {
			continue
		}
		if req.Severity != "" && !strings.EqualFold(string(f.Severity), req.Severity) {
			continue
		}

		totalMatching++

		var key string
		switch groupBy {
		case "checksum":
			if f.SecretChecksum != "" {
				key = f.SecretChecksum
			} else {
				key = f.FindingID
			}
		case "directory":
			key = filepath.Dir(f.File)
		case "file":
			key = f.File
		case "rule":
			key = f.RuleID
		}

		entry, ok := groupsByKey[key]
		if !ok {
			entry = &acc{
				group: WorklistGroup{
					GroupBy:         groupBy,
					GroupKey:        key,
					RuleID:          f.RuleID,
					SecretType:      f.SecretType,
					HighestSeverity: f.Severity,
				},
				fileSet: map[string]struct{}{},
				ruleSet: map[string]struct{}{},
				sevRank: severityRank(string(f.Severity)),
			}
			groupsByKey[key] = entry
		}

		entry.group.OccurrenceCount++
		entry.fileSet[f.File] = struct{}{}
		entry.ruleSet[f.RuleID] = struct{}{}
		if rank := severityRank(string(f.Severity)); rank > entry.sevRank {
			entry.sevRank = rank
			entry.group.HighestSeverity = f.Severity
		}

		if len(entry.group.SampleLocations) < samplesPerGroup {
			entry.group.SampleLocations = append(entry.group.SampleLocations, toWorklistLocation(f, retained))
		}
	}

	allGroups := make([]WorklistGroup, 0, len(groupsByKey))
	for _, entry := range groupsByKey {
		files := make([]string, 0, len(entry.fileSet))
		for fp := range entry.fileSet {
			files = append(files, fp)
		}
		sort.Strings(files)
		entry.group.DistinctFileCount = len(files)
		if len(files) > 10 {
			entry.group.DistinctFiles = files[:10]
		} else {
			entry.group.DistinctFiles = files
		}
		if len(entry.ruleSet) > 1 {
			entry.group.RuleID = "multiple"
		}
		allGroups = append(allGroups, entry.group)
	}

	// Canonical ordering: largest noise clusters first, then highest severity, then key.
	sort.Slice(allGroups, func(i, j int) bool {
		if allGroups[i].OccurrenceCount != allGroups[j].OccurrenceCount {
			return allGroups[i].OccurrenceCount > allGroups[j].OccurrenceCount
		}
		ri, rj := severityRank(string(allGroups[i].HighestSeverity)), severityRank(string(allGroups[j].HighestSeverity))
		if ri != rj {
			return ri > rj
		}
		return allGroups[i].GroupKey < allGroups[j].GroupKey
	})

	totalGroups := len(allGroups)
	start := offset
	if start > totalGroups {
		start = totalGroups
	}
	end := start + limit
	if end > totalGroups {
		end = totalGroups
	}

	hasMore := end < totalGroups
	nextOffset := 0
	if hasMore {
		nextOffset = end
	}

	return &WorklistResult{
		ScanID:        req.ScanID,
		GroupBy:       groupBy,
		TotalMatching: totalMatching,
		TotalGroups:   totalGroups,
		Offset:        offset,
		Limit:         limit,
		HasMore:       hasMore,
		NextOffset:    nextOffset,
		Groups:        allGroups[start:end],
	}, nil
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "CONFIRMED":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// PreviewSuppressionRequest specifies a candidate suppression rule to dry-run on a scan.
type PreviewSuppressionRequest struct {
	ScanID string                      `json:"scanId"`
	RuleID string                      `json:"ruleId,omitempty"`
	Scope  *store.ExceptionScopeDetail `json:"scope"`
}

// ValidateSuppressionScope enforces regex validity and rejects overly broad
// wildcard scopes so an automated agent cannot accidentally suppress a whole repo.
func ValidateSuppressionScope(ruleID string, scope *store.ExceptionScopeDetail) error {
	if scope == nil {
		return fmt.Errorf("scope is required")
	}

	checkRegex := func(field, pattern string) (*regexp.Regexp, error) {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			return nil, fmt.Errorf("%s cannot be empty", field)
		}
		if isWildcardRegex(trimmed) {
			return nil, fmt.Errorf("%s %q is too broad; wildcard catch-all patterns are forbidden", field, pattern)
		}
		re, err := regexp.Compile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in %s: %w", field, err)
		}
		return re, nil
	}

	switch scope.Type {
	case "globalHash":
		if strings.TrimSpace(scope.SecretChecksum) == "" {
			return fmt.Errorf("scope.secretChecksum is required for globalHash")
		}
	case "pathHash":
		if strings.TrimSpace(scope.Path) == "" || strings.TrimSpace(scope.SecretChecksum) == "" {
			return fmt.Errorf("scope.path and scope.secretChecksum are required for pathHash")
		}
	case "globalString":
		if len(strings.TrimSpace(scope.StringMatch)) < 4 {
			return fmt.Errorf("scope.stringMatch must be at least 4 characters for globalString")
		}
	case "pathString":
		if strings.TrimSpace(scope.Path) == "" || strings.TrimSpace(scope.StringMatch) == "" {
			return fmt.Errorf("scope.path and scope.stringMatch are required for pathString")
		}
	case "pathRegex":
		if _, err := checkRegex("scope.regexMatch", scope.RegexMatch); err != nil {
			return err
		}
	case "globalRegex":
		re, err := checkRegex("scope.regexMatch", scope.RegexMatch)
		if err != nil {
			return err
		}
		if (ruleID == "" || ruleID == "*") && (re.MatchString("") || (re.MatchString("a") && re.MatchString("1") && re.MatchString("AKIAIOSFODNN7EXAMPLE"))) {
			return fmt.Errorf("globalRegex %q with wildcard ruleId is overly broad", scope.RegexMatch)
		}
	case "pathRegexRegex":
		if _, err := checkRegex("scope.path", scope.Path); err != nil {
			return err
		}
		if _, err := checkRegex("scope.regexMatch", scope.RegexMatch); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported exception scope type %q (supported: globalHash, pathHash, globalString, pathString, pathRegex, globalRegex, pathRegexRegex)", scope.Type)
	}

	return nil
}

func isWildcardRegex(p string) bool {
	// Strip outer anchors and whitespace to catch variants like ^.*$, .+, (.+), etc.
	s := strings.TrimSpace(p)
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimSuffix(s, "$")
	s = strings.Trim(s, "()")
	switch s {
	case "", ".", ".*", ".+", ".*?", ".+?", "[\\s\\S]*", "[\\s\\S]+", "[^]*":
		return true
	}
	return false
}

// PreviewSuppression dry-runs a candidate exception rule against scanID without mutating state.
func (s *Service) PreviewSuppression(_ context.Context, req PreviewSuppressionRequest) (*store.ExceptionPreview, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}
	ruleID := req.RuleID
	if ruleID == "" {
		ruleID = "*"
	}
	if err := ValidateSuppressionScope(ruleID, req.Scope); err != nil {
		return nil, err
	}

	exc := &store.Exception{
		ID:     "preview",
		RuleID: ruleID,
		Scope:  req.Scope,
		Status: "active",
	}
	return s.store.PreviewExceptionOnScan(req.ScanID, exc)
}

// TriageDecision is a single finding verdict submitted by an agent or human.
type TriageDecision struct {
	FindingID           string   `json:"findingId"`
	ApplyToSameChecksum bool     `json:"applyToSameChecksum,omitempty"`
	Verdict             string   `json:"verdict"` // "true_positive" | "false_positive" | "needs_review"
	Reason              string   `json:"reason,omitempty"`
	Justification       string   `json:"justification,omitempty"`
	RemediationHint     string   `json:"remediationHint,omitempty"`
	ContextClues        []string `json:"contextClues,omitempty"`
	FPLikelihood        *float64 `json:"fpLikelihood,omitempty"`
	PersistException    bool     `json:"persistException,omitempty"`
	ExceptionScope      string   `json:"exceptionScope,omitempty"` // "globalHash" (default if ApplyToSameChecksum) | "pathHash" | "pathString"
	StringMatch         string   `json:"stringMatch,omitempty"`    // required when exceptionScope == "pathString"
}

// TriageBatchRequest writes back a batch of triage verdicts for a scan.
type TriageBatchRequest struct {
	ScanID    string           `json:"scanId"`
	TriagedBy string           `json:"triagedBy,omitempty"`
	Decisions []TriageDecision `json:"decisions"`
}

// TriageBatchResult reports what changed after applying a batch of verdicts.
type TriageBatchResult struct {
	ScanID              string                  `json:"scanId"`
	UpdatedFindings     int                     `json:"updatedFindings"`
	CreatedExceptionIDs []string                `json:"createdExceptionIds,omitempty"`
	SanitisedSummary    *store.SanitisedSummary `json:"sanitisedSummary"`
}

// RecordTriageBatch persists triage verdicts, suppresses false positives,
// optionally creates durable exceptions for future scans, logs audit events,
// and recomputes the scan's sanitised summary.
func (s *Service) RecordTriageBatch(_ context.Context, req TriageBatchRequest) (*TriageBatchResult, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}
	if len(req.Decisions) == 0 {
		return nil, fmt.Errorf("at least one triage decision is required")
	}

	projectID, err := s.store.GetScanProjectID(req.ScanID)
	if err != nil {
		return nil, err
	}

	scanFindings, err := s.store.GetScanFindings(req.ScanID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.StoredFinding, len(scanFindings))
	for _, f := range scanFindings {
		byID[f.FindingID] = f
	}

	triagedBy := strings.TrimSpace(req.TriagedBy)
	if triagedBy == "" {
		triagedBy = "agent:mcp"
	}

	totalUpdated := 0
	var createdExcIDs []string

	for _, dec := range req.Decisions {
		status, err := parseTriageStatus(dec.Verdict)
		if err != nil {
			return nil, fmt.Errorf("finding %s: %w", dec.FindingID, err)
		}
		finding, ok := byID[dec.FindingID]
		if !ok {
			return nil, fmt.Errorf("finding %s not found in scan %s", dec.FindingID, req.ScanID)
		}

		fpLikelihood := 0.5
		if dec.FPLikelihood != nil {
			fpLikelihood = *dec.FPLikelihood
		} else {
			switch status {
			case sdk.TriageStatusFalsePositive:
				fpLikelihood = 0.98
			case sdk.TriageStatusTruePositive:
				fpLikelihood = 0.02
			}
		}

		ann := &sdk.AIAnnotation{
			Model:           triagedBy,
			Provider:        "agent-mcp",
			PromptMode:      sdk.PromptModeRawValue,
			FPLikelihood:    fpLikelihood,
			Summary:         dec.Justification,
			RemediationHint: dec.RemediationHint,
			ContextClues:    dec.ContextClues,
			GeneratedAt:     time.Now().UTC(),
			Verdict:         string(status),
			ReasonCategory:  dec.Reason,
			TriageSource:    triagedBy,
		}

		update := store.TriageUpdate{
			Status:              status,
			Source:              triagedBy,
			Annotation:          ann,
			ApplyToSameChecksum: dec.ApplyToSameChecksum,
		}

		switch status {
		case sdk.TriageStatusFalsePositive:
			supp := true
			update.Suppressed = &supp

			if dec.PersistException {
				scopeType := dec.ExceptionScope
				if scopeType == "" {
					if dec.ApplyToSameChecksum {
						scopeType = "globalHash"
					} else {
						scopeType = "pathHash"
					}
				}
				var scope *store.ExceptionScopeDetail
				switch scopeType {
				case "globalHash":
					if finding.SecretChecksum == "" {
						return nil, fmt.Errorf("finding %s has no secretChecksum for globalHash exception", dec.FindingID)
					}
					scope = &store.ExceptionScopeDetail{
						Type:           "globalHash",
						SecretChecksum: finding.SecretChecksum,
					}
				case "pathHash":
					if finding.SecretChecksum == "" {
						return nil, fmt.Errorf("finding %s has no secretChecksum for pathHash exception", dec.FindingID)
					}
					scope = &store.ExceptionScopeDetail{
						Type:           "pathHash",
						Path:           finding.File,
						SecretChecksum: finding.SecretChecksum,
					}
				case "pathString":
					strMatch := strings.TrimSpace(dec.StringMatch)
					if strMatch == "" {
						strMatch = strings.TrimSpace(finding.SourceContext)
					}
					scope = &store.ExceptionScopeDetail{
						Type:        "pathString",
						Path:        finding.File,
						StringMatch: strMatch,
					}
				default:
					return nil, fmt.Errorf("finding %s: unsupported exceptionScope %q (expected globalHash, pathHash, or pathString)", dec.FindingID, scopeType)
				}

				if err := ValidateSuppressionScope("*", scope); err != nil {
					return nil, fmt.Errorf("finding %s exception scope: %w", dec.FindingID, err)
				}

				reason := dec.Reason
				if reason == "" {
					reason = "false_positive_pattern"
				}
				exc := &store.Exception{
					ID:            "exc_" + uuid.New().String()[:12],
					ProjectID:     projectID,
					RuleID:        "*",
					Scope:         scope,
					Reason:        reason,
					Justification: dec.Justification,
					CreatedBy:     triagedBy,
					CreatedAt:     time.Now().UTC(),
					Status:        "active",
					Tags:          []string{"agent-triaged"},
					AuditTrail: []*store.AuditEvent{
						{
							Action:    "exception.created",
							Timestamp: time.Now().UTC(),
							User:      triagedBy,
							Details:   fmt.Sprintf("Created during agent triage of scan %s (%s)", req.ScanID, reason),
						},
					},
				}
				if err := s.store.CreateException(exc); err != nil {
					return nil, fmt.Errorf("create exception for finding %s: %w", dec.FindingID, err)
				}
				update.ExceptionID = exc.ID
				createdExcIDs = append(createdExcIDs, exc.ID)
			}

		case sdk.TriageStatusTruePositive:
			supp := false
			update.Suppressed = &supp
		}

		updated, err := s.store.UpdateFindingTriage(req.ScanID, dec.FindingID, update)
		if err != nil {
			return nil, err
		}
		totalUpdated += updated

		diffJSON, _ := json.Marshal(map[string]interface{}{
			"scanId":              req.ScanID,
			"verdict":             status,
			"reason":              dec.Reason,
			"applyToSameChecksum": dec.ApplyToSameChecksum,
			"updatedRows":         updated,
			"exceptionId":         update.ExceptionID,
		})
		_ = s.store.RecordAuditEvent(&store.AuditEvent{
			Action:    "finding.triaged",
			Timestamp: time.Now().UTC(),
			User:      triagedBy,
			Details:   string(diffJSON),
		}, "finding", dec.FindingID)
	}

	summary, err := s.store.RecomputeScanSummary(req.ScanID)
	if err != nil {
		return nil, err
	}

	return &TriageBatchResult{
		ScanID:              req.ScanID,
		UpdatedFindings:     totalUpdated,
		CreatedExceptionIDs: createdExcIDs,
		SanitisedSummary:    summary,
	}, nil
}

func parseTriageStatus(verdict string) (sdk.TriageStatus, error) {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "true_positive":
		return sdk.TriageStatusTruePositive, nil
	case "false_positive":
		return sdk.TriageStatusFalsePositive, nil
	case "needs_review":
		return sdk.TriageStatusNeedsReview, nil
	default:
		return "", fmt.Errorf("invalid verdict %q: expected true_positive, false_positive, or needs_review", verdict)
	}
}

// ApplySuppressionRuleRequest creates a durable pattern-level exception rule
// and retroactively suppresses matching findings in scanID.
type ApplySuppressionRuleRequest struct {
	ScanID        string                      `json:"scanId"`
	RuleID        string                      `json:"ruleId,omitempty"`
	Scope         *store.ExceptionScopeDetail `json:"scope"`
	Reason        string                      `json:"reason"`
	Justification string                      `json:"justification"`
	TriagedBy     string                      `json:"triagedBy,omitempty"`
	Force         bool                        `json:"force,omitempty"`
}

// ApplySuppressionRule validates, persists, and reconciles a suppression rule against scanID.
func (s *Service) ApplySuppressionRule(_ context.Context, req ApplySuppressionRuleRequest) (*store.ExceptionApplyResult, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, fmt.Errorf("reason is required")
	}
	if strings.TrimSpace(req.Justification) == "" {
		return nil, fmt.Errorf("justification is required")
	}

	ruleID := strings.TrimSpace(req.RuleID)
	if ruleID == "" {
		ruleID = "*"
	}
	if err := ValidateSuppressionScope(ruleID, req.Scope); err != nil {
		return nil, err
	}

	projectID, err := s.store.GetScanProjectID(req.ScanID)
	if err != nil {
		return nil, err
	}

	triagedBy := strings.TrimSpace(req.TriagedBy)
	if triagedBy == "" {
		triagedBy = "agent:mcp"
	}

	exc := &store.Exception{
		ID:            "exc_" + uuid.New().String()[:12],
		ProjectID:     projectID,
		RuleID:        ruleID,
		Scope:         req.Scope,
		Reason:        req.Reason,
		Justification: req.Justification,
		CreatedBy:     triagedBy,
		CreatedAt:     time.Now().UTC(),
		Status:        "active",
		Tags:          []string{"agent-suppression-rule"},
		AuditTrail: []*store.AuditEvent{
			{
				Action:    "exception.created",
				Timestamp: time.Now().UTC(),
				User:      triagedBy,
				Details:   fmt.Sprintf("Pattern rule applied to scan %s: %s", req.ScanID, req.Justification),
			},
		},
	}

	return s.store.ApplyExceptionToScan(req.ScanID, exc, triagedBy, req.Force)
}

func toWorklistLocation(f *store.StoredFinding, retained map[string]string) WorklistLocation {
	return WorklistLocation{
		FindingID:      f.FindingID,
		File:           f.File,
		LocalFile:      resolveLocalFile(f.File, retained),
		Line:           f.Line,
		Column:         f.Column,
		EndLine:        f.EndLine,
		EndColumn:      f.EndColumn,
		RuleID:         f.RuleID,
		SecretType:     f.SecretType,
		Severity:       f.Severity,
		SecretChecksum: f.SecretChecksum,
		TriageStatus:   f.TriageStatus,
		Suppressed:     f.Suppressed,
	}
}

// resolveLocalFile maps a finding's transposed remote repository URL path back
// to the local retained checkout directory (with path traversal verification).
func resolveLocalFile(filePath string, retained map[string]string) string {
	if len(retained) == 0 || filePath == "" {
		return ""
	}
	for repoURL, localDir := range retained {
		if repoURL == "" || localDir == "" {
			continue
		}
		prefixes := []string{strings.TrimRight(repoURL, "/")}
		if strings.HasSuffix(prefixes[0], ".git") {
			prefixes = append(prefixes, strings.TrimSuffix(prefixes[0], ".git"))
		} else {
			prefixes = append(prefixes, prefixes[0]+".git")
		}
		for _, prefix := range prefixes {
			withSlash := prefix + "/"
			if strings.HasPrefix(filePath, withSlash) {
				rel := strings.TrimPrefix(filePath, withSlash)
				cleanBase := filepath.Clean(localDir)
				candidate := filepath.Clean(filepath.Join(cleanBase, filepath.FromSlash(rel)))
				relCheck, err := filepath.Rel(cleanBase, candidate)
				if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) || filepath.IsAbs(relCheck) {
					return ""
				}
				return candidate
			}
		}
	}
	return ""
}

// ListFindingsRequest filters and paginates individual findings in a scan.
type ListFindingsRequest struct {
	ScanID            string `json:"scanId"`
	File              string `json:"file,omitempty"`
	RuleID            string `json:"ruleId,omitempty"`
	SecretChecksum    string `json:"secretChecksum,omitempty"`
	TriageStatus      string `json:"triageStatus,omitempty"`
	Severity          string `json:"severity,omitempty"`
	IncludeSuppressed bool   `json:"includeSuppressed,omitempty"`
	Limit             int    `json:"limit,omitempty"`
	Offset            int    `json:"offset,omitempty"`
}

// ListFindingsResult is a deterministically ordered page of individual findings.
type ListFindingsResult struct {
	ScanID     string             `json:"scanId"`
	TotalCount int                `json:"totalCount"`
	Offset     int                `json:"offset"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"hasMore"`
	NextOffset int                `json:"nextOffset,omitempty"`
	Findings   []WorklistLocation `json:"findings"`
}

// ListFindings returns individual findings in canonical order without the
// worklist 5-sample cap.
func (s *Service) ListFindings(_ context.Context, req ListFindingsRequest) (*ListFindingsResult, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	findings, err := s.store.GetScanFindings(req.ScanID)
	if err != nil {
		return nil, err
	}
	retained, _ := s.store.GetScanRetainedCheckouts(req.ScanID)

	matched := make([]WorklistLocation, 0, len(findings))
	for _, f := range findings {
		if f.Suppressed && !req.IncludeSuppressed {
			continue
		}
		if req.File != "" && f.File != req.File && !strings.HasSuffix(f.File, "/"+req.File) {
			continue
		}
		if req.RuleID != "" && !strings.EqualFold(f.RuleID, req.RuleID) {
			continue
		}
		if req.SecretChecksum != "" && f.SecretChecksum != req.SecretChecksum {
			continue
		}
		if req.TriageStatus != "" {
			ts := string(f.TriageStatus)
			if ts == "" {
				ts = string(sdk.TriageStatusUntriaged)
			}
			if !strings.EqualFold(ts, req.TriageStatus) {
				continue
			}
		}
		if req.Severity != "" && !strings.EqualFold(string(f.Severity), req.Severity) {
			continue
		}
		matched = append(matched, toWorklistLocation(f, retained))
	}

	sort.Slice(matched, func(i, j int) bool {
		ri, rj := severityRank(string(matched[i].Severity)), severityRank(string(matched[j].Severity))
		if ri != rj {
			return ri > rj
		}
		if matched[i].File != matched[j].File {
			return matched[i].File < matched[j].File
		}
		if matched[i].Line != matched[j].Line {
			return matched[i].Line < matched[j].Line
		}
		if matched[i].Column != matched[j].Column {
			return matched[i].Column < matched[j].Column
		}
		return matched[i].FindingID < matched[j].FindingID
	})

	total := len(matched)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	hasMore := end < total
	nextOffset := 0
	if hasMore {
		nextOffset = end
	}

	return &ListFindingsResult{
		ScanID:     req.ScanID,
		TotalCount: total,
		Offset:     offset,
		Limit:      limit,
		HasMore:    hasMore,
		NextOffset: nextOffset,
		Findings:   matched[start:end],
	}, nil
}

// FindingContextRequest asks for numbered source lines around a finding.
type FindingContextRequest struct {
	ScanID      string `json:"scanId"`
	FindingID   string `json:"findingId"`
	BeforeLines int    `json:"beforeLines,omitempty"`
	AfterLines  int    `json:"afterLines,omitempty"`
}

// FindingContextLine is one numbered line of source code around a finding.
type FindingContextLine struct {
	Line    int    `json:"line"`
	Text    string `json:"text"`
	IsMatch bool   `json:"isMatch,omitempty"`
}

// FindingContextResult contains surrounding source context for a finding.
type FindingContextResult struct {
	ScanID    string               `json:"scanId"`
	FindingID string               `json:"findingId"`
	File      string               `json:"file"`
	LocalFile string               `json:"localFile,omitempty"`
	Line      int                  `json:"line"`
	Column    int                  `json:"column"`
	StartLine int                  `json:"startLine"`
	EndLine   int                  `json:"endLine"`
	Source    string               `json:"source"` // "local_file" | "retained_checkout" | "stored_context"
	Lines     []FindingContextLine `json:"lines"`
}

// GetFindingContext reads surrounding source lines for a finding from local
// disk or a retained remote checkout, falling back to stored source_context.
func (s *Service) GetFindingContext(_ context.Context, req FindingContextRequest) (*FindingContextResult, error) {
	if req.FindingID == "" {
		return nil, fmt.Errorf("findingId is required")
	}

	before := req.BeforeLines
	if before <= 0 {
		before = 20
	}
	if before > 200 {
		before = 200
	}
	after := req.AfterLines
	if after <= 0 {
		after = 20
	}
	if after > 200 {
		after = 200
	}

	var target *store.StoredFinding
	if req.ScanID != "" {
		findings, err := s.store.GetScanFindings(req.ScanID)
		if err != nil {
			return nil, err
		}
		for _, f := range findings {
			if f.FindingID == req.FindingID {
				target = f
				break
			}
		}
	} else {
		f, err := s.store.GetFinding(req.FindingID)
		if err != nil {
			return nil, err
		}
		target = &store.StoredFinding{
			FindingID:     f.ID,
			File:          f.File,
			Line:          f.Line,
			Column:        f.Column,
			SourceContext: f.SourceContext,
		}
	}

	if target == nil {
		return nil, fmt.Errorf("finding %s not found in scan %s", req.FindingID, req.ScanID)
	}

	var retained map[string]string
	if req.ScanID != "" {
		retained, _ = s.store.GetScanRetainedCheckouts(req.ScanID)
	}

	localFile := resolveLocalFile(target.File, retained)
	sourceKind := ""
	readPath := ""

	if localFile != "" {
		if info, err := os.Stat(localFile); err == nil && !info.IsDir() {
			readPath = localFile
			sourceKind = "retained_checkout"
		}
	}
	if readPath == "" && !isGitURL(target.File) {
		if info, err := os.Stat(target.File); err == nil && !info.IsDir() {
			readPath = target.File
			localFile = target.File
			sourceKind = "local_file"
		}
	}

	if readPath != "" {
		lines, startLine, endLine, err := readLineWindow(readPath, target.Line, before, after)
		if err == nil {
			return &FindingContextResult{
				ScanID:    req.ScanID,
				FindingID: target.FindingID,
				File:      target.File,
				LocalFile: localFile,
				Line:      target.Line,
				Column:    target.Column,
				StartLine: startLine,
				EndLine:   endLine,
				Source:    sourceKind,
				Lines:     lines,
			}, nil
		}
	}

	// Fallback to stored source_context
	var fallbackLines []FindingContextLine
	if target.SourceContext != "" {
		for idx, l := range strings.Split(target.SourceContext, "\n") {
			lineNum := target.Line + idx
			if lineNum <= 0 {
				lineNum = idx + 1
			}
			fallbackLines = append(fallbackLines, FindingContextLine{
				Line:    lineNum,
				Text:    l,
				IsMatch: idx == 0,
			})
		}
	}
	startLine := target.Line
	endLine := target.Line
	if len(fallbackLines) > 0 {
		startLine = fallbackLines[0].Line
		endLine = fallbackLines[len(fallbackLines)-1].Line
	}

	return &FindingContextResult{
		ScanID:    req.ScanID,
		FindingID: target.FindingID,
		File:      target.File,
		LocalFile: localFile,
		Line:      target.Line,
		Column:    target.Column,
		StartLine: startLine,
		EndLine:   endLine,
		Source:    "stored_context",
		Lines:     fallbackLines,
	}, nil
}

func readLineWindow(filePath string, targetLine, before, after int) ([]FindingContextLine, int, int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	if targetLine < 1 {
		targetLine = 1
	}
	startLine := targetLine - before
	if startLine < 1 {
		startLine = 1
	}
	endLine := targetLine + after

	scanner := bufio.NewScanner(f)
	// Support long lines (up to 1 MiB) cleanly
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var lines []FindingContextLine
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo < startLine {
			continue
		}
		if lineNo > endLine {
			break
		}
		lines = append(lines, FindingContextLine{
			Line:    lineNo,
			Text:    scanner.Text(),
			IsMatch: lineNo == targetLine,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, 0, err
	}
	actualEnd := startLine
	if len(lines) > 0 {
		actualEnd = lines[len(lines)-1].Line
	}
	return lines, startLine, actualEnd, nil
}

// CleanupCheckoutResult summarises deleting a retained remote checkout for a scan.
type CleanupCheckoutResult struct {
	ScanID       string   `json:"scanId"`
	RemovedPaths []string `json:"removedPaths"`
	Cleaned      bool     `json:"cleaned"`
}

// CleanupCheckout deletes retained remote Git checkouts for scanID, clears
// retainedCheckouts metadata in SQLite, and records an audit_log entry.
func (s *Service) CleanupCheckout(_ context.Context, scanID string) (*CleanupCheckoutResult, error) {
	if scanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}

	retained, err := s.store.GetScanRetainedCheckouts(scanID)
	if err != nil {
		return nil, err
	}

	projectID, _ := s.store.GetScanProjectID(scanID)
	removed := []string{}
	seen := map[string]struct{}{}

	for _, dir := range retained {
		if dir == "" {
			continue
		}
		if _, ok := seen[dir]; !ok {
			seen[dir] = struct{}{}
			if err := os.RemoveAll(dir); err == nil {
				removed = append(removed, dir)
			}
		}
	}

	// Remove the per-scan directory <codeBaseDir>/<projectID>/<scanID> if present.
	if projectID != "" && s.store.GetCodeBaseDir() != "" {
		scanDir := filepath.Join(s.store.GetCodeBaseDir(), projectID, scanID)
		if info, err := os.Stat(scanDir); err == nil && info.IsDir() {
			if err := os.RemoveAll(scanDir); err == nil {
				if _, ok := seen[scanDir]; !ok {
					removed = append(removed, scanDir)
				}
			}
		}
	}
	sort.Strings(removed)

	if err := s.store.ClearScanRetainedCheckouts(scanID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	delete(s.trackedCheckouts, scanID)
	s.mu.Unlock()

	details, _ := json.Marshal(map[string]interface{}{
		"scanId":       scanID,
		"removedPaths": removed,
	})
	_ = s.store.RecordAuditEvent(&store.AuditEvent{
		Action:    "checkout.cleaned",
		Timestamp: time.Now().UTC(),
		User:      "agent:mcp",
		Details:   string(details),
	}, "scan", scanID)

	return &CleanupCheckoutResult{
		ScanID:       scanID,
		RemovedPaths: removed,
		Cleaned:      len(removed) > 0,
	}, nil
}

// CleanupAllTrackedCheckouts deletes all retained checkouts tracked by this
// Service instance (invoked on ephemeral server exit).
func (s *Service) CleanupAllTrackedCheckouts() {
	s.mu.RLock()
	scanIDs := make([]string, 0, len(s.trackedCheckouts))
	for sid := range s.trackedCheckouts {
		scanIDs = append(scanIDs, sid)
	}
	s.mu.RUnlock()

	for _, sid := range scanIDs {
		_, _ = s.CleanupCheckout(context.Background(), sid)
	}
}

func (s *Service) cleanupExpiredCheckouts() {
	ttl := resolveCheckoutTTL()
	if ttl <= 0 {
		return
	}
	now := time.Now()
	s.mu.RLock()
	var expired []string
	for sid, tc := range s.trackedCheckouts {
		if now.Sub(tc.createdAt) >= ttl {
			expired = append(expired, sid)
		}
	}
	s.mu.RUnlock()

	for _, sid := range expired {
		_, _ = s.CleanupCheckout(context.Background(), sid)
	}
}

func resolveCheckoutTTL() time.Duration {
	v := strings.TrimSpace(os.Getenv("CHECKMATE_CHECKOUT_TTL"))
	if v == "" {
		return 24 * time.Hour
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if hrs, err := strconv.Atoi(v); err == nil && hrs > 0 {
		return time.Duration(hrs) * time.Hour
	}
	return 24 * time.Hour
}

