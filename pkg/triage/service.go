package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Service orchestrates agent-driven scanning, finding clustering, dry-run
// suppression previews, triage verdict write-back, rule suppression, and
// sanitised report export. It is transport-agnostic and shared by both pkg/mcp
// and pkg/api.
type Service struct {
	store store.PlatformStore
}

// NewService creates a new triage Service backed by PlatformStore.
func NewService(s store.PlatformStore) *Service {
	return &Service{store: s}
}

// ScanRequest configures a scan triggered by an AI agent or API client.
type ScanRequest struct {
	Targets       []string `json:"targets,omitempty"`
	ProjectID     string   `json:"projectId,omitempty"`
	GitDiffBase   string   `json:"gitDiffBase,omitempty"`
	ExcludeTests  bool     `json:"excludeTests,omitempty"`
	ExclusionFile string   `json:"exclusionFile,omitempty"`
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
	ScanID                string                  `json:"scanId"`
	ProjectID             string                  `json:"projectId"`
	Status                string                  `json:"status"`
	FilesScanned          int                     `json:"filesScanned"`
	GitDiffBase           string                  `json:"gitDiffBase,omitempty"`
	ScannedTargets        []string                `json:"scannedTargets,omitempty"`
	RawFindings           int                     `json:"rawFindings"`
	AlreadySuppressed     int                     `json:"alreadySuppressed"`
	CarriedForwardTriaged int                     `json:"carriedForwardTriaged"`
	UntriagedFindings     int                     `json:"untriagedFindings"`
	Clusters              ScanClusters            `json:"clusters"`
	SanitisedSummary      *store.SanitisedSummary `json:"sanitisedSummary"`
}

// Scan runs a deterministic scan, persists results to SQLite, reconciles active
// exceptions, and returns a compact clustered overview.
func (s *Service) Scan(ctx context.Context, req ScanRequest) (*ScanOverview, error) {
	if s.store == nil {
		return nil, fmt.Errorf("store not initialised")
	}

	projectID, targets, err := s.resolveProjectAndTargets(req)
	if err != nil {
		return nil, err
	}

	policy := projects.ScanPolicy{
		Config: map[string]interface{}{
			"secret-search-options": secrets.SecretSearchOptions{
				ShowSource:        true,
				CalculateChecksum: true,
				ExcludeTestFiles:  req.ExcludeTests,
				Exclusions:        diagnostics.MakeEmptyExcludes(),
			},
		},
	}

	if req.ExclusionFile != "" {
		data, err := os.ReadFile(req.ExclusionFile)
		if err != nil {
			return nil, fmt.Errorf("read exclusion file %s: %w", req.ExclusionFile, err)
		}
		var excl diagnostics.ExcludeDefinition
		if err := yaml.Unmarshal(data, &excl); err != nil {
			return nil, fmt.Errorf("parse exclusion file %s: %w", req.ExclusionFile, err)
		}
		policy.Config["extra-exclusions"] = &excl
	}

	scannedTargets := targets
	if req.GitDiffBase != "" {
		changed, err := resolveGitDiffFiles(targets, req.GitDiffBase)
		if err != nil {
			return nil, err
		}
		if len(changed) == 0 {
			return &ScanOverview{
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

	var scanID string
	s.store.RunScan(
		ctx,
		projectID,
		policy,
		nil,
		func(id string) { scanID = id },
		nil,
		nil,
		nil,
		nil,
	)

	if scanID == "" {
		return nil, fmt.Errorf("scan failed to start")
	}

	return s.BuildScanOverview(scanID, projectID, req.GitDiffBase, scannedTargets)
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

	return &ScanOverview{
		ScanID:                scanID,
		ProjectID:             projectID,
		Status:                "complete",
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
		SanitisedSummary: summary,
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
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "git@") ||
		strings.HasPrefix(s, "ssh://")
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
	Limit             int    `json:"limit,omitempty"`
	Offset            int    `json:"offset,omitempty"`
}

// WorklistLocation is a lightweight coordinate pointer guiding the agent to the exact file/line.
type WorklistLocation struct {
	FindingID      string           `json:"findingId"`
	File           string           `json:"file"`
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

	findings, err := s.store.GetScanFindings(req.ScanID)
	if err != nil {
		return nil, err
	}

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

		if len(entry.group.SampleLocations) < 5 {
			entry.group.SampleLocations = append(entry.group.SampleLocations, WorklistLocation{
				FindingID:      f.FindingID,
				File:           f.File,
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
			})
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
