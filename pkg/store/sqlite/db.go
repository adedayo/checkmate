package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/core/util"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite" // CGO-free SQLite driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB is the SQLite-backed ProjectManager. It implements the projects.ProjectManager
// interface from checkmate-core, so it is a drop-in replacement for the Badger
// implementation without any changes to call sites.
type DB struct {
	db                *sql.DB
	baseDir           string
	codeBaseDir       string
	mu                sync.RWMutex
	broker            *store.ScanEventBroker
	webhookDispatcher func(eventType string, data interface{})
}

func (d *DB) SetWebhookDispatcher(dispatcher func(eventType string, data interface{})) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.webhookDispatcher = dispatcher
}

const (
	driverName   = "sqlite"
	migrationDir = "migrations"
)

// New opens (or creates) the CheckMate SQLite database at dataPath/checkmate.db,
// applies any pending migrations, and returns a ready DB.
//
// dataPath is the CheckMate data directory (e.g. ~/.checkmate).
func New(dataPath string) (*DB, error) {
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataPath, "checkmate.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)

	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite is single-writer. WAL mode is set in the migration, but enforce
	// a single writer connection to prevent SQLITE_BUSY under load.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if _, err := sqlDB.Exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("enable wal and foreign keys: %w", err)
	}

	if err := runMigrations(sqlDB, dbPath); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &DB{
		db:          sqlDB,
		baseDir:     dataPath,
		codeBaseDir: filepath.Join(dataPath, "code"),
		broker:      store.NewScanEventBroker(),
	}, nil
}

func runMigrations(db *sql.DB, dbPath string) error {
	src, err := iofs.New(migrationsFS, migrationDir)
	if err != nil {
		return fmt.Errorf("create migration source: %w", err)
	}

	driver, err := sqlite3.WithInstance(db, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("create migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "sqlite3", driver)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}

// GetBroker returns the PubSub broker for scan events.
func (d *DB) GetBroker() *store.ScanEventBroker {
	return d.broker
}

// ─── projects.ProjectManager implementation ────────────────────────────────────

// GetBaseDir returns the CheckMate data directory root.
func (d *DB) GetBaseDir() string { return d.baseDir }

// GetCodeBaseDir returns the directory where git repos are checked out.
func (d *DB) GetCodeBaseDir() string { return d.codeBaseDir }

// Close releases the database connection.
func (d *DB) Close() error { return d.db.Close() }

// GetWorkspaces returns all workspace names and their associated project summaries.
func (d *DB) GetWorkspaces() (*projects.Workspace, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.QueryContext(context.Background(),
		`SELECT id, workspace, name, data, created_at, updated_at FROM projects ORDER BY workspace, name`)
	if err != nil {
		return nil, fmt.Errorf("query projects for workspaces: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	ws := &projects.Workspace{
		Details: make(map[string]*projects.WorkspaceDetail),
	}

	for rows.Next() {
		ps, err := d.scanProjectSummaryFromRow(rows)
		if err != nil {
			log.Printf("GetWorkspaces: scan row: %v", err)
			continue
		}
		workspace := ps.Workspace
		if _, exists := ws.Details[workspace]; !exists {
			ws.Details[workspace] = &projects.WorkspaceDetail{
				Summary:          &projects.ScanSummary{},
				ProjectSummaries: []*projects.ProjectSummary{},
			}
		}
		ws.Details[workspace].ProjectSummaries = append(
			ws.Details[workspace].ProjectSummaries, ps)
	}

	return ws, rows.Err()
}

// SaveWorkspaces persists workspace names. In the SQLite implementation, workspaces
// are derived from projects — this updates the workspace name cache table.
func (d *DB) SaveWorkspaces(wss *projects.Workspace) error {
	if wss == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for name := range wss.Details {
		if _, err := tx.ExecContext(context.Background(),
			`INSERT OR IGNORE INTO workspaces(name) VALUES (?)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListProjectSummaries returns all project summaries ordered by workspace then name.
func (d *DB) ListProjectSummaries() []*projects.ProjectSummary {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.QueryContext(context.Background(),
		`SELECT id, workspace, name, data, created_at, updated_at FROM projects ORDER BY workspace, name`)
	if err != nil {
		log.Printf("ListProjectSummaries: %v", err)
		return nil
	}
	defer func() {
		_ = rows.Close()
	}()

	var summaries []*projects.ProjectSummary
	for rows.Next() {
		ps, err := d.scanProjectSummaryFromRow(rows)
		if err != nil {
			log.Printf("ListProjectSummaries: scan: %v", err)
			continue
		}
		summaries = append(summaries, ps)
	}
	return summaries
}

// GetProjectSummary retrieves a project summary by ID.
func (d *DB) GetProjectSummary(projectID string) (*projects.ProjectSummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRowContext(context.Background(),
		`SELECT id, workspace, name, data, created_at, updated_at FROM projects WHERE id = ?`, projectID)
	return d.scanProjectSummaryFromRow(row)
}

// SaveProjectSummary persists a project summary (upsert).
func (d *DB) SaveProjectSummary(summary *projects.ProjectSummary) error {
	if summary == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	data, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("marshal project summary: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = d.db.ExecContext(context.Background(), `
		INSERT INTO projects(id, workspace, name, data, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			workspace  = excluded.workspace,
			name       = excluded.name,
			data       = excluded.data,
			updated_at = excluded.updated_at`,
		summary.ID, summary.Workspace, summary.Name, string(data), now, now)
	return err
}

// GetProject retrieves a full project by ID.
func (d *DB) GetProject(id string) (projects.Project, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var dataJSON string
	err := d.db.QueryRowContext(context.Background(),
		`SELECT data FROM projects WHERE id = ?`, id).Scan(&dataJSON)
	if err == sql.ErrNoRows {
		return projects.Project{}, fmt.Errorf("project not found: %s", id)
	}
	if err != nil {
		return projects.Project{}, err
	}

	var proj projects.Project
	if err := json.Unmarshal([]byte(dataJSON), &proj); err != nil {
		return projects.Project{}, fmt.Errorf("unmarshal project: %w", err)
	}
	return proj, nil
}

// CreateProject creates a new project and returns it.
func (d *DB) CreateProject(desc projects.ProjectDescription) (*projects.Project, error) {
	id := util.NewRandomUUID().String()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	proj := projects.Project{
		ID:           id,
		Name:         desc.Name,
		Workspace:    desc.Workspace,
		Repositories: desc.Repositories,
		ScanIDs:      []string{},
		ScanPolicy:   desc.ScanPolicy,
	}

	data, err := json.Marshal(proj)
	if err != nil {
		return nil, fmt.Errorf("marshal project: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err = d.db.ExecContext(context.Background(),
		`INSERT INTO projects(id, workspace, name, data, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, desc.Workspace, desc.Name, string(data), nowStr, nowStr)
	if err != nil {
		return nil, fmt.Errorf("insert project: %w", err)
	}

	// Ensure workspace name is recorded
	_, _ = d.db.ExecContext(context.Background(),
		`INSERT OR IGNORE INTO workspaces(name) VALUES (?)`, desc.Workspace)

	return &proj, nil
}

// UpdateProject updates an existing project's metadata and policy.
func (d *DB) UpdateProject(projectID string, desc projects.ProjectDescription,
	wsSummariser projects.WorkspaceSummariser) (*projects.Project, error) {

	proj, err := d.GetProject(projectID)
	if err != nil {
		// Project not found — create new
		return d.CreateProject(desc)
	}

	proj.Name = desc.Name
	proj.Workspace = desc.Workspace
	proj.Repositories = desc.Repositories
	proj.ScanPolicy = desc.ScanPolicy

	data, err := json.Marshal(proj)
	if err != nil {
		return nil, fmt.Errorf("marshal updated project: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err = d.db.ExecContext(context.Background(),
		`UPDATE projects SET workspace = ?, name = ?, data = ?, updated_at = ? WHERE id = ?`,
		proj.Workspace, proj.Name, string(data), time.Now().UTC().Format(time.RFC3339), projectID)
	if err != nil {
		return nil, fmt.Errorf("update project: %w", err)
	}

	return &proj, nil
}

// DeleteProject removes a project and all its scans (cascade).
func (d *DB) DeleteProject(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.ExecContext(context.Background(),
		`DELETE FROM projects WHERE id = ?`, id)
	return err
}

// GetScanConfig returns the scan policy for a specific scan.
func (d *DB) GetScanConfig(projectID, scanID string) (*projects.ScanPolicy, error) {
	proj, err := d.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	policy := proj.ScanPolicy
	return &policy, nil
}

// GetScanResults returns all findings for a specific scan.
func (d *DB) GetScanResults(projectID, scanID string) ([]*diagnostics.SecurityDiagnostic, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.QueryContext(context.Background(),
		`SELECT finding_id, rule_id, secret_type, severity, confidence,
		        repo_url, commit_sha, branch, file_path, line_number, column_number,
		        evidence_redacted, secret_checksum, source_context,
		        suppressed, exception_id, verification_status, ai_annotation, detected_at
		 FROM findings WHERE scan_id = ? ORDER BY severity, file_path, line_number`,
		scanID)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var results []*diagnostics.SecurityDiagnostic
	for rows.Next() {
		diag, err := d.scanFindingRow(rows)
		if err != nil {
			log.Printf("GetScanResults: scan row: %v", err)
			continue
		}
		results = append(results, diag)
	}
	return results, rows.Err()
}

// GetScanResultSummary returns the summary metadata for a scan.
func (d *DB) GetScanResultSummary(projectID, scanID string) (projects.ScanSummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var summary projects.ScanSummary
	var status, startedAt, completedAt string
	var fileCount, totalFindings int
	var findingsBySeverityJSON, additionalInfoJSON string
	var score float64

	err := d.db.QueryRowContext(context.Background(),
		`SELECT status, file_count, total_findings, findings_by_severity,
		        score, started_at, completed_at, additional_info
		 FROM scans WHERE id = ? AND project_id = ?`, scanID, projectID).
		Scan(&status, &fileCount, &totalFindings, &findingsBySeverityJSON,
			&score, &startedAt, &completedAt, &additionalInfoJSON)
	if err == sql.ErrNoRows {
		return projects.ScanSummary{}, fmt.Errorf("scan not found: %s/%s", projectID, scanID)
	}

	summary.Score.Metric = float32(score)
	return summary, err
}

// GetScanMetrics returns the metrics for a specific scan.
func (d *DB) GetScanMetrics(projectID, scanID string) (*store.ScanMetrics, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var fileCount, totalFindings int
	var findingsBySeverityJSON sql.NullString
	var score sql.NullFloat64

	err := d.db.QueryRowContext(context.Background(),
		`SELECT file_count, total_findings, findings_by_severity, score
		 FROM scans WHERE id = ? AND project_id = ?`, scanID, projectID).
		Scan(&fileCount, &totalFindings, &findingsBySeverityJSON, &score)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s/%s", projectID, scanID)
	}

	metrics := &store.ScanMetrics{
		TotalFindings:      totalFindings,
		Score:              score.Float64,
		FindingsBySeverity: make(map[string]int),
	}
	if findingsBySeverityJSON.Valid && findingsBySeverityJSON.String != "" && findingsBySeverityJSON.String != "{}" {
		_ = json.Unmarshal([]byte(findingsBySeverityJSON.String), &metrics.FindingsBySeverity)
	}
	return metrics, err
}

// DeleteProjectScans removes all historical scans for a project.
func (d *DB) DeleteProjectScans(projectID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.ExecContext(context.Background(),
		`DELETE FROM scans WHERE project_id = ?`, projectID)
	if err != nil {
		return err
	}

	// Remove scan IDs from project
	var dataStr string
	err = d.db.QueryRowContext(context.Background(), `SELECT data FROM projects WHERE id = ?`, projectID).Scan(&dataStr)
	if err == nil {
		var proj projects.ProjectSummary
		if json.Unmarshal([]byte(dataStr), &proj) == nil {
			proj.ScanIDs = nil
			proj.LastScanID = ""
			proj.LastScan = time.Time{}
			updatedData, _ := json.Marshal(proj)
			_, err = d.db.ExecContext(context.Background(),
				`UPDATE projects SET data = ?, updated_at = ? WHERE id = ?`,
				string(updatedData), time.Now().UTC().Format(time.RFC3339), projectID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GetIssues returns a filtered, paginated set of findings.
func (d *DB) GetIssues(paginated projects.PaginatedIssueSearch) (*projects.PagedResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT finding_id, rule_id, secret_type, severity, confidence,
		             repo_url, commit_sha, branch, file_path, line_number, column_number,
		             evidence_redacted, secret_checksum, source_context,
		             suppressed, exception_id, verification_status, ai_annotation, detected_at
		      FROM findings WHERE project_id = ?`
	args := []interface{}{paginated.ProjectID}

	query += ` ORDER BY severity, file_path, line_number LIMIT ? OFFSET ?`
	limit := paginated.PageSize
	if limit <= 0 {
		limit = 50
	}
	offset := paginated.Page * limit
	args = append(args, limit, offset)

	rows, err := d.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, fmt.Errorf("query issues: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var items []*diagnostics.SecurityDiagnostic
	for rows.Next() {
		diag, err := d.scanFindingRow(rows)
		if err != nil {
			continue
		}
		items = append(items, diag)
	}

	var total int
	_ = d.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE project_id = ?`, paginated.ProjectID).Scan(&total)

	return &projects.PagedResult{
		Diagnostics: items,
		Total:       total,
		Page:        paginated.Page,
	}, nil
}

// RemediateIssue creates an exception for a finding (marks it suppressed).
func (d *DB) RemediateIssue(exclude diagnostics.ExcludeRequirement) diagnostics.PolicyUpdateResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	id := util.NewRandomUUID().String()
	now := time.Now().UTC().Format(time.RFC3339)

	fingerprint := ""
	if exclude.Issue.SHA256 != nil {
		fingerprint = *exclude.Issue.SHA256
	}

	scopeJSON, _ := json.Marshal(map[string]interface{}{
		"type":           "globalHash",
		"secretChecksum": fingerprint,
	})

	_, err := d.db.ExecContext(context.Background(), `
		INSERT INTO exceptions(id, project_id, rule_id, scope_type, scope_json, reason, created_by, created_at, status)
		VALUES (?, ?, ?, 'globalHash', ?, 'false_positive_pattern', 'system', ?, 'active')`,
		id, exclude.ProjectID, exclude.What, string(scopeJSON), now)

	if err != nil {
		log.Printf("RemediateIssue: %v", err)
		return diagnostics.PolicyUpdateResult{Status: "error"}
	}

	// Mark all findings with this checksum as suppressed
	_, _ = d.db.ExecContext(context.Background(),
		`UPDATE findings SET suppressed = 1, exception_id = ? WHERE secret_checksum = ?`,
		id, fingerprint)

	return diagnostics.PolicyUpdateResult{Status: "success"}
}

// GetCodeContext returns surrounding code context for a finding location.
func (d *DB) GetCodeContext(cnt common.CodeContext) string {
	// TODO: implement file reading with context lines
	return ""
}

// GetProjectLocation returns the filesystem location of a project's data.
func (d *DB) GetProjectLocation(projID string) string {
	return filepath.Join(d.baseDir, "projects", projID)
}

// GetGitConfigManager returns the git service configuration manager.
func (d *DB) GetGitConfigManager() (gitutils.GitConfigManager, error) {
	return newGitConfigManager(d), nil
}

// BuildExclusionProvider constructs an ExclusionProvider for a project based on active exceptions.
func (d *DB) BuildExclusionProvider(projectID string) (diagnostics.ExclusionProvider, error) {
	allExceptions, err := d.ListExceptions(projectID)
	if err != nil {
		return nil, err
	}

	def := &diagnostics.ExcludeDefinition{
		GloballyExcludedRegExs:  []string{},
		GloballyExcludedStrings: []string{},
		GloballyExcludedHashes:  []string{},
		PathExclusionRegExs:     []string{},
		PerFileExcludedStrings:  make(map[string][]string),
		PerFileExcludedHashes:   make(map[string][]string),
		PathRegexExcludedRegExs: make(map[string][]string),
	}

	for _, exc := range allExceptions {
		if exc.Status != "active" {
			continue
		}
		if exc.Scope == nil {
			continue
		}

		scope := exc.Scope
		switch scope.Type {
		case "globalHash", "value": // "value" is legacy from my previous hardcoded scope
			if scope.SecretChecksum != "" {
				def.GloballyExcludedHashes = append(def.GloballyExcludedHashes, scope.SecretChecksum)
			}
		case "globalString":
			if scope.StringMatch != "" {
				def.GloballyExcludedStrings = append(def.GloballyExcludedStrings, scope.StringMatch)
			}
		case "globalRegex":
			if scope.RegexMatch != "" {
				def.GloballyExcludedRegExs = append(def.GloballyExcludedRegExs, scope.RegexMatch)
			}
		case "pathRegex":
			if scope.RegexMatch != "" {
				def.PathExclusionRegExs = append(def.PathExclusionRegExs, scope.RegexMatch)
			}
		case "pathString":
			if scope.Path != "" && scope.StringMatch != "" {
				def.PerFileExcludedStrings[scope.Path] = append(def.PerFileExcludedStrings[scope.Path], scope.StringMatch)
			}
		case "pathHash":
			if scope.Path != "" && scope.SecretChecksum != "" {
				def.PerFileExcludedHashes[scope.Path] = append(def.PerFileExcludedHashes[scope.Path], scope.SecretChecksum)
			}
		case "pathRegexRegex":
			if scope.Path != "" && scope.RegexMatch != "" {
				def.PathRegexExcludedRegExs[scope.Path] = append(def.PathRegexExcludedRegExs[scope.Path], scope.RegexMatch)
			}
		}
	}

	container := diagnostics.ExcludeContainer{
		ExcludeDef: def,
	}
	return diagnostics.CompileExcludes(container)
}

// matchException evaluates a finding against a list of active exceptions.
func matchException(finding *diagnostics.SecurityDiagnostic, exceptions []*store.Exception) (bool, string) {
	if finding == nil {
		return false, ""
	}

	ruleName := finding.Justification.Headline.Description

	for _, exc := range exceptions {
		if exc.RuleID != "*" && exc.RuleID != ruleName {
			continue
		}

		if exc.Scope == nil {
			continue
		}

		switch exc.Scope.Type {
		case "global", "project":
			return true, exc.ID
		case "directory":
			if finding.Location != nil && strings.HasPrefix(*finding.Location, exc.Scope.Path) {
				return true, exc.ID
			}
		case "file":
			if finding.Location != nil && *finding.Location == exc.Scope.Path {
				return true, exc.ID
			}
		case "line":
			if finding.Location != nil && *finding.Location == exc.Scope.Path {
				line := int(finding.Range.Start.Line + 1)
				if exc.Scope.LineStart != nil && exc.Scope.LineEnd != nil && line >= *exc.Scope.LineStart && line <= *exc.Scope.LineEnd {
					return true, exc.ID
				}
			}
		case "value":
			if finding.SHA256 != nil && *finding.SHA256 == exc.Scope.SecretChecksum {
				return true, exc.ID
			}
		}
	}
	return false, ""
}

// RunScan executes a full scan for a project, persisting findings and summary.
func (d *DB) RunScan(
	ctx context.Context,
	projectID string,
	scanPolicy projects.ScanPolicy,
	scanner projects.SecurityScanner,
	scanIDCallback func(string),
	repoStatusChecker projects.RepositoryStatusChecker,
	progressMonitor func(diagnostics.Progress),
	summariser projects.ScanSummariser,
	wsSummariser projects.WorkspaceSummariser,
	consumers ...diagnostics.SecurityDiagnosticsConsumer,
) {
	scanID := util.NewRandomUUID().String()
	now := time.Now().UTC().Format(time.RFC3339)

	// Create scan record
	d.mu.Lock()
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO scans(id, project_id, status, started_at, created_at)
		VALUES (?, ?, 'running', ?, ?)`,
		scanID, projectID, now, now)
	d.mu.Unlock()
	if err != nil {
		log.Printf("RunScan: create scan record: %v", err)
		return
	}

	// Notify caller of the scan ID (used for WebSocket/SSE stream registration)
	if scanIDCallback != nil {
		scanIDCallback(scanID)
	}

	proj, err := d.GetProject(projectID)
	if err != nil {
		log.Printf("RunScan: get project: %v", err)
		d.markScanFailed(ctx, scanID)
		return
	}

	// Check/update repository status
	for i, repo := range proj.Repositories {
		if repoStatusChecker != nil {
			updated, err := repoStatusChecker(ctx, d, &repo)
			if err == nil && updated != nil {
				proj.Repositories[i] = *updated
			}
		}
	}

	// Build target paths
	var targets []string
	for _, repo := range proj.Repositories {
		targets = append(targets, repo.GetCodeLocation(d, projectID))
	}

	// Run the scan — scanner emits findings via its channel
	secOptions := secrets.SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        diagnostics.MakeEmptyExcludes(),
	}

	if opts, ok := scanPolicy.Config["secret-search-options"]; ok {
		if scanOpts, good := opts.(secrets.SecretSearchOptions); good {
			secOptions = scanOpts
		}
	}

	// ALWAYS apply the database exclusion provider so it overrides or supplements native exclusions
	if exProvider, err := d.BuildExclusionProvider(projectID); err == nil && exProvider != nil {
		secOptions.Exclusions = exProvider
	}

	findingsCh, pathsCh := secrets.SearchSecretsOnPaths(targets, secOptions)

	startTime := time.Now()
	var allFindings []*diagnostics.SecurityDiagnostic

	// Fetch active exceptions
	allExceptions, _ := d.ListExceptions(projectID)
	var activeExceptions []*store.Exception
	nowT := time.Now()
	for _, exc := range allExceptions {
		if exc.Status != "active" {
			continue
		}
		if exc.ExpiresAt != nil && exc.ExpiresAt.Before(nowT) {
			continue
		}
		activeExceptions = append(activeExceptions, exc)
	}

	for finding := range findingsCh {
		allFindings = append(allFindings, finding)

		suppressed, excID := matchException(finding, activeExceptions)
		if suppressed {
			finding.Excluded = true
		}

		// Persist finding
		go d.persistFinding(ctx, finding, scanID, projectID, suppressed, excID)

		// Notify consumers (e.g. WebSocket broadcaster)
		for _, c := range consumers {
			c.ReceiveDiagnostic(finding)
		}

		// Notify SSE clients
		d.broker.Publish(store.ScanEvent{
			ScanID: scanID,
			Type:   store.EventFinding,
			Data:   finding,
		})
	}

	files := <-pathsCh

	// Build summary
	scanSummary := summariser(projectID, scanID, allFindings)
	if scanSummary == nil {
		_ = scanSummary
	}

	// Aggregate findings by severity
	severityCounts := make(map[string]int)
	for _, f := range allFindings {
		sev := f.Justification.Headline.Confidence.String()
		severityCounts[sev]++
	}
	severityJSON, _ := json.Marshal(severityCounts)

	// Compute a simple score: higher is worse (0-10 scale)
	var scanScore float64
	if len(allFindings) > 0 {
		critical := severityCounts["Critical"] + severityCounts["CRITICAL"]
		high := severityCounts["High"] + severityCounts["HIGH"]
		medium := severityCounts["Medium"] + severityCounts["MEDIUM"]
		low := severityCounts["Low"] + severityCounts["LOW"]
		scanScore = float64(critical*10+high*5+medium*2+low) / float64(len(allFindings))
		if scanScore > 10 {
			scanScore = 10
		}
	}

	// Update scan record with completion
	durationMs := time.Since(startTime).Milliseconds()
	d.mu.Lock()
	_, _ = d.db.ExecContext(ctx, `
		UPDATE scans SET
			status = 'complete',
			file_count = ?,
			total_findings = ?,
			findings_by_severity = ?,
			score = ?,
			duration_ms = ?,
			completed_at = ?
		WHERE id = ?`,
		len(files), len(allFindings), string(severityJSON), scanScore, durationMs,
		time.Now().UTC().Format(time.RFC3339), scanID)
	d.mu.Unlock()

	// Update project with last scan ID
	proj.ScanIDs = append(proj.ScanIDs, scanID)
	proj.LastScanID = scanID
	proj.LastScan = time.Now().UTC()
	data, _ := json.Marshal(proj)
	d.mu.Lock()
	_, _ = d.db.ExecContext(ctx,
		`UPDATE projects SET data = ?, updated_at = ? WHERE id = ?`,
		string(data), time.Now().UTC().Format(time.RFC3339), projectID)
	d.mu.Unlock()

	d.broker.Publish(store.ScanEvent{
		ScanID: scanID,
		Type:   store.EventComplete,
		Data:   map[string]interface{}{"status": "complete"},
	})

	if d.webhookDispatcher != nil {
		go d.webhookDispatcher("scan.completed", map[string]interface{}{
			"projectId":     projectID,
			"scanId":        scanID,
			"status":        "complete",
			"totalFindings": len(allFindings),
			"duration":      durationMs,
		})
	}
}

func (d *DB) markScanFailed(ctx context.Context, scanID string) {
	d.mu.Lock()
	_, _ = d.db.ExecContext(ctx,
		`UPDATE scans SET status = 'failed', completed_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), scanID)
	d.mu.Unlock()

	d.broker.Publish(store.ScanEvent{
		ScanID: scanID,
		Type:   store.EventComplete,
		Data:   map[string]interface{}{"status": "failed"},
	})

	if d.webhookDispatcher != nil {
		go d.webhookDispatcher("scan.completed", map[string]interface{}{
			"scanId": scanID,
			"status": "failed",
		})
	}
}

func (d *DB) persistFinding(ctx context.Context, finding *diagnostics.SecurityDiagnostic, scanID, projectID string, suppressed bool, exceptionID string) {
	if finding == nil {
		return
	}

	checksum := ""
	if finding.SHA256 != nil {
		checksum = *finding.SHA256
	}

	location := ""
	if finding.Location != nil {
		location = *finding.Location
	}

	ruleName := finding.Justification.Headline.Description

	line := finding.Range.Start.Line + 1
	col := finding.Range.Start.Character + 1

	// Build deterministic finding ID
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s:%s:%s:%d:%d:%s", ruleName, "", location, line, col, checksum)
	findingID := fmt.Sprintf("%x", hash.Sum(nil))

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)

	// Since checkmate-core SecurityDiagnostic lacks standard fields like branch/commit,
	// we map what we can for the relational columns and store the rest as JSON (if needed).
	// In the future, findings might include an evidence redacted string.
	evidenceRedacted := ""
	source := ""
	if finding.Source != nil {
		source = *finding.Source
	}

	suppressedInt := 0
	if suppressed {
		suppressedInt = 1
	}
	var excID interface{} = nil
	if exceptionID != "" {
		excID = exceptionID
	}

	var prevAIAnnotation, prevVerificationStatus sql.NullString
	_ = d.db.QueryRowContext(ctx, `
		SELECT ai_annotation, verification_status
		FROM findings
		WHERE project_id = ? AND finding_id = ? AND (ai_annotation IS NOT NULL OR (verification_status IS NOT NULL AND verification_status != 'NOT_CHECKED'))
		ORDER BY rowid DESC LIMIT 1
	`, projectID, findingID).Scan(&prevAIAnnotation, &prevVerificationStatus)

	initialVerifStatus := "NOT_CHECKED"
	if prevVerificationStatus.Valid && prevVerificationStatus.String != "" {
		initialVerifStatus = prevVerificationStatus.String
	}

	var aiAnnotationVal interface{} = nil
	if prevAIAnnotation.Valid && prevAIAnnotation.String != "" {
		aiAnnotationVal = prevAIAnnotation.String
	}

	_, err := d.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO findings(
			finding_id, scan_id, project_id,
			rule_id, secret_type, severity, confidence,
			repo_url, commit_sha, branch, file_path, line_number, column_number,
			evidence_redacted, secret_checksum, source_context,
			suppressed, exception_id, verification_status, ai_annotation, detected_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		findingID, scanID, projectID,
		ruleName, "generic.high_entropy", finding.Justification.Headline.Confidence.String(), finding.Justification.Headline.Confidence.String(),
		"", "", "", location, line,
		col,
		evidenceRedacted, checksum, source,
		suppressedInt, excID, initialVerifStatus, aiAnnotationVal, now,
	)
	if err != nil {
		log.Printf("persistFinding: %v", err)
	}

	if !suppressed && d.webhookDispatcher != nil {
		go d.webhookDispatcher("finding.detected", map[string]interface{}{
			"findingId":  findingID,
			"secretType": "generic.high_entropy",
			"severity":   finding.Justification.Headline.Confidence.String(),
			"file":       location,
			"line":       line,
		})
	}
}

// ─── Row scanners ─────────────────────────────────────────────────────────────

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (d *DB) scanProjectSummaryFromRow(row rowScanner) (*projects.ProjectSummary, error) {
	var id, workspace, name, dataJSON, createdAt, updatedAt string
	if err := row.Scan(&id, &workspace, &name, &dataJSON, &createdAt, &updatedAt); err != nil {
		return nil, err
	}

	var ps projects.ProjectSummary
	if err := json.Unmarshal([]byte(dataJSON), &ps); err != nil {
		// Fallback to minimal summary if JSON is partial
		ps = projects.ProjectSummary{
			ID:        id,
			Name:      name,
			Workspace: workspace,
		}
	}
	ps.ID = id
	ps.Name = name
	ps.Workspace = workspace

	if ps.LastScanID == "" && len(ps.ScanIDs) > 0 {
		ps.LastScanID = ps.ScanIDs[len(ps.ScanIDs)-1]
	}

	return &ps, nil
}

func (d *DB) scanFindingRow(row rowScanner) (*diagnostics.SecurityDiagnostic, error) {
	var (
		findingID, ruleID, secretType, severity, confidence string
		repoURL, commitSha, branch                          sql.NullString
		filePath                                            string
		lineNumber, columnNumber                            int
		evidenceRedacted, secretChecksum                    sql.NullString
		sourceContext                                       sql.NullString
		suppressed                                          int
		exceptionID                                         sql.NullString
		verificationStatus, aiAnnotationJSON                sql.NullString
		detectedAt                                          string
	)

	if err := row.Scan(
		&findingID, &ruleID, &secretType, &severity, &confidence,
		&repoURL, &commitSha, &branch, &filePath, &lineNumber, &columnNumber,
		&evidenceRedacted, &secretChecksum, &sourceContext,
		&suppressed, &exceptionID, &verificationStatus, &aiAnnotationJSON,
		&detectedAt,
	); err != nil {
		return nil, err
	}

	diag := &diagnostics.SecurityDiagnostic{
		ID: findingID,
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: ruleID,
				Confidence:  parseConfidence(confidence),
			},
		},
		Location: &filePath,
		SHA256:   &secretChecksum.String,
		Source:   &sourceContext.String,
	}
	if lineNumber > 0 {
		diag.Range.Start.Line = int64(lineNumber - 1)
	} else {
		diag.Range.Start.Line = int64(lineNumber)
	}
	if columnNumber > 0 {
		diag.Range.Start.Character = int64(columnNumber - 1)
	} else {
		diag.Range.Start.Character = int64(columnNumber)
	}

	if aiAnnotationJSON.Valid && aiAnnotationJSON.String != "" {
		var ann interface{}
		if err := json.Unmarshal([]byte(aiAnnotationJSON.String), &ann); err == nil {
			diag.AIAnnotation = ann
		}
	}

	return diag, nil
}

func parseConfidence(c string) diagnostics.Confidence {
	switch strings.ToLower(c) {
	case "critical":
		return diagnostics.Critical
	case "high":
		return diagnostics.High
	case "medium":
		return diagnostics.Medium
	case "low":
		return diagnostics.Low
	case "info":
		return diagnostics.Info
	default:
		return diagnostics.High
	}
}

// ─── PlatformStore Implementation ─────────────────────────────────────────────

func (d *DB) Ping() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.db.Ping()
}

func (d *DB) ListProjectScans(projectID string, limit, offset int) ([]*store.ScanRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, project_id, status, started_at, completed_at
		FROM scans
		WHERE project_id = ?
		ORDER BY started_at DESC
		LIMIT ? OFFSET ?
	`, projectID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var scans []*store.ScanRecord
	for rows.Next() {
		var id, projID, status string
		var startedAt, completedAt sql.NullString
		if err := rows.Scan(&id, &projID, &status, &startedAt, &completedAt); err != nil {
			return nil, err
		}

		record := &store.ScanRecord{
			ID:        id,
			ProjectID: projID,
			Status:    status,
		}

		if startedAt.Valid && startedAt.String != "" {
			sTime, _ := time.Parse(time.RFC3339, startedAt.String)
			record.StartedAt = sTime
		}

		if completedAt.Valid && completedAt.String != "" {
			cTime, _ := time.Parse(time.RFC3339, completedAt.String)
			record.CompletedAt = &cTime
		}

		scans = append(scans, record)
	}
	return scans, nil
}

func (d *DB) SearchFindings(req store.FindingSearchRequest) (*store.FindingSearchResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	where := []string{"1=1"}
	args := []interface{}{}

	if len(req.ProjectIDs) > 0 {
		placeholders := make([]string, len(req.ProjectIDs))
		for i, id := range req.ProjectIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		where = append(where, fmt.Sprintf("project_id IN (%s)", strings.Join(placeholders, ",")))
	}

	// For severity and secretType, we would match them against rule_id/confidence/severity
	// stored in the finding. Currently rule_id is stored in findings table.
	// We'll implement basic filtering here. For a full implementation, we need to map SDK
	// SecretType back to rule_ids or store secret_type directly in the findings table.
	// Assuming finding schema supports this or we do basic LIKE queries for now.

	// Ensure limit/offset
	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	page := req.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	query := fmt.Sprintf("SELECT id, scan_id, project_id, finding_id, rule_id, confidence, location, line_number, column_number, secret_checksum, source_context FROM findings WHERE %s LIMIT ? OFFSET ?", strings.Join(where, " AND "))
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var findings []*diagnostics.SecurityDiagnostic
	for rows.Next() {
		diag, err := d.scanFindingRow(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, diag)
	}

	// We would normally do a COUNT(*) with the same WHERE clause to get TotalCount.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings WHERE %s", strings.Join(where, " AND "))
	var total int
	_ = d.db.QueryRow(countQuery, args[:len(args)-2]...).Scan(&total)

	return &store.FindingSearchResult{
		Findings:   findings,
		TotalCount: total,
		Page:       page,
		Limit:      limit,
	}, nil
}
