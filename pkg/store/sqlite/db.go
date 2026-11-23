package sqlite

import (
	"context"
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

// GetCodeContext returns file content or surrounding code context for a finding
// location, resolving retained remote checkouts when available and falling back
// to stored source_context if the file is no longer on disk.
func (d *DB) GetCodeContext(cnt common.CodeContext) string {
	loc := strings.TrimSpace(cnt.Location)
	if loc == "" {
		return ""
	}

	resolvedPath := loc
	if cnt.ScanID != "" {
		if retained, err := d.GetScanRetainedCheckouts(cnt.ScanID); err == nil && len(retained) > 0 {
			if mapped := ResolveRetainedFilePath(loc, retained); mapped != "" {
				resolvedPath = mapped
			}
		}
	}

	if info, err := os.Stat(resolvedPath); err == nil && !info.IsDir() {
		// Cap direct reads at 1 MiB to keep memory bounded.
		const maxBytes = 1 << 20
		f, err := os.Open(resolvedPath)
		if err == nil {
			defer func() { _ = f.Close() }()
			buf := make([]byte, maxBytes)
			n, _ := f.Read(buf)
			return string(buf[:n])
		}
	}

	// Fallback to persisted source_context for this file/scan.
	d.mu.RLock()
	defer d.mu.RUnlock()
	var src sql.NullString
	if cnt.ScanID != "" {
		_ = d.db.QueryRowContext(context.Background(),
			`SELECT source_context FROM findings WHERE scan_id = ? AND file_path = ? AND source_context != '' LIMIT 1`,
			cnt.ScanID, loc).Scan(&src)
	} else if cnt.ProjectID != "" {
		_ = d.db.QueryRowContext(context.Background(),
			`SELECT source_context FROM findings WHERE project_id = ? AND file_path = ? AND source_context != '' LIMIT 1`,
			cnt.ProjectID, loc).Scan(&src)
	}
	if src.Valid {
		return src.String
	}
	return ""
}

// ResolveRetainedFilePath maps a finding's transposed remote repository URL
// file path (e.g. "https://host/org/repo.git/pkg/a.go") back to the on-disk
// file under a retained checkout directory, rejecting any path traversal.
func ResolveRetainedFilePath(filePath string, retained map[string]string) string {
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
	return d.buildExclusionProviderWithExtra(projectID, nil)
}

func (d *DB) buildExclusionProviderWithExtra(projectID string, extra *diagnostics.ExcludeDefinition) (diagnostics.ExclusionProvider, error) {
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

	if extra != nil {
		merged := secrets.MergeExclusions(*extra, *def)
		def = &merged
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

// scanTargets returns what the scanner should be pointed at for each
// repository in a project.
//
// A git repository is named by its URL, not by the path GetCodeLocation would
// derive for it. Nothing in the SQLite scan path clones before scanning, so
// that derived path is a directory which does not exist; walking it reads no
// files, and the scan therefore reported zero findings for every repository
// added by URL while looking exactly like a successful scan of a clean
// repository. The scanner's own acquisition clones a URL it is handed, into
// SecretSearchOptions.CloneBaseDir.
func scanTargets(repositories []projects.Repository) []string {
	targets := make([]string, 0, len(repositories))
	for _, repo := range repositories {
		targets = append(targets, repo.Location)
	}
	return targets
}

// RunScan executes a full scan for a project, persisting findings and summary.
//
// Two parameters are accepted and deliberately unused, both required by the
// projects.ProjectManager interface that simpleProjectManager also implements.
// They are named here rather than left to be discovered, because an accepted-
// but-unused parameter is exactly the defect that hid the missing progress
// reporting fixed in change 005: the caller supplies something, the compiler is
// satisfied, and nothing happens.
//
//   - scanner: this implementation calls secrets.SearchSecretsOnPathsWithProgress
//     directly rather than driving scanner.Scan, so the argument is inert. Any
//     caller passing a custom scanner gets the built-in secrets finder instead.
//
//   - wsSummariser: simpleProjectManager invokes this after a scan to refresh
//     workspace summaries (see core/projects/management.go). This implementation
//     does not, so workspace summaries are never recomputed after a SQLite scan.
//     That is a real behavioural difference, not merely dead weight; it is
//     recorded as a follow-up in change 005 rather than fixed here, because
//     changing it alters output rather than restoring absent reporting.
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

	// Build target paths. Callers (such as git-diff scoped agent scans) may
	// supply an explicit target-override slice while still running under the
	// project's exceptions and triage history.
	targets := scanTargets(proj.Repositories)
	if override, ok := scanPolicy.Config["target-override"]; ok {
		if list, good := override.([]string); good && len(list) > 0 {
			targets = list
		}
	}

	// Run the scan. Note this calls the secrets finder directly; the `scanner`
	// parameter is not used. See the doc comment on RunScan.
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

	// ALWAYS apply the database exclusion provider so it overrides or supplements native exclusions.
	// If the caller also supplied an extra ExcludeDefinition (e.g. a .checkmate.yaml file), merge them.
	if extraDef, ok := scanPolicy.Config["extra-exclusions"].(*diagnostics.ExcludeDefinition); ok && extraDef != nil {
		if mergedProvider, err := d.buildExclusionProviderWithExtra(projectID, extraDef); err == nil && mergedProvider != nil {
			secOptions.Exclusions = mergedProvider
		}
	} else if exProvider, err := d.BuildExclusionProvider(projectID); err == nil && exProvider != nil {
		secOptions.Exclusions = exProvider
	}

	// Clones land in the store's managed code directory, under the project
	// (or under project/scanID when KeepCheckouts is enabled so each retained
	// scan checkout is cleanly isolated for inspection and cleanup).
	if secOptions.CloneBaseDir == "" {
		if secOptions.KeepCheckouts {
			secOptions.CloneBaseDir = filepath.Join(d.GetCodeBaseDir(), projectID, scanID)
		} else {
			secOptions.CloneBaseDir = filepath.Join(d.GetCodeBaseDir(), projectID)
		}
	}

	// Resolve Git credentials through the store's git_config table (matching
	// explicit GitServiceID and repository hostname) plus env / ssh-agent fallback.
	if secOptions.AuthResolver == nil {
		repoServiceIDs := make(map[string]string, len(proj.Repositories))
		for _, repo := range proj.Repositories {
			if repo.GitServiceID != "" {
				repoServiceIDs[repo.Location] = repo.GitServiceID
				repoServiceIDs[gitutils.SanitiseRepoURL(repo.Location)] = repo.GitServiceID
			}
		}
		secOptions.AuthResolver = &gitutils.ChainedAuthResolver{
			ConfigManager:  newGitConfigManager(d),
			RepoServiceIDs: repoServiceIDs,
		}
	}

	//Progress is reported through the same coalescing reporter the scanner
	//path uses. A nil monitor is tolerated so callers that do not want
	//progress need not supply one.
	monitor := progressMonitor
	if monitor == nil {
		monitor = func(diagnostics.Progress) {}
	}

	monitor(diagnostics.Progress{
		ProjectID:   projectID,
		ScanID:      scanID,
		Position:    0,
		Total:       1,
		CurrentFile: "starting scan ...",
	})

	findingsCh, pathsCh, reportCh := secrets.SearchSecretsOnPathsWithReport(
		ctx, targets, secOptions, projectID, scanID, monitor)

	startTime := time.Now()
	var allFindings []*diagnostics.SecurityDiagnostic

	// Suppressions created while this scan is running should apply to it, not
	// only to the next one. The engine-side exclusion provider above was
	// compiled before the workers started and cannot be changed underneath
	// them, so the store-side matcher is refreshed periodically instead: a
	// false positive suppressed at file 40,000 then covers files 40,001
	// onwards. Findings already recorded are reconciled after the loop, so the
	// scan ends under one policy rather than a mixture — see below.
	//
	// Refreshing on a timer rather than per finding keeps this off the hot
	// path; ListExceptions takes the store lock, and a scan can emit findings
	// far faster than an operator can click.
	matcher := newExceptionMatcher(d.listExceptionsQuietly(projectID))
	const exceptionRefreshInterval = 2 * time.Second
	lastExceptionRefresh := time.Now()

	// Findings are persisted by a single batching writer rather than a
	// goroutine per finding. See findingWriter for why: the previous approach
	// queued thousands of goroutines on the store's exclusive lock, which
	// starved interactive writes — suppressing a finding mid-scan appeared to
	// hang until the scan finished.
	writer := d.newFindingWriter(ctx, scanID, projectID)

	for finding := range findingsCh {
		allFindings = append(allFindings, finding)

		if time.Since(lastExceptionRefresh) >= exceptionRefreshInterval {
			matcher = newExceptionMatcher(d.listExceptionsQuietly(projectID))
			lastExceptionRefresh = time.Now()
		}

		suppressed, excID := matcher.match(finding)
		if suppressed {
			finding.Excluded = true
		}

		writer.add(finding, suppressed, excID)

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

	// Blocks until every finding is durable. Everything below — the summary,
	// the severity counts, marking the scan complete — describes a scan whose
	// findings are in the database, which was not previously guaranteed.
	writer.close()

	// A suppression created part-way through the scan has so far only affected
	// the findings that arrived after it. Apply it to the ones that arrived
	// before, so the completed scan reflects a single, final policy rather than
	// a record of when the operator happened to click. Without this, two
	// identical secrets in the same scan can end up with different verdicts,
	// and the summary, severity counts and score below would be computed from
	// that mixed set.
	//
	// Done once, after the writer has drained, so it cannot race the inserts it
	// is amending.
	d.reconcileSuppressions(ctx, scanID, projectID, allFindings)

	files := <-pathsCh
	acqReport := <-reportCh

	// Persist acquisition metadata (and any retained checkout paths) into
	// scans.additional_info regardless of whether the scan succeeds or fails.
	d.persistAcquisitionMetadata(ctx, scanID, acqReport)

	// Total acquisition failure: never present a scan that could not clone any
	// target as a clean 0-finding result.
	if acqReport.Succeeded == 0 && acqReport.Failed > 0 {
		d.markScanFailedWithAcquisition(ctx, scanID, acqReport)
		return
	}

	// Findings arrive in file-completion order, which is nondeterministic now
	// that files are scanned in parallel. Everything derived from the slice
	// below — the summary, the severity counts, the report — is order-
	// sensitive to some degree, so pin the order before any of it is computed
	// or stored.
	diagnostics.SortDiagnosticsCanonically(allFindings)

	// Build summary
	if summariser != nil {
		scanSummary := summariser(projectID, scanID, allFindings)
		if scanSummary == nil {
			_ = scanSummary
		}
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

	_, _ = d.RecomputeScanSummary(scanID)

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
	d.markScanFailedWithAcquisition(ctx, scanID, gitutils.AcquisitionReport{})
}

func (d *DB) markScanFailedWithAcquisition(ctx context.Context, scanID string, acq gitutils.AcquisitionReport) {
	d.mu.Lock()
	_, _ = d.db.ExecContext(ctx,
		`UPDATE scans SET status = 'failed', completed_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), scanID)
	d.mu.Unlock()

	eventData := map[string]interface{}{"status": "failed"}
	if acq.Failed > 0 {
		eventData["acquisition"] = acq
		if len(acq.Failures) > 0 {
			eventData["error"] = fmt.Sprintf("acquisition failed for %s (%s): %s",
				acq.Failures[0].Target, acq.Failures[0].ErrorKind, acq.Failures[0].Message)
		}
	}

	d.broker.Publish(store.ScanEvent{
		ScanID: scanID,
		Type:   store.EventComplete,
		Data:   eventData,
	})

	if d.webhookDispatcher != nil {
		go d.webhookDispatcher("scan.completed", map[string]interface{}{
			"scanId": scanID,
			"status": "failed",
		})
	}
}

func (d *DB) persistAcquisitionMetadata(ctx context.Context, scanID string, acq gitutils.AcquisitionReport) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var raw sql.NullString
	_ = d.db.QueryRowContext(ctx, `SELECT additional_info FROM scans WHERE id = ?`, scanID).Scan(&raw)

	info := make(map[string]interface{})
	if raw.Valid && raw.String != "" && raw.String != "{}" {
		_ = json.Unmarshal([]byte(raw.String), &info)
	}
	info["acquisition"] = acq
	if len(acq.RetainedPaths) > 0 {
		info["retainedCheckouts"] = acq.RetainedPaths
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		return
	}
	_, _ = d.db.ExecContext(ctx, `UPDATE scans SET additional_info = ? WHERE id = ?`, string(encoded), scanID)
}

// GetScanAcquisitionReport returns the persisted AcquisitionReport for scanID.
func (d *DB) GetScanAcquisitionReport(scanID string) (*gitutils.AcquisitionReport, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var raw sql.NullString
	err := d.db.QueryRowContext(context.Background(),
		`SELECT additional_info FROM scans WHERE id = ?`, scanID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return nil, err
	}
	if !raw.Valid || raw.String == "" || raw.String == "{}" {
		return nil, nil
	}
	var wrapper struct {
		Acquisition *gitutils.AcquisitionReport `json:"acquisition"`
	}
	if err := json.Unmarshal([]byte(raw.String), &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Acquisition, nil
}

// GetScanRetainedCheckouts returns the map of sanitisedRepoURL -> localDir
// retained on disk for scanID, if any.
func (d *DB) GetScanRetainedCheckouts(scanID string) (map[string]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var raw sql.NullString
	err := d.db.QueryRowContext(context.Background(),
		`SELECT additional_info FROM scans WHERE id = ?`, scanID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return nil, err
	}
	if !raw.Valid || raw.String == "" || raw.String == "{}" {
		return nil, nil
	}
	var wrapper struct {
		RetainedCheckouts map[string]string `json:"retainedCheckouts"`
	}
	if err := json.Unmarshal([]byte(raw.String), &wrapper); err != nil {
		return nil, err
	}
	return wrapper.RetainedCheckouts, nil
}

// ClearScanRetainedCheckouts removes retainedCheckouts metadata from
// scans.additional_info once retained checkouts have been deleted from disk.
func (d *DB) ClearScanRetainedCheckouts(scanID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var raw sql.NullString
	err := d.db.QueryRowContext(context.Background(),
		`SELECT additional_info FROM scans WHERE id = ?`, scanID).Scan(&raw)
	if err == sql.ErrNoRows {
		return fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return err
	}
	info := make(map[string]interface{})
	if raw.Valid && raw.String != "" && raw.String != "{}" {
		_ = json.Unmarshal([]byte(raw.String), &info)
	}
	delete(info, "retainedCheckouts")
	if acqMap, ok := info["acquisition"].(map[string]interface{}); ok {
		delete(acqMap, "retainedPaths")
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		return err
	}
	_, err = d.db.ExecContext(context.Background(),
		`UPDATE scans SET additional_info = ? WHERE id = ?`, string(encoded), scanID)
	return err
}

// GetScanRecord returns status and timestamp metadata for a single scan.
func (d *DB) GetScanRecord(scanID string) (*store.ScanRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var id, projID, status string
	var startedAt, completedAt sql.NullString
	err := d.db.QueryRowContext(context.Background(),
		`SELECT id, project_id, status, started_at, completed_at FROM scans WHERE id = ?`,
		scanID).Scan(&id, &projID, &status, &startedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return nil, err
	}
	record := &store.ScanRecord{
		ID:        id,
		ProjectID: projID,
		Status:    status,
	}
	if startedAt.Valid && startedAt.String != "" {
		record.StartedAt, _ = time.Parse(time.RFC3339, startedAt.String)
	}
	if completedAt.Valid && completedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		record.CompletedAt = &t
	}
	return record, nil
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

	// The suppressed column was scanned but never mapped, so every finding
	// read back from the store reported itself as not suppressed regardless of
	// what was recorded. Suppression survived the write and was lost on the
	// read, which makes a suppression look as though it did nothing.
	diag.Excluded = suppressed == 1

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

	// The column list must match scanFindingRow's Scan, and the table. This
	// previously selected "id" and "location", neither of which exists in the
	// findings schema, and eleven columns where the scanner reads nineteen —
	// so every call failed with "no such column: id". Nothing exercised it.
	query := fmt.Sprintf(`SELECT finding_id, rule_id, secret_type, severity, confidence,
	        repo_url, commit_sha, branch, file_path, line_number, column_number,
	        evidence_redacted, secret_checksum, source_context,
	        suppressed, exception_id, verification_status, ai_annotation, detected_at
	 FROM findings WHERE %s ORDER BY file_path, line_number LIMIT ? OFFSET ?`,
		strings.Join(where, " AND "))
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
