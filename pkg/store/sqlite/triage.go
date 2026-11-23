package sqlite

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
)

func computeContextHash(sourceContext string) string {
	trimmed := strings.TrimSpace(sourceContext)
	if trimmed == "" {
		return ""
	}
	// Normalise line endings so CRLF/LF differences do not cause spurious drift.
	norm := strings.ReplaceAll(trimmed, "\r\n", "\n")
	sum := sha256.Sum256([]byte(norm))
	return fmt.Sprintf("%x", sum)
}

func classifyRuleSecretType(ruleName string) string {
	name := strings.ToUpper(ruleName)
	switch {
	case strings.Contains(name, "AWS_ACCESS") || strings.Contains(name, "AWS ACCESS"):
		return string(sdk.SecretTypeAWSAccessKey)
	case strings.Contains(name, "AWS_SECRET") || strings.Contains(name, "AWS SECRET"):
		return string(sdk.SecretTypeAWSSecretKey)
	case strings.Contains(name, "GITHUB"):
		return string(sdk.SecretTypeGitHubPAT)
	case strings.Contains(name, "GITLAB"):
		return string(sdk.SecretTypeGitLabPAT)
	case strings.Contains(name, "RSA"):
		return string(sdk.SecretTypeRSAPrivateKey)
	case strings.Contains(name, "PRIVATE KEY") || strings.Contains(name, "PRIVATE_KEY") || strings.Contains(name, "PEM"):
		return string(sdk.SecretTypePEMPrivateKey)
	case strings.Contains(name, "SSH"):
		return string(sdk.SecretTypeSSHPrivateKey)
	case strings.Contains(name, "PASSWORD") || strings.Contains(name, "PASSWD"):
		return string(sdk.SecretTypePassword)
	case strings.Contains(name, "JWT"):
		return string(sdk.SecretTypeJWT)
	case strings.Contains(name, "API_KEY") || strings.Contains(name, "API KEY") || strings.Contains(name, "APIKEY"):
		return string(sdk.SecretTypeAPIKey)
	case strings.Contains(name, "TOKEN"):
		return string(sdk.SecretTypeToken)
	default:
		return string(sdk.SecretTypeHighEntropy)
	}
}

// GetScanProjectID returns the project_id associated with a scan.
func (d *DB) GetScanProjectID(scanID string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var projectID sql.NullString
	err := d.db.QueryRow(`SELECT project_id FROM scans WHERE id = ?`, scanID).Scan(&projectID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("scan not found: %s", scanID)
		}
		return "", err
	}
	return projectID.String, nil
}

// GetScanFileCount returns the number of files scanned for scanID.
func (d *DB) GetScanFileCount(scanID string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow(`SELECT file_count FROM scans WHERE id = ?`, scanID).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("scan not found: %s", scanID)
		}
		return 0, err
	}
	return count, nil
}

// GetScanFindings returns all stored findings for a scan in canonical order.
func (d *DB) GetScanFindings(scanID string) ([]*store.StoredFinding, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT finding_id, scan_id, project_id, rule_id, secret_type, severity, confidence,
		       repo_url, commit_sha, branch, file_path, line_number, column_number,
		       end_line, end_column,
		       evidence_redacted, secret_checksum, source_context,
		       suppressed, exception_id, verification_status, ai_annotation,
		       triage_status, triage_source, triaged_at, context_hash, detected_at
		FROM findings
		WHERE scan_id = ?
		ORDER BY file_path ASC, line_number ASC, column_number ASC, rule_id ASC, finding_id ASC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query scan findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*store.StoredFinding
	for rows.Next() {
		f, err := scanStoredFindingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func scanStoredFindingRow(row rowScanner) (*store.StoredFinding, error) {
	var (
		f                                                            store.StoredFinding
		projectID, repoURL, commitSHA, branch                        sql.NullString
		evidenceRedacted, sourceContext, exceptionID, aiAnnotation   sql.NullString
		triageStatus, triageSource, triagedAt, contextHash           sql.NullString
		secretType, severity, confidence, verificationStatus, detAt  string
		suppressed                                                   int
	)

	if err := row.Scan(
		&f.FindingID, &f.ScanID, &projectID, &f.RuleID, &secretType, &severity, &confidence,
		&repoURL, &commitSHA, &branch, &f.File, &f.Line, &f.Column,
		&f.EndLine, &f.EndColumn,
		&evidenceRedacted, &f.SecretChecksum, &sourceContext,
		&suppressed, &exceptionID, &verificationStatus, &aiAnnotation,
		&triageStatus, &triageSource, &triagedAt, &contextHash, &detAt,
	); err != nil {
		return nil, err
	}

	f.ProjectID = projectID.String
	f.SecretType = sdk.SecretType(secretType)
	f.Severity = sdk.Severity(severity)
	f.Confidence = sdk.Confidence(confidence)
	f.RepositoryURL = repoURL.String
	f.CommitSHA = commitSHA.String
	f.Branch = branch.String
	f.EvidenceRedacted = evidenceRedacted.String
	f.SourceContext = sourceContext.String
	f.Suppressed = suppressed > 0
	f.ExceptionID = exceptionID.String
	f.VerificationStatus = verificationStatus

	if triageStatus.Valid && triageStatus.String != "" {
		f.TriageStatus = sdk.TriageStatus(triageStatus.String)
	} else {
		f.TriageStatus = sdk.TriageStatusUntriaged
	}
	f.TriageSource = triageSource.String
	if triagedAt.Valid && triagedAt.String != "" {
		if t, err := time.Parse(time.RFC3339, triagedAt.String); err == nil {
			f.TriagedAt = &t
		}
	}
	f.ContextHash = contextHash.String
	if t, err := time.Parse(time.RFC3339Nano, detAt); err == nil {
		f.DetectedAt = t
	}
	if aiAnnotation.Valid && aiAnnotation.String != "" {
		var ann sdk.AIAnnotation
		if err := json.Unmarshal([]byte(aiAnnotation.String), &ann); err == nil {
			f.AIAnnotation = &ann
		}
	}

	return &f, nil
}

// UpdateFindingTriage updates triage metadata (and optional suppression state)
// for a finding within a scan, optionally fanning out across all findings in the
// same scan sharing its secret_checksum. Returns the number of rows updated.
func (d *DB) UpdateFindingTriage(scanID, findingID string, update store.TriageUpdate) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var checksum string
	err := d.db.QueryRow(`
		SELECT secret_checksum FROM findings WHERE scan_id = ? AND finding_id = ?
	`, scanID, findingID).Scan(&checksum)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("finding %s not found in scan %s", findingID, scanID)
		}
		return 0, err
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)

	var annJSON interface{}
	if update.Annotation != nil {
		b, err := json.Marshal(update.Annotation)
		if err != nil {
			return 0, err
		}
		annJSON = string(b)
	}

	var excIDVal interface{}
	if update.ExceptionID != "" {
		excIDVal = update.ExceptionID
	}

	setParts := []string{
		"triage_status = ?",
		"triage_source = ?",
		"triaged_at = ?",
	}
	args := []interface{}{string(update.Status), update.Source, nowStr}

	if update.Annotation != nil {
		setParts = append(setParts, "ai_annotation = ?")
		args = append(args, annJSON)
	}
	if update.Suppressed != nil {
		suppInt := 0
		if *update.Suppressed {
			suppInt = 1
		}
		setParts = append(setParts, "suppressed = ?")
		args = append(args, suppInt)
		if !*update.Suppressed {
			setParts = append(setParts, "exception_id = NULL")
		} else if update.ExceptionID != "" {
			setParts = append(setParts, "exception_id = ?")
			args = append(args, excIDVal)
		}
	} else if update.ExceptionID != "" {
		setParts = append(setParts, "exception_id = ?")
		args = append(args, excIDVal)
	}

	var where string
	if update.ApplyToSameChecksum && checksum != "" {
		where = "scan_id = ? AND secret_checksum = ?"
		args = append(args, scanID, checksum)
	} else {
		where = "scan_id = ? AND finding_id = ?"
		args = append(args, scanID, findingID)
	}

	query := fmt.Sprintf("UPDATE findings SET %s WHERE %s", strings.Join(setParts, ", "), where)
	res, err := d.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return int(affected), nil
}

// RecomputeScanSummary calculates the post-triage / post-suppression metrics
// for scanID and persists them to scans.sanitised_summary. Deterministic raw
// scan columns (total_findings, findings_by_severity, score) are never mutated.
func (d *DB) RecomputeScanSummary(scanID string) (*store.SanitisedSummary, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.recomputeScanSummaryLocked(scanID)
}

func (d *DB) recomputeScanSummaryLocked(scanID string) (*store.SanitisedSummary, error) {
	rows, err := d.db.Query(`
		SELECT severity, suppressed, triage_status, triage_source, triaged_at
		FROM findings
		WHERE scan_id = ?
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("recompute scan summary query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	summary := &store.SanitisedSummary{
		ActiveFindingsBySeverity: make(map[string]int),
	}

	var latestTriaged time.Time
	var latestBy string

	for rows.Next() {
		var severity string
		var suppressed int
		var triageStatus, triageSource, triagedAt sql.NullString
		if err := rows.Scan(&severity, &suppressed, &triageStatus, &triageSource, &triagedAt); err != nil {
			return nil, err
		}

		summary.RawFindings++

		status := sdk.TriageStatusUntriaged
		if triageStatus.Valid && triageStatus.String != "" {
			status = sdk.TriageStatus(triageStatus.String)
		}
		switch status {
		case sdk.TriageStatusTruePositive:
			summary.TriagedTruePositives++
		case sdk.TriageStatusFalsePositive:
			summary.TriagedFalsePositives++
		case sdk.TriageStatusNeedsReview:
			summary.NeedsReview++
		default:
			summary.Untriaged++
		}

		if suppressed > 0 {
			summary.SuppressedFindings++
		} else {
			summary.ActiveFindings++
			summary.ActiveFindingsBySeverity[severity]++
		}

		if triagedAt.Valid && triagedAt.String != "" {
			if t, err := time.Parse(time.RFC3339, triagedAt.String); err == nil {
				if t.After(latestTriaged) {
					latestTriaged = t
					latestBy = triageSource.String
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if summary.ActiveFindings > 0 {
		critical := summary.ActiveFindingsBySeverity["Critical"] + summary.ActiveFindingsBySeverity["CRITICAL"]
		high := summary.ActiveFindingsBySeverity["High"] + summary.ActiveFindingsBySeverity["HIGH"]
		medium := summary.ActiveFindingsBySeverity["Medium"] + summary.ActiveFindingsBySeverity["MEDIUM"]
		low := summary.ActiveFindingsBySeverity["Low"] + summary.ActiveFindingsBySeverity["LOW"]
		score := float64(critical*10+high*5+medium*2+low) / float64(summary.ActiveFindings)
		if score > 10 {
			score = 10
		}
		summary.SanitisedScore = math.Round(score*100) / 100
	}

	if summary.RawFindings > 0 {
		pct := (float64(summary.SuppressedFindings) / float64(summary.RawFindings)) * 100.0
		summary.NoiseReductionPercent = math.Round(pct*10) / 10
	}

	if !latestTriaged.IsZero() {
		t := latestTriaged
		summary.LastTriagedAt = &t
		summary.LastTriagedBy = latestBy
	}

	b, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if _, err := d.db.Exec(`UPDATE scans SET sanitised_summary = ? WHERE id = ?`, string(b), scanID); err != nil {
		return nil, fmt.Errorf("persist sanitised_summary: %w", err)
	}

	return summary, nil
}

// GetSanitisedSummary returns the sanitised summary for scanID, computing it on
// demand if it has not yet been populated.
func (d *DB) GetSanitisedSummary(scanID string) (*store.SanitisedSummary, error) {
	d.mu.RLock()
	var raw sql.NullString
	err := d.db.QueryRow(`SELECT sanitised_summary FROM scans WHERE id = ?`, scanID).Scan(&raw)
	d.mu.RUnlock()
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found: %s", scanID)
		}
		return nil, err
	}

	if raw.Valid && raw.String != "" && raw.String != "{}" {
		var summary store.SanitisedSummary
		if err := json.Unmarshal([]byte(raw.String), &summary); err == nil {
			if summary.ActiveFindingsBySeverity == nil {
				summary.ActiveFindingsBySeverity = make(map[string]int)
			}
			return &summary, nil
		}
	}

	return d.RecomputeScanSummary(scanID)
}

func storedFindingToDiagnostic(f *store.StoredFinding) *diagnostics.SecurityDiagnostic {
	loc := f.File
	sha := f.SecretChecksum
	src := f.SourceContext
	line := int64(f.Line)
	if line > 0 {
		line--
	}
	col := int64(f.Column)
	if col > 0 {
		col--
	}
	return &diagnostics.SecurityDiagnostic{
		ID: f.FindingID,
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: f.RuleID,
				Confidence:  parseConfidence(string(f.Confidence)),
			},
		},
		Range: code.Range{
			Start: code.Position{Line: line, Character: col},
		},
		Location: &loc,
		SHA256:   &sha,
		Source:   &src,
		Excluded: f.Suppressed,
	}
}

// PreviewExceptionOnScan dry-runs a candidate exception rule against all
// findings in scanID using CheckMate's exact exceptionMatcher semantics.
func (d *DB) PreviewExceptionOnScan(scanID string, exc *store.Exception) (*store.ExceptionPreview, error) {
	findings, err := d.GetScanFindings(scanID)
	if err != nil {
		return nil, err
	}

	candidate := *exc
	if candidate.Status == "" {
		candidate.Status = "active"
	}
	matcher := newExceptionMatcher([]*store.Exception{&candidate})

	preview := &store.ExceptionPreview{
		MatchedByRule:          make(map[string]int),
		SampleMatchedLocations: []store.ExceptionMatchLocation{},
	}

	const maxSamples = 20
	for _, f := range findings {
		diag := storedFindingToDiagnostic(f)
		matched, _ := matcher.match(diag)
		if !matched {
			continue
		}

		preview.MatchedCount++
		preview.MatchedByRule[f.RuleID]++

		if f.Suppressed {
			preview.AlreadySuppressedCount++
		}
		if f.TriageStatus == sdk.TriageStatusUntriaged {
			preview.UntriagedMatchedCount++
		}
		if f.TriageStatus == sdk.TriageStatusTruePositive {
			preview.WouldSuppressTruePositives++
			preview.ConflictingFindingIDs = append(preview.ConflictingFindingIDs, f.FindingID)
		}

		if len(preview.SampleMatchedLocations) < maxSamples {
			preview.SampleMatchedLocations = append(preview.SampleMatchedLocations, store.ExceptionMatchLocation{
				FindingID:    f.FindingID,
				File:         f.File,
				Line:         f.Line,
				Column:       f.Column,
				RuleID:       f.RuleID,
				TriageStatus: f.TriageStatus,
				Suppressed:   f.Suppressed,
			})
		}
	}

	return preview, nil
}

// ApplyExceptionToScan persists exc (if not already present), retroactively
// suppresses all matching findings in scanID, marks untriaged matches as
// false_positive, records an audit event, and recomputes the scan summary.
// Unless force is true, it refuses to proceed if exc matches any finding already
// marked true_positive.
func (d *DB) ApplyExceptionToScan(scanID string, exc *store.Exception, triagedBy string, force bool) (*store.ExceptionApplyResult, error) {
	preview, err := d.PreviewExceptionOnScan(scanID, exc)
	if err != nil {
		return nil, err
	}
	if preview.WouldSuppressTruePositives > 0 && !force {
		return nil, fmt.Errorf("suppression rule matches %d finding(s) already confirmed as true_positive (%s); pass force=true to override",
			preview.WouldSuppressTruePositives, strings.Join(preview.ConflictingFindingIDs, ", "))
	}

	if err := d.CreateException(exc); err != nil {
		return nil, fmt.Errorf("create exception: %w", err)
	}

	findings, err := d.GetScanFindings(scanID)
	if err != nil {
		return nil, err
	}

	matcher := newExceptionMatcher([]*store.Exception{exc})
	nowStr := time.Now().UTC().Format(time.RFC3339)

	if triagedBy == "" {
		triagedBy = exc.CreatedBy
	}
	if triagedBy == "" {
		triagedBy = "agent:mcp"
	}

	ann := &sdk.AIAnnotation{
		Summary:        exc.Justification,
		Verdict:        string(sdk.TriageStatusFalsePositive),
		ReasonCategory: exc.Reason,
		TriageSource:   triagedBy,
		FPLikelihood:   1.0,
		GeneratedAt:    time.Now().UTC(),
	}
	annBytes, _ := json.Marshal(ann)

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	suppressedNow := 0
	alreadySuppressed := 0

	for _, f := range findings {
		diag := storedFindingToDiagnostic(f)
		matched, _ := matcher.match(diag)
		if !matched {
			continue
		}
		if f.Suppressed {
			alreadySuppressed++
			continue
		}

		if _, err := tx.Exec(`
			UPDATE findings
			SET suppressed = 1,
			    exception_id = ?,
			    triage_status = CASE WHEN triage_status = 'untriaged' OR ? THEN 'false_positive' ELSE triage_status END,
			    triage_source = CASE WHEN triage_status = 'untriaged' OR ? THEN ? ELSE triage_source END,
			    triaged_at = CASE WHEN triage_status = 'untriaged' OR ? THEN ? ELSE triaged_at END,
			    ai_annotation = CASE WHEN ai_annotation IS NULL THEN ? ELSE ai_annotation END
			WHERE scan_id = ? AND finding_id = ?
		`, exc.ID, force, force, triagedBy, force, nowStr, string(annBytes), scanID, f.FindingID); err != nil {
			return nil, fmt.Errorf("suppress finding %s: %w", f.FindingID, err)
		}
		suppressedNow++
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true

	summary, err := d.recomputeScanSummaryLocked(scanID)
	if err != nil {
		return nil, err
	}

	return &store.ExceptionApplyResult{
		ExceptionID:       exc.ID,
		SuppressedCount:   suppressedNow,
		AlreadySuppressed: alreadySuppressed,
		SanitisedSummary:  summary,
	}, nil
}

// RecordAuditEvent writes an entry to the audit_log table.
func (d *DB) RecordAuditEvent(audit *store.AuditEvent, resourceType, resourceID string) error {
	if audit == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if audit.Timestamp.IsZero() {
		audit.Timestamp = time.Now().UTC()
	}
	return d.insertAuditLogTx(d.db, audit, resourceType, resourceID)
}
