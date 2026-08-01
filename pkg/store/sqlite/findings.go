package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
)

func (s *DB) GetFinding(findingID string) (*sdk.Finding, error) {
	row := s.db.QueryRow(`
		SELECT finding_id, rule_id, secret_type, severity, confidence,
		       repo_url, commit_sha, branch, file_path, line_number, column_number,
		       evidence_redacted, secret_checksum, source_context,
		       suppressed, exception_id, verification_status, verified_at,
		       ai_annotation, detected_at
		FROM findings
		WHERE finding_id = ?
		LIMIT 1
	`, findingID)

	var f sdk.Finding
	var repoURL, commitSHA, branch, evidenceRedacted, sourceContext, exceptionID, verifiedAt, aiAnnotationStr sql.NullString
	var secretType, severity, confidence, verificationStatus, detectedAt string
	var suppressed int

	err := row.Scan(
		&f.ID, &f.RuleID, &secretType, &severity, &confidence,
		&repoURL, &commitSHA, &branch, &f.File, &f.Line, &f.Column,
		&evidenceRedacted, &f.SecretChecksum, &sourceContext,
		&suppressed, &exceptionID, &verificationStatus, &verifiedAt,
		&aiAnnotationStr, &detectedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("finding not found")
		}
		return nil, err
	}

	f.SecretType = sdk.SecretType(secretType)
	f.Severity = sdk.Severity(severity)
	f.Confidence = sdk.Confidence(confidence)
	f.VerificationStatus = sdk.VerificationStatus(verificationStatus)
	f.Suppressed = suppressed > 0

	if repoURL.Valid {
		f.RepositoryURL = repoURL.String
	}
	if commitSHA.Valid {
		f.CommitSHA = commitSHA.String
	}
	if branch.Valid {
		f.Branch = branch.String
	}
	if evidenceRedacted.Valid {
		f.EvidenceRedacted = evidenceRedacted.String
	}
	if sourceContext.Valid {
		f.SourceContext = sourceContext.String
	}
	if exceptionID.Valid {
		f.ExceptionID = exceptionID.String
	}

	if parsedTime, err := time.Parse(time.RFC3339Nano, detectedAt); err == nil {
		f.DetectedAt = parsedTime
	}

	if aiAnnotationStr.Valid && aiAnnotationStr.String != "" {
		var ann sdk.AIAnnotation
		if err := json.Unmarshal([]byte(aiAnnotationStr.String), &ann); err == nil {
			f.AIAnnotation = &ann
		}
	}

	return &f, nil
}

func (s *DB) UpdateFindingAIAnnotation(findingID string, annotation *sdk.AIAnnotation) error {
	b, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		UPDATE findings
		SET ai_annotation = ?
		WHERE finding_id = ?
	`, string(b), findingID)
	return err
}

func (s *DB) GetUnannotatedFindings(scanID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT finding_id
		FROM findings
		WHERE scan_id = ? AND ai_annotation IS NULL
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := rows.Close()
		if err != nil {
			return
		}

	}()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func (s *DB) GetAITokenUsage() (*store.AITokenUsage, error) {
	row := s.db.QueryRow(`
		SELECT 
			COALESCE(SUM(json_extract(ai_annotation, '$.promptTokens')), 0),
			COALESCE(SUM(json_extract(ai_annotation, '$.completionTokens')), 0)
		FROM findings 
		WHERE ai_annotation IS NOT NULL
	`)

	var usage store.AITokenUsage
	err := row.Scan(&usage.PromptTokens, &usage.CompletionTokens)
	if err != nil {
		return nil, err
	}
	return &usage, nil
}
