package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/sdk"
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

	if repoURL.Valid { f.RepositoryURL = repoURL.String }
	if commitSHA.Valid { f.CommitSHA = commitSHA.String }
	if branch.Valid { f.Branch = branch.String }
	if evidenceRedacted.Valid { f.EvidenceRedacted = evidenceRedacted.String }
	if sourceContext.Valid { f.SourceContext = sourceContext.String }
	if exceptionID.Valid { f.ExceptionID = exceptionID.String }
	
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
