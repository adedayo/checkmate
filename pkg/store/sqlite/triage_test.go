package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedTestScan(t *testing.T, db *DB) (string, string) {
	t.Helper()
	proj, err := db.CreateProject(projects.ProjectDescription{
		Name:      "triage-test-project",
		Workspace: "default",
	})
	require.NoError(t, err)

	scanID := "scan-triage-1"
	now := time.Now().UTC().Format(time.RFC3339)
	db.mu.Lock()
	_, err = db.db.Exec(`
		INSERT INTO scans (id, project_id, status, file_count, total_findings, findings_by_severity, score, created_at)
		VALUES (?, ?, 'complete', 3, 3, '{"High":3}', 5.0, ?)
	`, scanID, proj.ID, now)
	db.mu.Unlock()
	require.NoError(t, err)

	makeDiag := func(file string, line int64, rule, sha, src string) *diagnostics.SecurityDiagnostic {
		return &diagnostics.SecurityDiagnostic{
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: rule,
					Confidence:  diagnostics.High,
				},
			},
			Range: code.Range{
				Start: code.Position{Line: line, Character: 4},
			},
			Location: &file,
			SHA256:   &sha,
			Source:   &src,
		}
	}

	batch := []findingWrite{
		{finding: makeDiag("/repo/testdata/mock.json", 10, "Generic High Entropy", "sha_dup", `"token": "dummy_fixture_value_1"`)},
		{finding: makeDiag("/repo/testdata/other.json", 20, "Generic High Entropy", "sha_dup", `"token": "dummy_fixture_value_1"`)},
		{finding: makeDiag("/repo/cmd/app/main.go", 5, "AWS Access Key", "sha_real", `awsKey := "AKIAIOSFODNN7REALKEY"`)},
	}
	db.persistFindingBatch(context.Background(), scanID, proj.ID, batch)
	return proj.ID, scanID
}

func TestTriageBatchAndSanitisedSummary(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projID, scanID := seedTestScan(t, db)

	findings, err := db.GetScanFindings(scanID)
	require.NoError(t, err)
	require.Len(t, findings, 3)

	// Initial summary: 3 raw, 3 active, 0 suppressed, 3 untriaged
	summary, err := db.RecomputeScanSummary(scanID)
	require.NoError(t, err)
	assert.Equal(t, 3, summary.RawFindings)
	assert.Equal(t, 3, summary.ActiveFindings)
	assert.Equal(t, 0, summary.SuppressedFindings)
	assert.Equal(t, 3, summary.Untriaged)

	// Mark one duplicate as false_positive with ApplyToSameChecksum=true
	var dupFinding, realFinding *store.StoredFinding
	for _, f := range findings {
		if f.SecretChecksum == "sha_dup" && dupFinding == nil {
			dupFinding = f
		}
		if f.SecretChecksum == "sha_real" {
			realFinding = f
		}
	}
	require.NotNil(t, dupFinding)
	require.NotNil(t, realFinding)

	suppressed := true
	updated, err := db.UpdateFindingTriage(scanID, dupFinding.FindingID, store.TriageUpdate{
		Status:              sdk.TriageStatusFalsePositive,
		Source:              "agent:test",
		Suppressed:          &suppressed,
		ApplyToSameChecksum: true,
		Annotation: &sdk.AIAnnotation{
			Summary:        "Unit test fixture token",
			Verdict:        string(sdk.TriageStatusFalsePositive),
			ReasonCategory: "test_fixture",
			FPLikelihood:   0.99,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, updated)

	// Mark real finding as true_positive
	notSuppressed := false
	updated, err = db.UpdateFindingTriage(scanID, realFinding.FindingID, store.TriageUpdate{
		Status:     sdk.TriageStatusTruePositive,
		Source:     "agent:test",
		Suppressed: &notSuppressed,
		Annotation: &sdk.AIAnnotation{
			Summary:         "Live AWS access key in production code",
			RemediationHint: "Rotate IAM key immediately",
			Verdict:         string(sdk.TriageStatusTruePositive),
			FPLikelihood:    0.01,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, updated)

	// Recompute sanitised summary: raw stays 3, active drops to 1, 66.7% reduction
	summary, err = db.RecomputeScanSummary(scanID)
	require.NoError(t, err)
	assert.Equal(t, 3, summary.RawFindings)
	assert.Equal(t, 1, summary.ActiveFindings)
	assert.Equal(t, 2, summary.SuppressedFindings)
	assert.Equal(t, 2, summary.TriagedFalsePositives)
	assert.Equal(t, 1, summary.TriagedTruePositives)
	assert.Equal(t, 0, summary.Untriaged)
	assert.InDelta(t, 66.7, summary.NoiseReductionPercent, 0.2)

	// Verify deterministic raw metrics on scans table were NOT overwritten
	metrics, err := db.GetScanMetrics(projID, scanID)
	require.NoError(t, err)
	assert.Equal(t, 3, metrics.TotalFindings)
}

func TestDriftAwareCarryForward(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projID, scanID1 := seedTestScan(t, db)
	findings1, err := db.GetScanFindings(scanID1)
	require.NoError(t, err)

	// Triage the real finding and one dup finding in scan 1
	var realF, dupF *store.StoredFinding
	for _, f := range findings1 {
		if f.File == "/repo/cmd/app/main.go" {
			realF = f
		}
		if f.File == "/repo/testdata/mock.json" {
			dupF = f
		}
	}
	require.NotNil(t, realF)
	require.NotNil(t, dupF)

	_, err = db.UpdateFindingTriage(scanID1, realF.FindingID, store.TriageUpdate{
		Status: sdk.TriageStatusTruePositive,
		Source: "agent:test",
	})
	require.NoError(t, err)
	_, err = db.UpdateFindingTriage(scanID1, dupF.FindingID, store.TriageUpdate{
		Status: sdk.TriageStatusFalsePositive,
		Source: "agent:test",
	})
	require.NoError(t, err)

	// Scan 2: realF has identical context (should carry forward); dupF has drifted context (should reset to untriaged)
	scanID2 := "scan-triage-2"
	db.mu.Lock()
	_, err = db.db.Exec(`INSERT INTO scans (id, project_id, status, created_at) VALUES (?, ?, 'complete', ?)`,
		scanID2, projID, time.Now().UTC().Format(time.RFC3339))
	db.mu.Unlock()
	require.NoError(t, err)

	realLoc := "/repo/cmd/app/main.go"
	realSha := "sha_real"
	realSrcUnchanged := `awsKey := "AKIAIOSFODNN7REALKEY"`

	dupLoc := "/repo/testdata/mock.json"
	dupSha := "sha_dup"
	dupSrcDrifted := `prodClient.Authenticate("dummy_fixture_value_1")` // context changed!

	db.persistFindingBatch(context.Background(), scanID2, projID, []findingWrite{
		{finding: &diagnostics.SecurityDiagnostic{
			Justification: diagnostics.Justification{Headline: diagnostics.Evidence{Description: "AWS Access Key", Confidence: diagnostics.High}},
			Range:         code.Range{Start: code.Position{Line: 5, Character: 4}},
			Location:      &realLoc, SHA256: &realSha, Source: &realSrcUnchanged,
		}},
		{finding: &diagnostics.SecurityDiagnostic{
			Justification: diagnostics.Justification{Headline: diagnostics.Evidence{Description: "Generic High Entropy", Confidence: diagnostics.High}},
			Range:         code.Range{Start: code.Position{Line: 10, Character: 4}},
			Location:      &dupLoc, SHA256: &dupSha, Source: &dupSrcDrifted,
		}},
	})

	findings2, err := db.GetScanFindings(scanID2)
	require.NoError(t, err)
	require.Len(t, findings2, 2)

	byFile := map[string]*store.StoredFinding{}
	for _, f := range findings2 {
		byFile[f.File] = f
	}
	assert.Equal(t, sdk.TriageStatusTruePositive, byFile[realLoc].TriageStatus, "unchanged context should carry forward triage status")
	assert.Equal(t, "agent:test", byFile[realLoc].TriageSource)
	assert.Equal(t, sdk.TriageStatusUntriaged, byFile[dupLoc].TriageStatus, "drifted context should reset triage status to untriaged")
}

func TestPreviewAndApplyExceptionProtectsTruePositives(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projID, scanID := seedTestScan(t, db)
	findings, err := db.GetScanFindings(scanID)
	require.NoError(t, err)

	// Confirm the AWS key as true_positive
	for _, f := range findings {
		if f.SecretChecksum == "sha_real" {
			_, err := db.UpdateFindingTriage(scanID, f.FindingID, store.TriageUpdate{
				Status: sdk.TriageStatusTruePositive,
				Source: "agent:test",
			})
			require.NoError(t, err)
		}
	}

	// Rule targeting /repo/cmd/ matches the confirmed true_positive
	conflictExc := &store.Exception{
		ID:        "exc_conflict",
		ProjectID: projID,
		RuleID:    "*",
		Scope:     &store.ExceptionScopeDetail{Type: "pathRegex", RegexMatch: `.*/cmd/.*`},
		Reason:    "false_positive_pattern",
		CreatedBy: "agent:test",
		CreatedAt: time.Now().UTC(),
		Status:    "active",
	}

	preview, err := db.PreviewExceptionOnScan(scanID, conflictExc)
	require.NoError(t, err)
	assert.Equal(t, 1, preview.MatchedCount)
	assert.Equal(t, 1, preview.WouldSuppressTruePositives)
	assert.Len(t, preview.ConflictingFindingIDs, 1)

	// Applying without force must fail
	_, err = db.ApplyExceptionToScan(scanID, conflictExc, "agent:test", false)
	require.Error(t, err)

	// Narrow rule targeting testdata succeeds and suppresses both fixture findings
	safeExc := &store.Exception{
		ID:            "exc_testdata",
		ProjectID:     projID,
		RuleID:        "*",
		Scope:         &store.ExceptionScopeDetail{Type: "pathRegex", RegexMatch: `.*/testdata/.*`},
		Reason:        "test_fixture",
		Justification: "Test fixture directory",
		CreatedBy:     "agent:test",
		CreatedAt:     time.Now().UTC(),
		Status:        "active",
	}
	res, err := db.ApplyExceptionToScan(scanID, safeExc, "agent:test", false)
	require.NoError(t, err)
	assert.Equal(t, 2, res.SuppressedCount)
	assert.Equal(t, 1, res.SanitisedSummary.ActiveFindings)
	assert.Equal(t, 2, res.SanitisedSummary.SuppressedFindings)
}
