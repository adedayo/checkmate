package triage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/report"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createFixtureRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(repoDir, "cmd", "deploy"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(repoDir, "testdata", "fixtures"), 0755))

	// Realistic credential in production path
	prodCode := `package main

const awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "cmd", "deploy", "main.go"), []byte(prodCode), 0644))

	// Repeated dummy high-entropy fixture strings across multiple files in testdata
	fixtureA := `{
  "mock_api_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
  "sample_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
`
	fixtureB := `{
  "mock_api_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "testdata", "fixtures", "a.json"), []byte(fixtureA), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "testdata", "fixtures", "b.json"), []byte(fixtureB), 0644))

	return repoDir
}

func TestWildcardGuardrails(t *testing.T) {
	badCases := []struct {
		name   string
		ruleID string
		scope  *store.ExceptionScopeDetail
	}{
		{"nil scope", "*", nil},
		{"wildcard pathRegex .*", "*", &store.ExceptionScopeDetail{Type: "pathRegex", RegexMatch: ".*"}},
		{"wildcard pathRegex ^.+$", "*", &store.ExceptionScopeDetail{Type: "pathRegex", RegexMatch: "^.+$"}},
		{"wildcard globalRegex", "*", &store.ExceptionScopeDetail{Type: "globalRegex", RegexMatch: ".+"}},
		{"overly broad globalRegex", "*", &store.ExceptionScopeDetail{Type: "globalRegex", RegexMatch: "[a-zA-Z0-9]+"}},
		{"short globalString", "*", &store.ExceptionScopeDetail{Type: "globalString", StringMatch: "ab"}},
		{"missing checksum", "*", &store.ExceptionScopeDetail{Type: "globalHash"}},
		{"invalid regex", "*", &store.ExceptionScopeDetail{Type: "pathRegex", RegexMatch: "[unclosed"}},
	}

	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSuppressionScope(tc.ruleID, tc.scope)
			assert.Error(t, err)
		})
	}

	// Valid narrow rules should pass
	assert.NoError(t, ValidateSuppressionScope("*", &store.ExceptionScopeDetail{
		Type:       "pathRegex",
		RegexMatch: `.*/testdata/fixtures/.*`,
	}))
	assert.NoError(t, ValidateSuppressionScope("*", &store.ExceptionScopeDetail{
		Type:           "globalHash",
		SecretChecksum: "abc123def456",
	}))
}

func TestEndToEndScanTriageSuppressAndRescan(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	svc := NewService(db)
	repoDir := createFixtureRepo(t)
	ctx := context.Background()

	// 1. Run initial scan
	overview, err := svc.Scan(ctx, ScanRequest{Targets: []string{repoDir}})
	require.NoError(t, err)
	require.NotEmpty(t, overview.ScanID)
	require.NotEmpty(t, overview.ProjectID)
	assert.GreaterOrEqual(t, overview.FilesScanned, 3, "expected filesScanned to reflect scanned files")
	require.GreaterOrEqual(t, overview.RawFindings, 3, "expected findings in both prod and testdata")
	assert.Equal(t, overview.RawFindings, overview.UntriagedFindings)

	// 2. Fetch directory-grouped worklist and verify end coordinates are populated
	dirWorklist, err := svc.GetWorklist(ctx, WorklistRequest{
		ScanID:  overview.ScanID,
		GroupBy: "directory",
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, dirWorklist.TotalGroups, 2)
	for _, g := range dirWorklist.Groups {
		for _, loc := range g.SampleLocations {
			assert.GreaterOrEqual(t, loc.EndLine, loc.Line)
			assert.Greater(t, loc.EndColumn, 0)
		}
	}

	// 3. Preview suppression for testdata/fixtures
	testdataScope := &store.ExceptionScopeDetail{
		Type:       "pathRegex",
		RegexMatch: `.*/testdata/fixtures/.*`,
	}
	preview, err := svc.PreviewSuppression(ctx, PreviewSuppressionRequest{
		ScanID: overview.ScanID,
		Scope:  testdataScope,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, preview.MatchedCount, 2)
	assert.Equal(t, 0, preview.WouldSuppressTruePositives)

	// 4. Apply pattern suppression rule for testdata/fixtures
	applyRes, err := svc.ApplySuppressionRule(ctx, ApplySuppressionRuleRequest{
		ScanID:        overview.ScanID,
		Scope:         testdataScope,
		Reason:        "test_fixture",
		Justification: "Synthetic tokens inside testdata/fixtures",
		TriagedBy:     "agent:test-runner",
	})
	require.NoError(t, err)
	assert.Equal(t, preview.MatchedCount, applyRes.SuppressedCount)
	assert.Less(t, applyRes.SanitisedSummary.ActiveFindings, overview.RawFindings)
	assert.Greater(t, applyRes.SanitisedSummary.NoiseReductionPercent, 0.0)

	// 5. Fetch remaining untriaged worklist -> should only contain cmd/deploy/main.go findings
	remWorklist, err := svc.GetWorklist(ctx, WorklistRequest{
		ScanID:  overview.ScanID,
		GroupBy: "file",
	})
	require.NoError(t, err)
	require.Equal(t, 1, remWorklist.TotalGroups)
	assert.Contains(t, remWorklist.Groups[0].GroupKey, filepath.Join("cmd", "deploy", "main.go"))

	// 6. Record true_positive decisions for all remaining findings
	var decisions []TriageDecision
	for _, loc := range remWorklist.Groups[0].SampleLocations {
		decisions = append(decisions, TriageDecision{
			FindingID:       loc.FindingID,
			Verdict:         "true_positive",
			Reason:          "real_credential",
			Justification:   "Hardcoded AWS credential in cmd/deploy/main.go",
			RemediationHint: "Rotate IAM credential and inject via environment",
		})
	}
	batchRes, err := svc.RecordTriageBatch(ctx, TriageBatchRequest{
		ScanID:    overview.ScanID,
		TriagedBy: "agent:test-runner",
		Decisions: decisions,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, batchRes.SanitisedSummary.Untriaged)
	assert.Equal(t, len(decisions), batchRes.SanitisedSummary.TriagedTruePositives)

	// 7. Export sanitised JSON, SARIF, and .checkmate.yaml
	jsonExport, err := svc.ExportSanitised(ctx, ExportRequest{ScanID: overview.ScanID, Format: "json"})
	require.NoError(t, err)
	var parsed SanitisedReportJSON
	require.NoError(t, json.Unmarshal([]byte(jsonExport.Content), &parsed))
	assert.Equal(t, len(decisions), len(parsed.Findings))
	for _, f := range parsed.Findings {
		assert.False(t, f.Suppressed)
		assert.Equal(t, sdk.TriageStatusTruePositive, f.TriageStatus)
	}

	sarifExport, err := svc.ExportSanitised(ctx, ExportRequest{ScanID: overview.ScanID, Format: "sarif", IncludeSuppressed: true})
	require.NoError(t, err)
	var sarifDoc report.SarifLog
	require.NoError(t, json.Unmarshal([]byte(sarifExport.Content), &sarifDoc))
	assert.Equal(t, overview.RawFindings, len(sarifDoc.Runs[0].Results))

	yamlExport, err := svc.ExportSanitised(ctx, ExportRequest{ScanID: overview.ScanID, Format: "checkmate_yaml"})
	require.NoError(t, err)
	assert.Contains(t, yamlExport.Content, "testdata/fixtures")

	// 8. Rescan the same repo: should reuse projectID, automatically exclude testdata/fixtures,
	//    and carry forward the true_positive verdict so untriaged == 0!
	rescan, err := svc.Scan(ctx, ScanRequest{Targets: []string{repoDir}})
	require.NoError(t, err)
	assert.Equal(t, overview.ProjectID, rescan.ProjectID)
	assert.Equal(t, len(decisions), rescan.RawFindings, "persisted pathRegex exception should exclude testdata/fixtures on rescan")
	assert.Equal(t, len(decisions), rescan.CarriedForwardTriaged)
	assert.Equal(t, 0, rescan.UntriagedFindings)
}

func TestRecordTriageBatchPathStringException(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	svc := NewService(db)
	repoDir := createFixtureRepo(t)
	ctx := context.Background()

	overview, err := svc.Scan(ctx, ScanRequest{Targets: []string{repoDir}})
	require.NoError(t, err)

	wl, err := svc.GetWorklist(ctx, WorklistRequest{ScanID: overview.ScanID, GroupBy: "file"})
	require.NoError(t, err)

	var targetLoc WorklistLocation
	for _, g := range wl.Groups {
		if filepath.Base(g.GroupKey) == "b.json" {
			targetLoc = g.SampleLocations[0]
			break
		}
	}
	require.NotEmpty(t, targetLoc.FindingID)

	res, err := svc.RecordTriageBatch(ctx, TriageBatchRequest{
		ScanID:    overview.ScanID,
		TriagedBy: "agent:test-pathstring",
		Decisions: []TriageDecision{
			{
				FindingID:        targetLoc.FindingID,
				Verdict:          "false_positive",
				Reason:           "test_fixture",
				Justification:    "Mock token literal in b.json",
				PersistException: true,
				ExceptionScope:   "pathString",
				StringMatch:      "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, res.CreatedExceptionIDs, 1)

	exc, err := db.GetException(res.CreatedExceptionIDs[0])
	require.NoError(t, err)
	assert.Equal(t, "pathString", exc.Scope.Type)
	assert.Equal(t, targetLoc.File, exc.Scope.Path)
	assert.Equal(t, "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", exc.Scope.StringMatch)
}
