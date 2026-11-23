package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/mcp"
	"github.com/adedayo/checkmate/pkg/report"
	"github.com/adedayo/checkmate/pkg/triage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_MCPAndTriageWriteBack(t *testing.T) {
	_, cleanup := setupAuthTest(t)
	defer cleanup()

	// Prepare fixture repo with 1 prod credential + 1 test fixture token
	repoDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repoDir, "cmd"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(repoDir, "testdata"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "cmd", "main.go"), []byte(`package main
const awsKey = "AKIAIOSFODNN7EXAMPLE"
`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "testdata", "mock.json"), []byte(`{
  "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
}
`), 0644))

	// 1. Trigger a scan via POST /v1/mcp
	scanReqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "checkmate_scan",
			"arguments": map[string]interface{}{"targets": []string{repoDir}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/mcp", bytes.NewReader(scanReqBody))
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var rpcResp mcp.Response
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rpcResp))
	require.Nil(t, rpcResp.Error)

	var toolRes mcp.CallToolResult
	rawRes, _ := json.Marshal(rpcResp.Result)
	require.NoError(t, json.Unmarshal(rawRes, &toolRes))
	require.False(t, toolRes.IsError)

	var overview triage.ScanOverview
	require.NoError(t, json.Unmarshal([]byte(toolRes.Content[0].Text), &overview))
	require.NotEmpty(t, overview.ScanID)
	require.Equal(t, 2, overview.RawFindings)

	findings, err := pm.GetScanFindings(overview.ScanID)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	var prodID, mockID string
	for _, f := range findings {
		if filepath.Base(f.File) == "main.go" {
			prodID = f.FindingID
		} else {
			mockID = f.FindingID
		}
	}
	require.NotEmpty(t, prodID)
	require.NotEmpty(t, mockID)

	// 2. Suppress the testdata finding via PUT /v1/findings/{findingId}/triage
	putBody, _ := json.Marshal(map[string]interface{}{
		"scanId":           overview.ScanID,
		"triagedBy":        "agent:rest-test",
		"verdict":          "false_positive",
		"reason":           "test_fixture",
		"justification":    "Mock token in testdata/mock.json",
		"persistException": true,
	})
	req = httptest.NewRequest(http.MethodPut, "http://localhost/v1/findings/"+mockID+"/triage", bytes.NewReader(putBody))
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 3. Confirm the prod finding via POST /v1/scans/{scanId}/triage/batch
	batchBody, _ := json.Marshal(map[string]interface{}{
		"triagedBy": "agent:rest-test",
		"decisions": []map[string]interface{}{
			{
				"findingId":       prodID,
				"verdict":         "true_positive",
				"reason":          "real_credential",
				"justification":   "Hardcoded AWS key in cmd/main.go",
				"remediationHint": "Revoke key and move to env var",
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "http://localhost/v1/scans/"+overview.ScanID+"/triage/batch", bytes.NewReader(batchBody))
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 4. Fetch GET /v1/scans/{scanId}/sanitised -> only 1 active finding
	req = httptest.NewRequest(http.MethodGet, "http://localhost/v1/scans/"+overview.ScanID+"/sanitised", nil)
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var sanitised triage.SanitisedReportJSON
	require.NoError(t, json.NewDecoder(w.Body).Decode(&sanitised))
	assert.Equal(t, 2, sanitised.SanitisedSummary.RawFindings)
	assert.Equal(t, 1, sanitised.SanitisedSummary.ActiveFindings)
	assert.Equal(t, 1, sanitised.SanitisedSummary.SuppressedFindings)
	assert.Equal(t, 0, sanitised.SanitisedSummary.Untriaged)
	require.Len(t, sanitised.Findings, 1)
	assert.Equal(t, prodID, sanitised.Findings[0].FindingID)

	// 5. Fetch sanitised SARIF via GET /v1/scans/{scanId}/report?view=sanitised
	req = httptest.NewRequest(http.MethodGet, "http://localhost/v1/scans/"+overview.ScanID+"/report?view=sanitised", nil)
	req.Header.Set("Accept", "application/sarif+json")
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var sarifSanitised report.SarifLog
	require.NoError(t, json.NewDecoder(w.Body).Decode(&sarifSanitised))
	require.Len(t, sarifSanitised.Runs[0].Results, 1)

	// 6. Fetch full audit SARIF with suppressions[]
	req = httptest.NewRequest(http.MethodGet, "http://localhost/v1/scans/"+overview.ScanID+"/report?view=sanitised&includeSuppressed=true", nil)
	req.Header.Set("Accept", "application/sarif+json")
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var sarifFull report.SarifLog
	require.NoError(t, json.NewDecoder(w.Body).Decode(&sarifFull))
	require.Len(t, sarifFull.Runs[0].Results, 2)
}
