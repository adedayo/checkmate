package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/store/sqlite"
	"github.com/adedayo/checkmate/pkg/triage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createMCPFixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "fixtures"), 0755))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "config.go"), []byte(`package src
const awsKey = "AKIAIOSFODNN7EXAMPLE"
`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures", "mock.json"), []byte(`{
  "fake_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
}
`), 0644))
	return dir
}

func TestMCPStdioEndToEndTriageWorkflow(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	srv := NewServer(db, "test-1.0.0")
	repoDir := createMCPFixtureRepo(t)

	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- srv.ServeStdio(ctx, clientToServerR, serverToClientW)
	}()

	reader := bufio.NewReader(serverToClientR)
	sendRPC := func(id int, method string, params interface{}) Response {
		t.Helper()
		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  method,
			"params":  params,
		}
		b, err := json.Marshal(req)
		require.NoError(t, err)
		_, err = clientToServerW.Write(append(b, '\n'))
		require.NoError(t, err)

		line, err := reader.ReadBytes('\n')
		require.NoError(t, err)
		var resp Response
		require.NoError(t, json.Unmarshal(line, &resp))
		require.Nil(t, resp.Error, "unexpected RPC error for %s: %+v", method, resp.Error)
		return resp
	}

	// 1. Initialize handshake
	initResp := sendRPC(1, "initialize", map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"clientInfo":      map[string]string{"name": "test-agent", "version": "1.0"},
	})
	rawInit, _ := json.Marshal(initResp.Result)
	assert.Contains(t, string(rawInit), `"protocolVersion":"2025-03-26"`)
	assert.Contains(t, string(rawInit), `"name":"checkmate"`)

	// Send initialized notification (no response expected)
	_, err = clientToServerW.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))
	require.NoError(t, err)

	// 2. Ping & tools/list
	_ = sendRPC(2, "ping", nil)
	toolsResp := sendRPC(3, "tools/list", nil)
	toolsJSON, _ := json.Marshal(toolsResp.Result)
	for _, toolName := range []string{
		"checkmate_scan",
		"checkmate_get_worklist",
		"checkmate_preview_suppression",
		"checkmate_triage_batch",
		"checkmate_apply_suppression_rule",
		"checkmate_export_sanitised",
	} {
		assert.Contains(t, string(toolsJSON), toolName)
	}

	// 3. Call checkmate_scan
	scanResp := sendRPC(4, "tools/call", map[string]interface{}{
		"name":      "checkmate_scan",
		"arguments": map[string]interface{}{"targets": []string{repoDir}},
	})
	var scanCall CallToolResult
	b, _ := json.Marshal(scanResp.Result)
	require.NoError(t, json.Unmarshal(b, &scanCall))
	require.False(t, scanCall.IsError)

	var overview triage.ScanOverview
	require.NoError(t, json.Unmarshal([]byte(scanCall.Content[0].Text), &overview))
	require.NotEmpty(t, overview.ScanID)
	require.GreaterOrEqual(t, overview.RawFindings, 2)

	// 4. Call checkmate_get_worklist
	wlResp := sendRPC(5, "tools/call", map[string]interface{}{
		"name":      "checkmate_get_worklist",
		"arguments": map[string]interface{}{"scanId": overview.ScanID, "groupBy": "file"},
	})
	var wlCall CallToolResult
	b, _ = json.Marshal(wlResp.Result)
	require.NoError(t, json.Unmarshal(b, &wlCall))
	require.False(t, wlCall.IsError)

	var wl triage.WorklistResult
	require.NoError(t, json.Unmarshal([]byte(wlCall.Content[0].Text), &wl))
	require.Equal(t, 2, wl.TotalGroups)

	// 5. Preview & apply suppression for fixtures/
	prevResp := sendRPC(6, "tools/call", map[string]interface{}{
		"name": "checkmate_preview_suppression",
		"arguments": map[string]interface{}{
			"scanId": overview.ScanID,
			"scope":  map[string]interface{}{"type": "pathRegex", "regexMatch": `.*/fixtures/.*`},
		},
	})
	var prevCall CallToolResult
	b, _ = json.Marshal(prevResp.Result)
	require.NoError(t, json.Unmarshal(b, &prevCall))
	require.False(t, prevCall.IsError)
	assert.Contains(t, prevCall.Content[0].Text, `"matchedCount": 1`)

	applyResp := sendRPC(7, "tools/call", map[string]interface{}{
		"name": "checkmate_apply_suppression_rule",
		"arguments": map[string]interface{}{
			"scanId":        overview.ScanID,
			"scope":         map[string]interface{}{"type": "pathRegex", "regexMatch": `.*/fixtures/.*`},
			"reason":        "test_fixture",
			"justification": "Synthetic token in fixtures directory",
			"triagedBy":     "agent:stdio-test",
		},
	})
	var applyCall CallToolResult
	b, _ = json.Marshal(applyResp.Result)
	require.NoError(t, json.Unmarshal(b, &applyCall))
	require.False(t, applyCall.IsError)

	// 6. Export sanitised JSON and verify only src/config.go remains active
	expResp := sendRPC(8, "tools/call", map[string]interface{}{
		"name": "checkmate_export_sanitised",
		"arguments": map[string]interface{}{
			"scanId": overview.ScanID,
			"format": "json",
		},
	})
	var expCall CallToolResult
	b, _ = json.Marshal(expResp.Result)
	require.NoError(t, json.Unmarshal(b, &expCall))
	require.False(t, expCall.IsError)

	var expRes triage.ExportResult
	require.NoError(t, json.Unmarshal([]byte(expCall.Content[0].Text), &expRes))
	assert.Equal(t, 1, expRes.FindingCount)
	assert.Contains(t, expRes.Content, "config.go")
	assert.NotContains(t, expRes.Content, "mock.json")

	// 7. Read MCP resource and prompt
	resResp := sendRPC(9, "resources/read", map[string]interface{}{
		"uri": "checkmate://scans/" + overview.ScanID + "/summary",
	})
	resJSON, _ := json.Marshal(resResp.Result)
	assert.Contains(t, string(resJSON), overview.ScanID)

	promptResp := sendRPC(10, "prompts/get", map[string]interface{}{
		"name":      "triage_scan",
		"arguments": map[string]string{"scanId": overview.ScanID},
	})
	promptJSON, _ := json.Marshal(promptResp.Result)
	assert.Contains(t, string(promptJSON), overview.ScanID)

	require.NoError(t, clientToServerW.Close())
	require.NoError(t, <-done)
}

func TestMCPStreamableHTTPTransport(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	srv := NewServer(db, "test-http")
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	// POST initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`
	resp, err := http.Post(ts.URL, "application/json", bytes.NewBufferString(initBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Mcp-Session-Id"))

	var rpcResp Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rpcResp))
	assert.Nil(t, rpcResp.Error)

	// POST notification -> 202 Accepted
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	resp2, err := http.Post(ts.URL, "application/json", bytes.NewBufferString(notifBody))
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusAccepted, resp2.StatusCode)

	// DELETE session -> 204 No Content
	delReq, err := http.NewRequest(http.MethodDelete, ts.URL, nil)
	require.NoError(t, err)
	resp3, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp3.StatusCode)
}
