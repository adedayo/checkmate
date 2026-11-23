package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
)

type lspTestHarness struct {
	t      *testing.T
	inW    *io.PipeWriter
	outR   *bufio.Reader
	doneCh chan struct {
		code int
		err  error
	}
}

func startLSPHarness(t *testing.T, opts ServerOptions) *lspTestHarness {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	srv := NewServer(opts)
	doneCh := make(chan struct {
		code int
		err  error
	}, 1)

	go func() {
		code, err := srv.Serve(context.Background(), inR, outW)
		_ = outW.Close()
		doneCh <- struct {
			code int
			err  error
		}{code: code, err: err}
	}()

	h := &lspTestHarness{
		t:      t,
		inW:    inW,
		outR:   bufio.NewReader(outR),
		doneCh: doneCh,
	}
	t.Cleanup(func() {
		_ = inW.Close()
		_ = inR.Close()
		_ = outR.Close()
	})
	return h
}

func (h *lspTestHarness) send(msg interface{}) {
	h.t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		h.t.Fatalf("marshal msg: %v", err)
	}
	frame := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	if _, err := io.WriteString(h.inW, frame); err != nil {
		h.t.Fatalf("write frame: %v", err)
	}
}

func (h *lspTestHarness) readRaw(timeout time.Duration) []byte {
	h.t.Helper()
	type res struct {
		data []byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		b, err := readMessage(h.outR)
		ch <- res{data: b, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatalf("readMessage: %v", r.err)
		}
		return r.data
	case <-time.After(timeout):
		h.t.Fatalf("timed out waiting for LSP message after %v", timeout)
		return nil
	}
}

func (h *lspTestHarness) readUntilMethod(method string, timeout time.Duration) json.RawMessage {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw := h.readRaw(time.Until(deadline))
		var env struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(raw, &env); err == nil && env.Method == method {
			return env.Params
		}
	}
	h.t.Fatalf("did not receive %s within %v", method, timeout)
	return nil
}

func (h *lspTestHarness) readResponseID(wantID int, timeout time.Duration) RPCResponse {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	wantStr := fmt.Sprintf("%d", wantID)
	for time.Now().Before(deadline) {
		raw := h.readRaw(time.Until(deadline))
		var resp RPCResponse
		if err := json.Unmarshal(raw, &resp); err == nil && string(resp.ID) == wantStr {
			return resp
		}
	}
	h.t.Fatalf("did not receive response id=%d within %v", wantID, timeout)
	return RPCResponse{}
}

func TestConvertConfidenceCriticalMapsToError(t *testing.T) {
	if got := convertConfidence(diagnostics.Critical); got != SeverityError {
		t.Fatalf("Critical mapped to %d, want SeverityError (1)", got)
	}
	if got := convertConfidence(diagnostics.High); got != SeverityError {
		t.Fatalf("High mapped to %d, want SeverityError (1)", got)
	}
	if got := convertConfidence(diagnostics.Medium); got != SeverityWarning {
		t.Fatalf("Medium mapped to %d, want SeverityWarning (2)", got)
	}
	if got := convertConfidence(diagnostics.Low); got != SeverityInformation {
		t.Fatalf("Low mapped to %d, want SeverityInformation (3)", got)
	}
	if got := convertConfidence(diagnostics.Info); got != SeverityHint {
		t.Fatalf("Info mapped to %d, want SeverityHint (4)", got)
	}
}

func TestLSP_InitializeWorkspaceScanAndCleanShutdown(t *testing.T) {
	wsDir := t.TempDir()
	secretFile := filepath.Join(wsDir, "secrets.py")
	if err := os.WriteFile(secretFile, []byte("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	h := startLSPHarness(t, ServerOptions{
		Debounce: 25 * time.Millisecond,
		Version:  "test",
	})

	// 1. initialize
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"workspaceFolders": []map[string]interface{}{
				{"uri": PathToFileURI(wsDir), "name": "ws"},
			},
		},
	})
	initResp := h.readResponseID(1, 5*time.Second)
	if initResp.Error != nil {
		t.Fatalf("initialize error: %+v", initResp.Error)
	}
	rawCap, _ := json.Marshal(initResp.Result)
	var initRes InitializeResult
	if err := json.Unmarshal(rawCap, &initRes); err != nil {
		t.Fatal(err)
	}
	if initRes.Capabilities.TextDocumentSync == nil || initRes.Capabilities.TextDocumentSync.Change != TextDocumentSyncKindFull {
		t.Fatalf("expected Full textDocumentSync capability, got %+v", initRes.Capabilities.TextDocumentSync)
	}
	if initRes.Capabilities.CodeActionProvider == nil || initRes.Capabilities.ExecuteCommandProvider == nil {
		t.Fatalf("expected codeActionProvider and executeCommandProvider capabilities")
	}

	// 2. initialized -> async workspace scan publishes file:// URI diagnostics
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialized",
		"params":  map[string]interface{}{},
	})

	paramsRaw := h.readUntilMethod("textDocument/publishDiagnostics", 5*time.Second)
	var pub PublishDiagnosticsParams
	if err := json.Unmarshal(paramsRaw, &pub); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub.URI, "file://") {
		t.Fatalf("expected file:// URI, got %q", pub.URI)
	}
	if len(pub.Diagnostics) == 0 {
		t.Fatalf("expected workspace scan diagnostic for %s", secretFile)
	}
	if pub.Diagnostics[0].Source != "CheckMate" {
		t.Fatalf("expected source=CheckMate, got %q", pub.Diagnostics[0].Source)
	}
	if pub.Diagnostics[0].Data == nil || pub.Diagnostics[0].Data.FindingID == "" || pub.Diagnostics[0].Data.SecretChecksum == "" {
		t.Fatalf("expected structured Diagnostic.Data, got %+v", pub.Diagnostics[0].Data)
	}

	// 3. shutdown returns null result without calling os.Exit, followed by exit -> code 0
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "shutdown",
	})
	sdResp := h.readResponseID(2, 5*time.Second)
	if sdResp.Error != nil || sdResp.Result != nil {
		t.Fatalf("expected shutdown null result, got %+v", sdResp)
	}

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "exit",
	})
	select {
	case res := <-h.doneCh:
		if res.code != 0 || res.err != nil {
			t.Fatalf("expected clean exit code 0, got code=%d err=%v", res.code, res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for server exit")
	}
}

func TestLSP_ExitWithoutShutdownReturnsOne(t *testing.T) {
	h := startLSPHarness(t, ServerOptions{DisableWorkspaceScan: true})
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "exit",
	})
	select {
	case res := <-h.doneCh:
		if res.code != 1 {
			t.Fatalf("expected exit code 1 when exit sent without shutdown, got %d", res.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for exit")
	}
}

func TestLSP_DidOpenDidChangeDebounceAndClear(t *testing.T) {
	wsDir := t.TempDir()
	docPath := filepath.Join(wsDir, "app.py")
	docURI := PathToFileURI(docPath)

	h := startLSPHarness(t, ServerOptions{
		DisableWorkspaceScan: true,
		Debounce:             60 * time.Millisecond,
	})

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]interface{}{"rootUri": PathToFileURI(wsDir)},
	})
	_ = h.readResponseID(1, 5*time.Second)

	// 1. didOpen with a secret -> diagnostic published
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/didOpen",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{
				"uri":        docURI,
				"languageId": "python",
				"version":    1,
				"text":       "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
			},
		},
	})
	raw := h.readUntilMethod("textDocument/publishDiagnostics", 5*time.Second)
	var pub PublishDiagnosticsParams
	_ = json.Unmarshal(raw, &pub)
	if len(pub.Diagnostics) == 0 {
		t.Fatalf("expected diagnostic on didOpen with secret")
	}

	// 2. Rapid didChange edits collapse via debounce and only final clean version (v4) publishes []
	for v := 2; v <= 3; v++ {
		h.send(map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "textDocument/didChange",
			"params": map[string]interface{}{
				"textDocument":   map[string]interface{}{"uri": docURI, "version": v},
				"contentChanges": []map[string]interface{}{{"text": "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"}},
			},
		})
	}
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/didChange",
		"params": map[string]interface{}{
			"textDocument":   map[string]interface{}{"uri": docURI, "version": 4},
			"contentChanges": []map[string]interface{}{{"text": "aws_access_key_id = os.environ['AWS_KEY']\n"}},
		},
	})

	raw2 := h.readUntilMethod("textDocument/publishDiagnostics", 5*time.Second)
	var pub2 PublishDiagnosticsParams
	_ = json.Unmarshal(raw2, &pub2)
	if pub2.Version == nil || *pub2.Version != 4 {
		t.Fatalf("expected debounced publish for version 4, got %+v", pub2.Version)
	}
	if len(pub2.Diagnostics) != 0 {
		t.Fatalf("expected cleared diagnostics [] after removing secret, got %+v", pub2.Diagnostics)
	}

	// Clean exit
	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 9, "method": "shutdown"})
	_ = h.readResponseID(9, 5*time.Second)
	h.send(map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})
	<-h.doneCh
}

func TestLSP_QuickFixCodeActionPersistsToSQLiteAndClearsDiagnostic(t *testing.T) {
	wsDir := t.TempDir()
	docPath := filepath.Join(wsDir, "config.py")
	docURI := PathToFileURI(docPath)

	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := startLSPHarness(t, ServerOptions{
		Store:                db,
		DisableWorkspaceScan: true,
		Debounce:             25 * time.Millisecond,
	})

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]interface{}{"rootUri": PathToFileURI(wsDir)},
	})
	_ = h.readResponseID(1, 5*time.Second)

	// 1. Open document with secret
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/didOpen",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{
				"uri":        docURI,
				"languageId": "python",
				"version":    1,
				"text":       "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
			},
		},
	})
	raw := h.readUntilMethod("textDocument/publishDiagnostics", 5*time.Second)
	var pub PublishDiagnosticsParams
	_ = json.Unmarshal(raw, &pub)
	if len(pub.Diagnostics) == 0 {
		t.Fatalf("expected diagnostic on didOpen")
	}

	// 2. Request codeAction for the diagnostic
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "textDocument/codeAction",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{"uri": docURI},
			"range":        pub.Diagnostics[0].Range,
			"context": map[string]interface{}{
				"diagnostics": pub.Diagnostics,
			},
		},
	})
	caResp := h.readResponseID(2, 5*time.Second)
	rawActions, _ := json.Marshal(caResp.Result)
	var actions []CodeAction
	if err := json.Unmarshal(rawActions, &actions); err != nil {
		t.Fatal(err)
	}
	if len(actions) < 3 {
		t.Fatalf("expected 3 quickfix actions (pathHash, globalHash, excludeFile), got %d: %+v", len(actions), actions)
	}

	// 3. Execute the first Quick Fix (suppressPathHash)
	chosen := actions[0]
	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "workspace/executeCommand",
		"params": map[string]interface{}{
			"command":   chosen.Command.Command,
			"arguments": chosen.Command.Arguments,
		},
	})

	// Wait for cleared publishDiagnostics (the response to id=3 and the notification may arrive in either order)
	deadline := time.Now().Add(5 * time.Second)
	gotExecResp := false
	gotClearedDiags := false
	for time.Now().Before(deadline) && (!gotExecResp || !gotClearedDiags) {
		msgRaw := h.readRaw(time.Until(deadline))
		var env struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(msgRaw, &env)
		if string(env.ID) == "3" {
			gotExecResp = true
		}
		if env.Method == "textDocument/publishDiagnostics" {
			var p PublishDiagnosticsParams
			_ = json.Unmarshal(env.Params, &p)
			if p.URI == docURI && len(p.Diagnostics) == 0 {
				gotClearedDiags = true
			}
		}
	}
	if !gotExecResp {
		t.Fatalf("missing executeCommand response")
	}
	if !gotClearedDiags {
		t.Fatalf("expected open document diagnostics to clear to [] after Quick Fix")
	}

	// Verify exception was persisted in SQLite with no plaintext secret
	summaries := db.ListProjectSummaries()
	if len(summaries) == 0 {
		t.Fatalf("expected SQLite project created for workspace")
	}
	excs, err := db.ListExceptions(summaries[0].ID)
	if err != nil || len(excs) == 0 {
		t.Fatalf("expected persisted SQLite exception, got err=%v excs=%+v", err, excs)
	}
	if excs[0].CreatedBy != "lsp:editor" || excs[0].Scope == nil || excs[0].Scope.Type != "pathHash" {
		t.Fatalf("unexpected persisted exception: %+v", excs[0])
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 4, "method": "shutdown"})
	_ = h.readResponseID(4, 5*time.Second)
	h.send(map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})
	<-h.doneCh
}

func TestLSP_QuickFixPersistsToYAMLWhenNoDB(t *testing.T) {
	wsDir := t.TempDir()
	docPath := filepath.Join(wsDir, "yaml_test.py")
	docURI := PathToFileURI(docPath)

	h := startLSPHarness(t, ServerOptions{
		Store:                nil, // --no-db mode
		DisableWorkspaceScan: true,
		Debounce:             25 * time.Millisecond,
	})

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]interface{}{"rootUri": PathToFileURI(wsDir)},
	})
	_ = h.readResponseID(1, 5*time.Second)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/didOpen",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{
				"uri":        docURI,
				"languageId": "python",
				"version":    1,
				"text":       "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
			},
		},
	})
	raw := h.readUntilMethod("textDocument/publishDiagnostics", 5*time.Second)
	var pub PublishDiagnosticsParams
	_ = json.Unmarshal(raw, &pub)
	if len(pub.Diagnostics) == 0 {
		t.Fatalf("expected diagnostic")
	}

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "workspace/executeCommand",
		"params": map[string]interface{}{
			"command": CmdSuppressGlobalHash,
			"arguments": []interface{}{
				quickFixCommandArg{
					URI:            docURI,
					FilePath:       docPath,
					SecretChecksum: pub.Diagnostics[0].Data.SecretChecksum,
					RuleID:         pub.Diagnostics[0].Data.RuleID,
				},
			},
		},
	})
	_ = h.readResponseID(2, 5*time.Second)

	yamlBytes, err := os.ReadFile(filepath.Join(wsDir, ".checkmate.yaml"))
	if err != nil {
		t.Fatalf("expected .checkmate.yaml created in --no-db mode: %v", err)
	}
	if !strings.Contains(string(yamlBytes), pub.Diagnostics[0].Data.SecretChecksum) {
		t.Fatalf("expected secret checksum in .checkmate.yaml, got:\n%s", string(yamlBytes))
	}
	if strings.Contains(string(yamlBytes), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("plaintext secret must never be written to .checkmate.yaml!")
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "shutdown"})
	_ = h.readResponseID(3, 5*time.Second)
	h.send(map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})
	<-h.doneCh
}
