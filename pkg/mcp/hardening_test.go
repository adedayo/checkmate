package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/store/sqlite"
	"github.com/adedayo/checkmate/pkg/triage"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func newTestMCPServer(t *testing.T) (*Server, *sqlite.DB) {
	t.Helper()
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	srv := NewServer(db, "test")
	t.Cleanup(func() {
		srv.Close()
		_ = db.Close()
	})
	return srv, db
}

func createMCPTestGitServer(t *testing.T, filename, content, requiredToken string) *httptest.Server {
	t.Helper()
	bareDir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := git.PlainInit(bareDir, true); err != nil {
		t.Fatalf("init bare: %v", err)
	}
	workDir := filepath.Join(t.TempDir(), "work")
	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("init work: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, filename), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	_, _ = wt.Add(filename)
	_, _ = wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "Tester", Email: "t@example.com", When: time.Now()},
	})
	cmd := exec.Command("git", "-C", workDir, "push", bareDir, "HEAD:refs/heads/master")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("push: %v: %s", err, string(out))
	}
	_ = os.WriteFile(filepath.Join(bareDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0600)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requiredToken != "" {
			_, pass, ok := r.BasicAuth()
			if !ok || pass != requiredToken {
				w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/info/refs") && r.URL.Query().Get("service") == "git-upload-pack" {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			cmd := exec.Command("git", "upload-pack", "--stateless-rpc", "--advertise-refs", bareDir)
			out, _ := cmd.Output()
			pkt := "# service=git-upload-pack\n"
			_, _ = fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
			_, _ = w.Write(out)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			reqBody, _ := io.ReadAll(r.Body)
			cmd := exec.Command("git", "upload-pack", "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(reqBody)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			_ = cmd.Run()
			_, _ = w.Write(stdout.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
}

func TestStdioProgressNotificationsAndAsyncScan(t *testing.T) {
	srv, _ := newTestMCPServer(t)

	targetDir := t.TempDir()
	for i := 0; i < 5; i++ {
		fname := filepath.Join(targetDir, fmt.Sprintf("f%d.py", i))
		body := fmt.Sprintf("aws_access_key_id = \"AKIAIOSFODNN7EXAMPL%d\"\n", i)
		if err := os.WriteFile(fname, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Synchronous checkmate_scan with _meta.progressToken over stdio pipe
	reqLine, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "checkmate_scan",
			"arguments": map[string]interface{}{"targets": []string{targetDir}},
			"_meta":     map[string]interface{}{"progressToken": "scan-tok-1"},
		},
	})
	var outBuf bytes.Buffer
	if err := srv.ServeStdio(context.Background(), bytes.NewReader(append(reqLine, '\n')), &outBuf); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	progressCount := 0
	gotFinalResp := false
	for _, line := range lines {
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("invalid json line %q: %v", line, err)
		}
		if msg["method"] == "notifications/progress" {
			progressCount++
			params, _ := msg["params"].(map[string]interface{})
			if params["progressToken"] != "scan-tok-1" {
				t.Errorf("unexpected progressToken: %v", params["progressToken"])
			}
		} else if msg["id"] != nil {
			gotFinalResp = true
		}
	}
	if progressCount == 0 {
		t.Fatalf("expected at least 1 notifications/progress frame over stdio, got 0 (output=%s)", outBuf.String())
	}
	if !gotFinalResp {
		t.Fatalf("expected final JSON-RPC response")
	}

	// 2. Async checkmate_scan + checkmate_get_scan_status polling
	asyncReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "checkmate_scan",
			"arguments": map[string]interface{}{
				"targets": []string{targetDir},
				"async":   true,
			},
		},
	})
	respBytes, hasResp := srv.HandleMessage(context.Background(), asyncReq)
	if !hasResp {
		t.Fatalf("expected async response")
	}
	var rpcResp struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		t.Fatal(err)
	}
	var startStatus triage.ScanStatus
	if err := json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &startStatus); err != nil {
		t.Fatal(err)
	}
	if startStatus.ScanID == "" {
		t.Fatalf("expected scanId from async checkmate_scan")
	}

	deadline := time.Now().Add(10 * time.Second)
	var finalStatus triage.ScanStatus
	for time.Now().Before(deadline) {
		pollReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      3,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      "checkmate_get_scan_status",
				"arguments": map[string]interface{}{"scanId": startStatus.ScanID},
			},
		})
		pb, _ := srv.HandleMessage(context.Background(), pollReq)
		var pr struct {
			Result CallToolResult `json:"result"`
		}
		_ = json.Unmarshal(pb, &pr)
		_ = json.Unmarshal([]byte(pr.Result.Content[0].Text), &finalStatus)
		if finalStatus.Status == "complete" || finalStatus.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if finalStatus.Status != "complete" || finalStatus.Overview == nil {
		t.Fatalf("expected async scan to reach complete with overview, got %+v", finalStatus)
	}
}

func TestListFindingsAndSamplesPerGroup(t *testing.T) {
	srv, _ := newTestMCPServer(t)

	targetDir := t.TempDir()
	var sb strings.Builder
	// 12 distinct AWS access key patterns in a single file
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&sb, "key_%02d = \"AKIAIOSFODNN7EXA%04d\"\n", i, 1000+i)
	}
	denseFile := filepath.Join(targetDir, "dense.py")
	if err := os.WriteFile(denseFile, []byte(sb.String()), 0600); err != nil {
		t.Fatal(err)
	}

	ov, err := srv.triage.Scan(context.Background(), triage.ScanRequest{Targets: []string{targetDir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if ov.RawFindings < 12 {
		t.Fatalf("expected at least 12 findings, got %d", ov.RawFindings)
	}

	// Default samplesPerGroup = 5
	wlDefault, err := srv.triage.GetWorklist(context.Background(), triage.WorklistRequest{
		ScanID:  ov.ScanID,
		GroupBy: "file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wlDefault.Groups) != 1 || len(wlDefault.Groups[0].SampleLocations) != 5 {
		t.Fatalf("expected default 5 sample locations, got %+v", wlDefault.Groups)
	}

	// Widened samplesPerGroup = 15 returns all 12
	wlWide, err := srv.triage.GetWorklist(context.Background(), triage.WorklistRequest{
		ScanID:          ov.ScanID,
		GroupBy:         "file",
		SamplesPerGroup: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wlWide.Groups[0].SampleLocations) < 12 {
		t.Fatalf("expected >=12 sample locations with samplesPerGroup=15, got %d", len(wlWide.Groups[0].SampleLocations))
	}

	// Paginate all findings via checkmate_list_findings tool
	collected := 0
	offset := 0
	for {
		callReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      10 + offset,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "checkmate_list_findings",
				"arguments": map[string]interface{}{
					"scanId": ov.ScanID,
					"file":   denseFile,
					"limit":  5,
					"offset": offset,
				},
			},
		})
		rb, _ := srv.HandleMessage(context.Background(), callReq)
		var pr struct {
			Result CallToolResult `json:"result"`
		}
		if err := json.Unmarshal(rb, &pr); err != nil {
			t.Fatal(err)
		}
		var page triage.ListFindingsResult
		if err := json.Unmarshal([]byte(pr.Result.Content[0].Text), &page); err != nil {
			t.Fatal(err)
		}
		collected += len(page.Findings)
		if !page.HasMore {
			break
		}
		offset = page.NextOffset
	}
	if collected < 12 {
		t.Fatalf("expected to paginate >=12 findings via checkmate_list_findings, got %d", collected)
	}
}

func TestRemoteCheckoutKeepContextCleanupAndFailure(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	srv, _ := newTestMCPServer(t)

	body := "# line 1\n# line 2\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n# line 4\n"
	gitSrv := createMCPTestGitServer(t, "secrets.py", body, "")
	defer gitSrv.Close()
	repoURL := gitSrv.URL + "/org/remote-demo.git"

	// 1. Scan remote repo with keepCheckout=true
	scanReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "checkmate_scan",
			"arguments": map[string]interface{}{
				"targets":      []string{repoURL},
				"keepCheckout": true,
			},
		},
	})
	rb, _ := srv.HandleMessage(context.Background(), scanReq)
	var scanResp struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.Unmarshal(rb, &scanResp); err != nil {
		t.Fatal(err)
	}
	if scanResp.Result.IsError {
		t.Fatalf("expected successful remote scan, got error: %s", scanResp.Result.Content[0].Text)
	}
	var ov triage.ScanOverview
	if err := json.Unmarshal([]byte(scanResp.Result.Content[0].Text), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.LocalCheckoutPath == "" || len(ov.RetainedCheckouts) != 1 {
		t.Fatalf("expected retained checkout path in overview, got %+v", ov)
	}

	// 2. List findings and verify localFile is readable
	listRes, err := srv.triage.ListFindings(context.Background(), triage.ListFindingsRequest{ScanID: ov.ScanID})
	if err != nil || len(listRes.Findings) == 0 {
		t.Fatalf("expected findings from remote scan: err=%v, res=%+v", err, listRes)
	}
	first := listRes.Findings[0]
	if first.LocalFile == "" {
		t.Fatalf("expected localFile to be populated on retained remote finding: %+v", first)
	}
	if _, err := os.Stat(first.LocalFile); err != nil {
		t.Fatalf("expected localFile %s to exist on disk: %v", first.LocalFile, err)
	}

	// 3. Get finding context via MCP tool
	ctxReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "checkmate_get_finding_context",
			"arguments": map[string]interface{}{
				"scanId":      ov.ScanID,
				"findingId":   first.FindingID,
				"beforeLines": 2,
				"afterLines":  2,
			},
		},
	})
	cb, _ := srv.HandleMessage(context.Background(), ctxReq)
	var ctxResp struct {
		Result CallToolResult `json:"result"`
	}
	_ = json.Unmarshal(cb, &ctxResp)
	var ctxRes triage.FindingContextResult
	if err := json.Unmarshal([]byte(ctxResp.Result.Content[0].Text), &ctxRes); err != nil {
		t.Fatal(err)
	}
	if ctxRes.Source != "retained_checkout" || len(ctxRes.Lines) < 3 {
		t.Fatalf("expected retained_checkout context lines, got %+v", ctxRes)
	}

	// 4. Cleanup checkout removes files from disk
	cleanReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "checkmate_cleanup_checkout",
			"arguments": map[string]interface{}{"scanId": ov.ScanID},
		},
	})
	clb, _ := srv.HandleMessage(context.Background(), cleanReq)
	var cleanResp struct {
		Result CallToolResult `json:"result"`
	}
	_ = json.Unmarshal(clb, &cleanResp)
	if cleanResp.Result.IsError {
		t.Fatalf("cleanup failed: %s", cleanResp.Result.Content[0].Text)
	}
	if _, err := os.Stat(first.LocalFile); !os.IsNotExist(err) {
		t.Fatalf("expected retained checkout file to be removed after cleanup")
	}

	// 5. Unauthorized remote repo returns isError: true with acquisition failures
	authSrv := createMCPTestGitServer(t, "secrets.py", body, "secret-token")
	defer authSrv.Close()
	failReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "checkmate_scan",
			"arguments": map[string]interface{}{"targets": []string{authSrv.URL + "/org/locked.git"}},
		},
	})
	fb, _ := srv.HandleMessage(context.Background(), failReq)
	var failResp struct {
		Result CallToolResult `json:"result"`
	}
	_ = json.Unmarshal(fb, &failResp)
	if !failResp.Result.IsError {
		t.Fatalf("expected isError=true when all targets fail acquisition, got: %s", string(fb))
	}
	if !strings.Contains(failResp.Result.Content[0].Text, "auth_failed") {
		t.Fatalf("expected auth_failed in structured error payload, got: %s", failResp.Result.Content[0].Text)
	}
}

func TestStreamableHTTPSSEProgressAndDelete(t *testing.T) {
	srv, _ := newTestMCPServer(t)
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "a.py"), []byte("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	const sessionID = "mcp-test-sse-session"

	// 1. Open GET /v1/mcp SSE stream
	sseReq, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseReq.Header.Set("Mcp-Session-Id", sessionID)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("GET SSE failed: %v", err)
	}
	defer func() { _ = sseResp.Body.Close() }()
	if sseResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on GET SSE, got %d", sseResp.StatusCode)
	}

	reader := bufio.NewReader(sseResp.Body)
	// Read initial ": connected" comment to confirm subscription is live
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "connected") {
		t.Fatalf("expected connected comment, got %q, err=%v", line, err)
	}

	eventsCh := make(chan string, 16)
	sseClosed := make(chan struct{})
	go func() {
		defer close(sseClosed)
		for {
			l, err := reader.ReadString('\n')
			if len(l) > 0 && strings.HasPrefix(l, "data: ") {
				eventsCh <- strings.TrimSpace(strings.TrimPrefix(l, "data: "))
			}
			if err != nil {
				return
			}
		}
	}()

	// 2. Trigger POST /v1/mcp scan with _meta.progressToken using the same session
	postBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      42,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "checkmate_scan",
			"arguments": map[string]interface{}{"targets": []string{targetDir}},
			"_meta":     map[string]interface{}{"progressToken": "sse-tok-42"},
		},
	})
	postReq, _ := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader(postBody))
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Mcp-Session-Id", sessionID)
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST MCP failed: %v", err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on POST, got %d", postResp.StatusCode)
	}

	// 3. Verify notifications/progress arrived over GET SSE stream
	select {
	case ev := <-eventsCh:
		if !strings.Contains(ev, "notifications/progress") || !strings.Contains(ev, "sse-tok-42") {
			t.Fatalf("unexpected SSE event payload: %s", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for SSE progress notification")
	}

	// 4. Close session via DELETE /v1/mcp and verify SSE stream terminates cleanly
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL, nil)
	delReq.Header.Set("Mcp-Session-Id", sessionID)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on DELETE, got %d", delResp.StatusCode)
	}

	select {
	case <-sseClosed:
	case <-time.After(5 * time.Second):
		t.Fatalf("expected SSE stream to close after DELETE /v1/mcp")
	}
}
