package sdk

import (
	"bytes"
	"context"
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

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createSDKTestGitServer(t *testing.T, filename, content, requiredToken string) *httptest.Server {
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

func TestSDKScanPathWithReport_AuthAndFailure(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	const token = "sdk-test-token"
	secretLine := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	srv := createSDKTestGitServer(t, "app.py", secretLine, token)
	defer srv.Close()

	repoURL := srv.URL + "/org/sdk-repo.git"

	// 1. Unauthenticated ScanGitRepo must return an error, not ([]Finding{}, nil)
	unauthOpts := DefaultOptions()
	unauthOpts.CloneBaseDir = t.TempDir()
	unauthOpts.AuthResolver = &gitutils.ChainedAuthResolver{DisableEnv: true}
	unauthScanner := NewScanner(unauthOpts)
	if _, err := unauthScanner.ScanGitRepo(context.Background(), repoURL); err == nil {
		t.Fatalf("expected ScanGitRepo to return error on unauthorized repo")
	}

	// 2. Authenticated ScanPathWithReport succeeds and finds the secret
	authOpts := DefaultOptions()
	authOpts.CloneBaseDir = t.TempDir()
	authOpts.GitAuth = &gitutils.GitAuth{User: "checkmate", Credential: token}
	authScanner := NewScanner(authOpts)

	rep, err := authScanner.ScanPathWithReport(context.Background(), repoURL)
	if err != nil {
		t.Fatalf("ScanPathWithReport with auth failed: %v", err)
	}
	if rep.Acquisition.Succeeded != 1 || rep.Acquisition.Failed != 0 {
		t.Fatalf("unexpected acquisition report: %+v", rep.Acquisition)
	}
	if len(rep.Findings) == 0 {
		t.Fatalf("expected findings from authenticated SDK scan")
	}
}
