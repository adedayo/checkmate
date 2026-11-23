package sqlite

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
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createSmartHTTPGitServer(t *testing.T, filename, content, requiredToken string) *httptest.Server {
	t.Helper()

	bareDir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := git.PlainInit(bareDir, true); err != nil {
		t.Fatalf("init bare repo: %v", err)
	}
	workDir := filepath.Join(t.TempDir(), "work")
	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("init work repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, filename), []byte(content), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add(filename); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "Tester", Email: "t@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
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
			out, err := cmd.Output()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
			if err := cmd.Run(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(stdout.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
}

func TestRunScan_AuthenticatedAndFailedAcquisition(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")

	const token = "sqlite-git-config-token"
	secretLine := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	srv := createSmartHTTPGitServer(t, "secrets.py", secretLine, token)
	defer srv.Close()

	repoURL := srv.URL + "/org/private-app.git"

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	proj, err := db.CreateProject(projects.ProjectDescription{
		Name:      "Private Repo",
		Workspace: "Default",
		Repositories: []projects.Repository{
			{Location: repoURL, LocationType: "git"},
		},
	})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// 1. Without git_config entry: scan MUST be marked 'failed', NOT 'complete' with 0 findings.
	var failedScanID string
	db.RunScan(context.Background(), proj.ID, projects.ScanPolicy{}, nil,
		func(id string) { failedScanID = id }, nil, nil, nil, nil)

	rec, err := db.GetScanRecord(failedScanID)
	if err != nil {
		t.Fatalf("GetScanRecord: %v", err)
	}
	if rec.Status != "failed" {
		t.Fatalf("expected failed scan status when clone fails, got %q", rec.Status)
	}
	acq, err := db.GetScanAcquisitionReport(failedScanID)
	if err != nil {
		t.Fatalf("GetScanAcquisitionReport: %v", err)
	}
	if acq == nil || acq.Failed != 1 || acq.Succeeded != 0 || len(acq.Failures) != 1 || acq.Failures[0].ErrorKind != gitutils.AcqErrAuth {
		t.Fatalf("unexpected acquisition report on failed scan: %+v", acq)
	}

	// 2. Configure git_config with matching InstanceURL: scan succeeds and finds the secret.
	gm, err := db.GetGitConfigManager()
	if err != nil {
		t.Fatalf("GetGitConfigManager: %v", err)
	}
	cfg := &gitutils.GitServiceConfig{
		GitServices: map[gitutils.GitServiceType]map[string]*gitutils.GitService{
			gitutils.GitHub: {
				"corp-gh": {
					ID:          "corp-gh",
					InstanceURL: srv.URL,
					API_Key:     token,
					Type:        gitutils.GitHub,
				},
			},
		},
	}
	if err := gm.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var okScanID string
	db.RunScan(context.Background(), proj.ID, projects.ScanPolicy{}, nil,
		func(id string) { okScanID = id }, nil, nil, nil, nil)

	rec2, err := db.GetScanRecord(okScanID)
	if err != nil {
		t.Fatalf("GetScanRecord(ok): %v", err)
	}
	if rec2.Status != "complete" {
		t.Fatalf("expected complete scan status with git_config auth, got %q", rec2.Status)
	}
	acq2, err := db.GetScanAcquisitionReport(okScanID)
	if err != nil {
		t.Fatalf("GetScanAcquisitionReport(ok): %v", err)
	}
	if acq2 == nil || acq2.Succeeded != 1 || acq2.Failed != 0 {
		t.Fatalf("unexpected acquisition report on ok scan: %+v", acq2)
	}
	findings, err := db.GetScanFindings(okScanID)
	if err != nil {
		t.Fatalf("GetScanFindings: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings from authenticated private repo scan")
	}
}
