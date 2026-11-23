package secrets

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

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createTestSmartHTTPServer(t *testing.T, filename, content, requiredToken string) *httptest.Server {
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

func TestSearchSecretsOnPathsWithReport_AuthAndKeepCheckouts(t *testing.T) {
	const token = "my-private-token"
	secretLine := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	srv := createTestSmartHTTPServer(t, "config.py", secretLine, token)
	defer srv.Close()

	repoURL := srv.URL + "/team/private-repo.git"

	// 1. Without auth: fails with AcqErrAuth and Succeeded=0, Failed=1
	diagsCh, pathsCh, repCh := SearchSecretsOnPathsWithReport(
		context.Background(),
		[]string{repoURL},
		SecretSearchOptions{
			CloneBaseDir:      t.TempDir(),
			CalculateChecksum: true,
			Exclusions:        diagnostics.MakeEmptyExcludes(),
			AuthResolver:      &gitutils.ChainedAuthResolver{DisableEnv: true},
		},
		"", "", nil,
	)
	for range diagsCh {
	}
	<-pathsCh
	rep := <-repCh
	if rep.Attempted != 1 || rep.Succeeded != 0 || rep.Failed != 1 {
		t.Fatalf("unexpected report without auth: %+v", rep)
	}
	if len(rep.Failures) != 1 || rep.Failures[0].ErrorKind != gitutils.AcqErrAuth {
		t.Fatalf("expected AcqErrAuth failure, got %+v", rep.Failures)
	}

	// 2. With auth + KeepCheckouts=true: succeeds, detects secret, preserves checkout on disk
	keepBase := t.TempDir()
	diagsCh, pathsCh, repCh = SearchSecretsOnPathsWithReport(
		context.Background(),
		[]string{repoURL},
		SecretSearchOptions{
			CloneBaseDir:      keepBase,
			CalculateChecksum: true,
			KeepCheckouts:     true,
			Exclusions:        diagnostics.MakeEmptyExcludes(),
			AuthResolver: &gitutils.ChainedAuthResolver{
				ExplicitAuth: &gitutils.GitAuth{User: "checkmate", Credential: token},
				DisableEnv:   true,
			},
		},
		"", "", nil,
	)
	var found []*diagnostics.SecurityDiagnostic
	for d := range diagsCh {
		found = append(found, d)
	}
	<-pathsCh
	rep = <-repCh
	if rep.Succeeded != 1 || rep.Failed != 0 {
		t.Fatalf("expected authenticated scan to succeed, got %+v", rep)
	}
	if len(found) == 0 {
		t.Fatalf("expected at least 1 finding from private repo")
	}
	retainedDir := rep.RetainedPaths[repoURL]
	if retainedDir == "" {
		t.Fatalf("expected RetainedPaths to contain %s, got %+v", repoURL, rep.RetainedPaths)
	}
	if _, err := os.Stat(filepath.Join(retainedDir, "config.py")); err != nil {
		t.Fatalf("expected retained checkout file to exist on disk: %v", err)
	}

	// 3. Partial failure: 1 good local dir + 1 unauthorized remote repo
	localDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(localDir, "local.py"), []byte(secretLine), 0600); err != nil {
		t.Fatal(err)
	}
	diagsCh, pathsCh, repCh = SearchSecretsOnPathsWithReport(
		context.Background(),
		[]string{localDir, repoURL},
		SecretSearchOptions{
			CloneBaseDir:      t.TempDir(),
			CalculateChecksum: true,
			Exclusions:        diagnostics.MakeEmptyExcludes(),
			AuthResolver:      &gitutils.ChainedAuthResolver{DisableEnv: true},
		},
		"", "", nil,
	)
	var partialFound []*diagnostics.SecurityDiagnostic
	for d := range diagsCh {
		partialFound = append(partialFound, d)
	}
	<-pathsCh
	rep = <-repCh
	if rep.Attempted != 2 || rep.Succeeded != 1 || rep.Failed != 1 {
		t.Fatalf("expected partial failure report (attempted=2, succeeded=1, failed=1), got %+v", rep)
	}
	if len(partialFound) == 0 {
		t.Fatalf("expected healthy local target to still yield findings despite remote failure")
	}
}
