package precommit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
)

const (
	testGitHubToken = "ghp_0123456789abcdef0123456789abcdef0123"
	testGitLabToken = "glpat-AbCdEfGhIjKlMnOpQrSt"
	testMySQLURI    = "mysql://root:Sup3rS3cretP@ss@127.0.0.1:3306/prod"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=CheckMate Test",
		"GIT_AUTHOR_EMAIL=test@checkmate.local",
		"GIT_COMMITTER_NAME=CheckMate Test",
		"GIT_COMMITTER_EMAIL=test@checkmate.local",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return string(out)
}

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestScanStaged_EmptyFastPath(t *testing.T) {
	repo := initTestRepo(t)
	res, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:  repo,
		DiffOnly: true,
	})
	if err != nil {
		t.Fatalf("ScanStaged on empty repo failed: %v", err)
	}
	if res.FilesScanned != 0 || len(res.Diagnostics) != 0 {
		t.Fatalf("expected 0 files and 0 findings, got files=%d findings=%d", res.FilesScanned, len(res.Diagnostics))
	}
}

func TestScanStaged_InitialCommitAndModernExtensions(t *testing.T) {
	repo := initTestRepo(t)

	// Unborn HEAD (before first commit): test .env, .env.local, .tfvars, .toml, .tsx, id_ed25519
	writeFile(t, filepath.Join(repo, ".env"), "DATABASE_URL="+testMySQLURI+"\n")
	writeFile(t, filepath.Join(repo, ".env.local"), "GITHUB_TOKEN="+testGitHubToken+"\n")
	writeFile(t, filepath.Join(repo, "infra/secrets.tfvars"), fmt.Sprintf("gitlab_token = %q\n", testGitLabToken))
	writeFile(t, filepath.Join(repo, "config.toml"), fmt.Sprintf("token = %q\n", testGitHubToken))
	writeFile(t, filepath.Join(repo, "web/App.tsx"), fmt.Sprintf("const apiToken = %q;\n", testGitHubToken))
	writeFile(t, filepath.Join(repo, "keys/id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef123456\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFile(t, filepath.Join(repo, "keys/id_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKey user@host\n")
	writeFile(t, filepath.Join(repo, "certs/keystore.p12"), "binary-p12-placeholder")
	// Root-relative package-lock.json must be excluded by default common exclusions.
	writeFile(t, filepath.Join(repo, "package-lock.json"), fmt.Sprintf(`{"token": %q}`+"\n", testGitHubToken))

	runGit(t, repo, "add", ".")

	res, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions: &ExclusionOptions{
			AutoDiscover: true,
			NoDB:         true,
		},
	})
	if err != nil {
		t.Fatalf("ScanStaged failed: %v", err)
	}

	byFile := map[string][]*diagnostics.SecurityDiagnostic{}
	for _, d := range res.Diagnostics {
		if d.Location != nil {
			byFile[*d.Location] = append(byFile[*d.Location], d)
		}
	}

	for _, mustFind := range []string{
		".env",
		".env.local",
		"infra/secrets.tfvars",
		"config.toml",
		"web/App.tsx",
		"keys/id_ed25519",
		"certs/keystore.p12",
	} {
		if len(byFile[mustFind]) == 0 {
			t.Errorf("expected finding in staged %s, got none", mustFind)
		}
	}

	if len(byFile["package-lock.json"]) != 0 {
		t.Errorf("expected root-relative package-lock.json to be excluded, got %d findings", len(byFile["package-lock.json"]))
	}

	// Verify id_ed25519.pub is Info (filtered out by Medium threshold) while id_ed25519 is Critical.
	filtered := FilterByConfidence(res.Diagnostics, diagnostics.Medium, false)
	for _, d := range filtered {
		if d.Location != nil && *d.Location == "keys/id_ed25519.pub" {
			t.Errorf("expected public key keys/id_ed25519.pub to be filtered out at Medium threshold, got confidence %s",
				d.Justification.Headline.Confidence)
		}
	}
}

func TestScanStaged_IndexVsWorkingTreeDivergence(t *testing.T) {
	repo := initTestRepo(t)

	// Initial clean commit.
	writeFile(t, filepath.Join(repo, "app.go"), "package app\n\nconst name = \"hello\"\n")
	runGit(t, repo, "add", "app.go")
	runGit(t, repo, "commit", "-q", "-m", "initial")

	// Case 1: Secret staged in index, then removed from working tree -> MUST still be caught.
	writeFile(t, filepath.Join(repo, "app.go"), fmt.Sprintf("package app\n\nconst token = %q\n", testGitHubToken))
	runGit(t, repo, "add", "app.go")
	writeFile(t, filepath.Join(repo, "app.go"), "package app\n\nconst name = \"cleaned in working tree\"\n")

	res, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged failed: %v", err)
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("expected staged secret to be caught even after removal from working tree")
	}

	// Case 2: Clean staged change, secret only in unstaged working tree -> MUST NOT trigger.
	writeFile(t, filepath.Join(repo, "app.go"), "package app\n\nconst name = \"clean staged\"\n")
	runGit(t, repo, "add", "app.go")
	writeFile(t, filepath.Join(repo, "app.go"), fmt.Sprintf("package app\n\nconst token = %q\n", testGitHubToken))

	res2, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged failed: %v", err)
	}
	if len(res2.Diagnostics) != 0 {
		t.Fatalf("expected unstaged working-tree secret NOT to trigger staged scan, got %d findings", len(res2.Diagnostics))
	}
}

func TestScanStaged_DiffOnlyIgnoresUntouchedLegacySecret(t *testing.T) {
	repo := initTestRepo(t)

	// Pre-existing legacy secret on line 3.
	legacy := fmt.Sprintf("package app\n\nconst legacyToken = %q\nconst x = 1\nconst y = 2\n", testGitHubToken)
	writeFile(t, filepath.Join(repo, "legacy.go"), legacy)
	runGit(t, repo, "add", "legacy.go")
	runGit(t, repo, "commit", "-q", "-m", "legacy commit")

	// Modify only line 6 with clean code.
	updated := legacy + "const z = 3\n"
	writeFile(t, filepath.Join(repo, "legacy.go"), updated)
	runGit(t, repo, "add", "legacy.go")

	diffRes, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged(diffOnly=true) failed: %v", err)
	}
	if len(diffRes.Diagnostics) != 0 {
		t.Fatalf("expected diff-only scan to ignore untouched legacy line, got %d findings", len(diffRes.Diagnostics))
	}

	// Full staged file mode MUST catch line 3.
	fullRes, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          false,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged(diffOnly=false) failed: %v", err)
	}
	if len(fullRes.Diagnostics) == 0 {
		t.Fatalf("expected full staged scan to detect pre-existing secret on line 3")
	}

	// Now add a NEW secret on line 7 -> diff-only MUST catch line 7 (and only line 7).
	withNew := updated + fmt.Sprintf("const newToken = %q\n", testGitLabToken)
	writeFile(t, filepath.Join(repo, "legacy.go"), withNew)
	runGit(t, repo, "add", "legacy.go")

	newRes, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged(new secret) failed: %v", err)
	}
	if len(newRes.Diagnostics) != 1 {
		t.Fatalf("expected exactly 1 finding for newly added line, got %d", len(newRes.Diagnostics))
	}
	if newRes.Diagnostics[0].Range.Start.Line+1 != 7 {
		t.Fatalf("expected finding on 1-based line 7, got %d", newRes.Diagnostics[0].Range.Start.Line+1)
	}
}

func TestInlineIgnoreAndCheckmateYAMLHashes(t *testing.T) {
	repo := initTestRepo(t)

	// Test both inline suppression forms alongside an unsuppressed secret.
	content := strings.Join([]string{
		"package cfg",
		fmt.Sprintf("const ignoredSameLine = %q // checkmate:ignore", testGitHubToken),
		"// checkmate:ignore-next-line",
		fmt.Sprintf("const ignoredNextLine = %q", testGitLabToken),
		fmt.Sprintf("const hashSuppressed = %q", testGitHubToken),
	}, "\n") + "\n"
	writeFile(t, filepath.Join(repo, "cfg.go"), content)
	runGit(t, repo, "add", "cfg.go")

	// First scan without .checkmate.yaml: only line 5 should surface.
	res1, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged failed: %v", err)
	}
	if len(res1.Diagnostics) != 1 {
		t.Fatalf("expected 1 finding (lines 2 and 4 ignored inline), got %d", len(res1.Diagnostics))
	}
	if res1.Diagnostics[0].Range.Start.Line+1 != 5 {
		t.Fatalf("expected finding on line 5, got line %d", res1.Diagnostics[0].Range.Start.Line+1)
	}
	if res1.Diagnostics[0].SHA256 == nil || *res1.Diagnostics[0].SHA256 == "" {
		t.Fatalf("expected SHA256 checksum on finding")
	}

	// Suppress line 5 via auto-discovered repo-root .checkmate.yaml PerFileExcludedHashes
	// (this also verifies secrets.MergeExclusions preserves PerFileExcludedHashes!).
	hash := *res1.Diagnostics[0].SHA256
	yamlCfg := fmt.Sprintf("PerFileExcludedHashes:\n  cfg.go:\n    - %s\n", hash)
	writeFile(t, filepath.Join(repo, ".checkmate.yaml"), yamlCfg)

	res2, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions:  &ExclusionOptions{AutoDiscover: true, NoDB: true},
	})
	if err != nil {
		t.Fatalf("ScanStaged with .checkmate.yaml failed: %v", err)
	}
	if len(res2.Diagnostics) != 0 {
		t.Fatalf("expected 0 findings after .checkmate.yaml PerFileExcludedHashes suppression, got %d", len(res2.Diagnostics))
	}
}

func TestReadOnlySQLiteExceptions(t *testing.T) {
	repo := initTestRepo(t)
	dataDir := t.TempDir()

	// Create a real SQLite DB with an active globalHash exception.
	db, err := sqlite.New(dataDir)
	if err != nil {
		t.Fatalf("sqlite.New failed: %v", err)
	}
	_, err = db.CreateProject(projects.ProjectDescription{
		Name:      "test-repo",
		Workspace: "default",
		Repositories: []projects.Repository{
			{Location: repo, LocationType: "filesystem"},
		},
	})
	if err != nil {
		t.Fatalf("CreateProject failed: %v", err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(testGitHubToken)))
	if err := db.CreateException(&store.Exception{
		ID:            "exc_test_precommit",
		ProjectID:     "",
		RuleID:        "*",
		Scope:         &store.ExceptionScopeDetail{Type: "globalHash", SecretChecksum: sum},
		Reason:        "false_positive_pattern",
		Justification: "test fixture",
		CreatedBy:     "test",
		Status:        "active",
	}); err != nil {
		t.Fatalf("CreateException failed: %v", err)
	}
	_ = db.Close()

	writeFile(t, filepath.Join(repo, "app.go"), fmt.Sprintf("package app\nconst tok = %q\n", testGitHubToken))
	runGit(t, repo, "add", "app.go")

	res, err := ScanStaged(context.Background(), StagedScanOptions{
		WorkDir:           repo,
		DiffOnly:          true,
		ShowSource:        true,
		CalculateChecksum: true,
		ExclusionOptions: &ExclusionOptions{
			AutoDiscover: true,
			DataPath:     dataDir,
			NoDB:         false,
		},
	})
	if err != nil {
		t.Fatalf("ScanStaged with SQLite DB failed: %v", err)
	}
	if len(res.Diagnostics) != 0 {
		t.Fatalf("expected SQLite globalHash exception to suppress finding, got %d findings", len(res.Diagnostics))
	}
}

func TestScanReader_StdinEnv(t *testing.T) {
	excl, err := LoadExclusions(ExclusionOptions{NoDB: true})
	if err != nil {
		t.Fatalf("LoadExclusions failed: %v", err)
	}
	res, err := ScanReader(context.Background(), strings.NewReader("GITHUB_TOKEN="+testGitHubToken+"\n"), ReaderScanOptions{
		Filename:          ".env",
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        excl,
	})
	if err != nil {
		t.Fatalf("ScanReader failed: %v", err)
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("expected finding from stdin .env content")
	}
}

func TestFormatAndRedaction(t *testing.T) {
	if got := RedactSecret("short"); got != "****" {
		t.Errorf("RedactSecret(short) = %q, want ****", got)
	}
	if got := RedactSecret("0123456789"); got != "01****89" {
		t.Errorf("RedactSecret(10 chars) = %q, want 01****89", got)
	}
	if got := RedactSecret(testGitHubToken); got != "ghp_****0123" {
		t.Errorf("RedactSecret(ghp token) = %q, want ghp_****0123", got)
	}

	loc := ".env"
	src := testGitHubToken
	sha := "abcdef123456"
	diags := []*diagnostics.SecurityDiagnostic{
		{
			Location: &loc,
			Source:   &src,
			SHA256:   &sha,
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{Description: "GitHub Token", Confidence: diagnostics.Critical},
			},
		},
	}
	RedactDiagnostics(diags)
	if *diags[0].Source != "ghp_****0123" {
		t.Fatalf("expected redacted source, got %q", *diags[0].Source)
	}
	if *diags[0].SHA256 != sha {
		t.Fatalf("expected SHA256 preserved after redaction")
	}

	var buf bytes.Buffer
	if err := WriteTextReport(&buf, diags, TextReportOptions{
		HookMode:     true,
		FilesScanned: 1,
		ScopeLabel:   "staged file(s)",
	}); err != nil {
		t.Fatalf("WriteTextReport failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, testGitHubToken) {
		t.Fatalf("raw secret leaked into text report: %s", out)
	}
	if !strings.Contains(out, "ghp_****0123") || !strings.Contains(out, sha) {
		t.Fatalf("expected redacted match and sha256 in text report, got:\n%s", out)
	}
}

func TestInstallAndUninstallHook(t *testing.T) {
	repo := initTestRepo(t)

	// Install into default .git/hooks/pre-commit.
	hookPath, err := InstallHook(context.Background(), repo, false)
	if err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat installed hook: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("expected installed hook to be executable, mode=%v", info.Mode())
	}

	// Re-installing over our own CheckMate-managed hook succeeds idempotently.
	if _, err := InstallHook(context.Background(), repo, false); err != nil {
		t.Fatalf("idempotent InstallHook failed: %v", err)
	}

	// Uninstall succeeds for CheckMate-managed hook.
	if _, err := UninstallHook(context.Background(), repo); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("expected hook to be removed")
	}

	// Existing non-CheckMate hook must not be overwritten without --force, nor removed by uninstall.
	writeFile(t, hookPath, "#!/bin/sh\necho custom hook\n")
	if _, err := InstallHook(context.Background(), repo, false); err == nil {
		t.Fatalf("expected InstallHook without force to refuse overwriting unmanaged hook")
	}
	if _, err := UninstallHook(context.Background(), repo); err == nil {
		t.Fatalf("expected UninstallHook to refuse removing unmanaged hook")
	}
	if _, err := InstallHook(context.Background(), repo, true); err != nil {
		t.Fatalf("expected InstallHook with force=true to overwrite unmanaged hook: %v", err)
	}
}

func TestMergeExclusionsPreservesHashes(t *testing.T) {
	a := diagnostics.ExcludeDefinition{
		GloballyExcludedHashes: []string{"h1", "h2"},
		PerFileExcludedHashes:  map[string][]string{"a.go": {"fh1"}},
	}
	b := diagnostics.ExcludeDefinition{
		GloballyExcludedHashes: []string{"h2", "h3"},
		PerFileExcludedHashes:  map[string][]string{"a.go": {"fh1", "fh2"}, "b.go": {"fh3"}},
	}
	merged := secrets.MergeExclusions(a, b)
	if len(merged.GloballyExcludedHashes) != 3 {
		t.Fatalf("expected 3 merged global hashes, got %v", merged.GloballyExcludedHashes)
	}
	if len(merged.PerFileExcludedHashes["a.go"]) != 2 || len(merged.PerFileExcludedHashes["b.go"]) != 1 {
		t.Fatalf("unexpected merged per-file hashes: %v", merged.PerFileExcludedHashes)
	}
}
