package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/precommit"
)

func resetSearchFlags() {
	showSource = true
	calculateChecksum = true
	exclusion = ""
	asJSON = true
	asSARIF = false
	asPDF = false
	runningCommentary = false
	sensitiveFiles = false
	sensitiveFilesOnly = false
	verbose = false
	reportIgnored = false
	generateSampleExclusion = false
	skipTestFiles = false
	gitToken = ""
	gitTokenEnv = ""
	sshKeyPath = ""
	gitDepth = 1
	insecureSkipTLS = false

	searchFormat = ""
	searchFailOnFindings = false
	searchRedact = false
	searchMinConfidence = "info"
	searchStaged = false
	searchDiffOnly = true
	searchStdin = false
	searchFilename = "stdin"
	searchNoAutoExclusion = true
	searchDataPath = "~/.checkmate"
	searchNoDB = true
	searchQuiet = false
	searchNoIgnore = false
	searchTrackedOnly = false
}

func resetHookFlags() {
	hookStaged = false
	hookDiffOnly = true
	hookFormat = "text"
	hookRedact = true
	hookMinConfidence = "medium"
	hookExclusion = ""
	hookNoAutoExclusion = false
	hookDataPath = "~/.checkmate"
	hookNoDB = true
	hookExcludeTests = false
	hookQuiet = false
	hookVerbose = false
	hookNoIgnore = false
	hookTrackedOnly = false
}

func TestRunSearchCommand_FailsOnUnauthenticatedRepo(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	resetSearchFlags()

	code := runSearchCommand(searchCmd, []string{srv.URL + "/org/private.git"})
	if code == 0 {
		t.Fatalf("expected non-zero exit code when all targets fail acquisition, got 0")
	}
}

func TestRunSearchCommand_ExitCodesAndEmptyJSON(t *testing.T) {
	dir := t.TempDir()
	cleanFile := filepath.Join(dir, "clean.go")
	secretFile := filepath.Join(dir, "secret.go")
	const tok = "ghp_0123456789abcdef0123456789abcdef0123"

	if err := os.WriteFile(cleanFile, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(fmt.Sprintf("package main\nconst token = %q\n", tok)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Clean file -> exit 0 and JSON is [] (never null).
	resetSearchFlags()
	searchFailOnFindings = true
	var out, errOut bytes.Buffer
	code := runSearchCommandIO(searchCmd, []string{cleanFile}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 for clean file, got %d (stderr: %s)", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("expected empty JSON array [], got %q", strings.TrimSpace(out.String()))
	}

	// Secret file with --fail-on-findings and --format agent -> exit 1 + redacted envelope.
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{secretFile}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for secret file, got %d (stderr: %s)", code, errOut.String())
	}
	if strings.Contains(out.String(), tok) {
		t.Fatalf("raw secret leaked in agent output: %s", out.String())
	}
	var env precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid agent JSON envelope: %v\n%s", err, out.String())
	}
	if env.Status != "findings_detected" || env.ExitCode != 1 || !env.Redacted || env.FindingsCount == 0 || len(env.NextSteps) == 0 {
		t.Fatalf("unexpected agent envelope: %+v", env)
	}

	// Invalid explicit --exclusion file -> exit 2 (fail closed).
	resetSearchFlags()
	searchFailOnFindings = true
	exclusion = filepath.Join(dir, "does-not-exist.yaml")
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{cleanFile}, strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for missing exclusion file, got %d", code)
	}
}

func TestRunSearchCommand_FileArgPerFileExclusion(t *testing.T) {
	dir := t.TempDir()
	const tok = "ghp_0123456789abcdef0123456789abcdef0123"
	target := filepath.Join(dir, "config.go")
	exclFile := filepath.Join(dir, "excl.yaml")

	if err := os.WriteFile(target, []byte(fmt.Sprintf("package cfg\nconst t = %q\n", tok)), 0o644); err != nil {
		t.Fatal(err)
	}

	// First scan without exclusion to obtain the finding's sha256.
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	var out, errOut bytes.Buffer
	code := runSearchCommandIO(searchCmd, []string{target}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 before exclusion, got %d", code)
	}
	var env precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil || len(env.Findings) == 0 || env.Findings[0].SHA256 == "" {
		t.Fatalf("expected finding with sha256, got: %s", out.String())
	}

	// Suppress using PerFileExcludedHashes keyed by the exact file path passed as arg.
	if err := os.WriteFile(exclFile, []byte(fmt.Sprintf("PerFileExcludedHashes:\n  %s:\n    - %s\n", target, env.Findings[0].SHA256)), 0o644); err != nil {
		t.Fatal(err)
	}

	resetSearchFlags()
	searchFailOnFindings = true
	exclusion = exclFile
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{target}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("expected PerFileExcludedHashes to suppress finding when scanning individual file arg, got code=%d out=%s err=%s",
			code, out.String(), errOut.String())
	}
}

func TestRunSearchCommand_StdinMode(t *testing.T) {
	resetSearchFlags()
	searchStdin = true
	searchFilename = ".env"
	searchFormat = "agent"
	searchFailOnFindings = true

	var out, errOut bytes.Buffer
	code := runSearchCommandIO(searchCmd, nil, strings.NewReader("TOKEN=ghp_0123456789abcdef0123456789abcdef0123\n"), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for secret on stdin .env, got %d (stderr: %s)", code, errOut.String())
	}
}

func TestRunDescribeCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runDescribeCommand(&out, &errOut, "json")
	if code != 0 {
		t.Fatalf("describe json failed with code %d: %s", code, errOut.String())
	}
	var m cliManifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("describe json invalid: %v", err)
	}
	if m.Name != "checkmate" || len(m.Recipes) == 0 || len(m.Commands) == 0 || m.ExitCodes["1"] == "" {
		t.Fatalf("incomplete manifest: %+v", m)
	}

	out.Reset()
	errOut.Reset()
	code = runDescribeCommand(&out, &errOut, "markdown")
	if code != 0 {
		t.Fatalf("describe markdown failed with code %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "checkmate hook run") || !strings.Contains(out.String(), "checkmate:ignore") {
		t.Fatalf("markdown manifest missing expected guidance:\n%s", out.String())
	}
}

func TestRunHookCommand_StagedJSON(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@local",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@local",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	run("init", "-q")

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	// Empty staged set -> exit 0, status=clean.
	resetHookFlags()
	hookFormat = "json"
	var out, errOut bytes.Buffer
	code := runHookCommand(hookRunCmd, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 on empty staged repo, got %d (out=%s err=%s)", code, out.String(), errOut.String())
	}
	var env precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid hook json: %v", err)
	}
	if env.Status != "clean" || env.ExitCode != 0 {
		t.Fatalf("unexpected clean hook envelope: %+v", env)
	}

	// Stage a .env secret -> exit 1, status=findings_detected, redacted.
	const tok = "ghp_0123456789abcdef0123456789abcdef0123"
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("API_KEY="+tok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".env")

	resetHookFlags()
	hookFormat = "json"
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, nil, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 on staged .env secret, got %d (out=%s err=%s)", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), tok) {
		t.Fatalf("raw secret leaked in hook json output")
	}
	var stagedEnv precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &stagedEnv); err != nil {
		t.Fatalf("invalid staged hook json: %v", err)
	}
	if stagedEnv.IgnoreMode != "staged" {
		t.Fatalf("expected ignoreMode=staged, got %q", stagedEnv.IgnoreMode)
	}
}

func TestGitIgnoreAwareScanning_SearchAndHook(t *testing.T) {
	const (
		tokLocal     = "ghp_111111111111111111111111111111111111"
		tokTracked   = "ghp_222222222222222222222222222222222222"
		tokUntracked = "ghp_333333333333333333333333333333333333"
		tokDist      = "ghp_444444444444444444444444444444444444"
	)

	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@local",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@local",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	write := func(rel, content string) string {
		t.Helper()
		full := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return full
	}

	run("init", "-q")
	write(".gitignore", ".env.*\n!.env.example\ndist/\n.temp/\n")
	write("src/clean.go", "package src\nfunc ok() {}\n")
	write(".env.example", "TOKEN=placeholder\n")
	run("add", ".gitignore", "src/clean.go", ".env.example")
	run("commit", "-q", "-m", "init")

	// Untracked gitignored files with real-looking tokens.
	envLocal := write(".env.local", "GITHUB_TOKEN="+tokLocal+"\n")
	write("dist/bundle.js", "const k = \""+tokDist+"\";\n")

	// 1. Default directory scan skips untracked gitignored files (exit 0, ignoreMode=gitignore).
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	var out, errOut bytes.Buffer
	code := runSearchCommandIO(searchCmd, []string{repo}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("default search in git repo should skip gitignored .env.local/dist; got exit %d out=%s err=%s", code, out.String(), errOut.String())
	}
	var env precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if env.IgnoreMode != "gitignore" {
		t.Fatalf("expected ignoreMode=gitignore, got %q", env.IgnoreMode)
	}

	// Same for `checkmate hook run <dir>`.
	resetHookFlags()
	hookFormat = "json"
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, []string{repo}, &out, &errOut)
	if code != 0 {
		t.Fatalf("default hook run <dir> should skip gitignored .env.local/dist; got exit %d out=%s err=%s", code, out.String(), errOut.String())
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid hook json: %v", err)
	}
	if env.IgnoreMode != "gitignore" {
		t.Fatalf("expected hook ignoreMode=gitignore, got %q", env.IgnoreMode)
	}

	// 2. --no-ignore catches secrets in untracked gitignored files (exit 1, ignoreMode=none).
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	searchNoIgnore = true
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{repo}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("--no-ignore should detect gitignored secrets; got exit %d out=%s", code, out.String())
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if env.IgnoreMode != "none" || env.FindingsCount < 2 {
		t.Fatalf("expected ignoreMode=none and >=2 findings, got %+v", env)
	}

	// 3. Explicit file argument bypasses .gitignore even without --no-ignore.
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{envLocal}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("explicit file arg .env.local must be scanned even when gitignored; got exit %d out=%s", code, out.String())
	}

	resetHookFlags()
	hookFormat = "json"
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, []string{envLocal}, &out, &errOut)
	if code != 1 {
		t.Fatalf("hook run explicit file arg .env.local must be scanned; got exit %d out=%s", code, out.String())
	}

	// 4. Untracked non-ignored secret is detected in default mode, skipped in --tracked-only.
	write("src/untracked_leak.go", fmt.Sprintf("package src\nconst leak = %q\n", tokUntracked))

	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{repo}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("untracked non-ignored secret must be detected by default; got exit %d", code)
	}

	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	searchTrackedOnly = true
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{repo}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("--tracked-only must skip untracked files; got exit %d out=%s", code, out.String())
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if env.IgnoreMode != "tracked-only" || env.Mode != "tracked-files" {
		t.Fatalf("expected tracked-only envelope, got mode=%q ignoreMode=%q", env.Mode, env.IgnoreMode)
	}

	// 5. Tracked-but-ignored file (git add -f) MUST be detected in default, --tracked-only, AND --staged.
	write(".env.tracked", "GITHUB_TOKEN="+tokTracked+"\n")
	run("add", "-f", ".env.tracked")

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	// Force-staged gitignored file detected by `hook run --staged` and `search --staged`.
	resetHookFlags()
	hookFormat = "json"
	hookStaged = true
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, nil, &out, &errOut)
	if code != 1 {
		t.Fatalf("hook run --staged MUST detect force-staged gitignored file; got exit %d out=%s", code, out.String())
	}

	resetSearchFlags()
	searchFailOnFindings = true
	searchStaged = true
	searchFormat = "agent"
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, nil, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("search --staged MUST detect force-staged gitignored file; got exit %d out=%s", code, out.String())
	}

	// Commit tracked-but-ignored file; must still be detected by `hook run --tracked-only` (no args) and default search.
	run("commit", "-q", "-m", "add tracked ignored secret")

	resetHookFlags()
	hookFormat = "json"
	hookTrackedOnly = true
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, nil, &out, &errOut)
	if code != 1 {
		t.Fatalf("hook run --tracked-only (no args) MUST detect committed tracked-but-ignored file; got exit %d out=%s", code, out.String())
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if env.Mode != "tracked-files" || env.IgnoreMode != "tracked-only" {
		t.Fatalf("unexpected tracked-only hook envelope: mode=%q ignoreMode=%q", env.Mode, env.IgnoreMode)
	}
}

func TestGitIgnoreAwareScanning_NonGitAndMutuallyExclusiveFlags(t *testing.T) {
	const tok = "ghp_555555555555555555555555555555555555"
	nonGitDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonGitDir, ".gitignore"), []byte(".env.local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonGitDir, ".env.local"), []byte("TOKEN="+tok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-Git directory MUST scan all files (including .env.local) and report ignoreMode=none.
	resetSearchFlags()
	searchFailOnFindings = true
	searchFormat = "agent"
	var out, errOut bytes.Buffer
	code := runSearchCommandIO(searchCmd, []string{nonGitDir}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("non-Git directory must scan .env.local; got exit %d out=%s", code, out.String())
	}
	var env precommit.AgentEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if env.IgnoreMode != "none" {
		t.Fatalf("expected ignoreMode=none for non-Git dir, got %q", env.IgnoreMode)
	}

	// --tracked-only outside Git repo MUST fail closed with exit 2 (even without --fail-on-findings).
	resetSearchFlags()
	searchTrackedOnly = true
	out.Reset()
	errOut.Reset()
	code = runSearchCommandIO(searchCmd, []string{nonGitDir}, strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("search --tracked-only outside Git must exit 2; got %d (out=%s err=%s)", code, out.String(), errOut.String())
	}

	// `hook run --tracked-only` with non-Git dir must exit 2.
	resetHookFlags()
	hookTrackedOnly = true
	hookFormat = "json"
	out.Reset()
	errOut.Reset()
	code = runHookCommand(hookRunCmd, []string{nonGitDir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("hook run --tracked-only outside Git must exit 2; got %d (out=%s err=%s)", code, out.String(), errOut.String())
	}

	// Mutually exclusive flags -> exit 2.
	resetSearchFlags()
	searchNoIgnore = true
	searchTrackedOnly = true
	out.Reset()
	errOut.Reset()
	if code := runSearchCommandIO(searchCmd, []string{nonGitDir}, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatalf("search --no-ignore --tracked-only must exit 2, got %d", code)
	}

	resetSearchFlags()
	searchTrackedOnly = true
	searchStaged = true
	out.Reset()
	errOut.Reset()
	if code := runSearchCommandIO(searchCmd, nil, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatalf("search --tracked-only --staged must exit 2, got %d", code)
	}

	resetSearchFlags()
	searchTrackedOnly = true
	searchStdin = true
	out.Reset()
	errOut.Reset()
	if code := runSearchCommandIO(searchCmd, nil, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatalf("search --tracked-only --stdin must exit 2, got %d", code)
	}

	resetHookFlags()
	hookNoIgnore = true
	hookTrackedOnly = true
	out.Reset()
	errOut.Reset()
	if code := runHookCommand(hookRunCmd, nil, &out, &errOut); code != 2 {
		t.Fatalf("hook run --no-ignore --tracked-only must exit 2, got %d", code)
	}

	resetHookFlags()
	hookStaged = true
	hookTrackedOnly = true
	out.Reset()
	errOut.Reset()
	if code := runHookCommand(hookRunCmd, nil, &out, &errOut); code != 2 {
		t.Fatalf("hook run --staged --tracked-only must exit 2, got %d", code)
	}
}

