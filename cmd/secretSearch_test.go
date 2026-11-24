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
}

