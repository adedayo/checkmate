package cmd

/*
Copyright © 2019 Adedayo Adetoye (aka Dayo)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/util"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/precommit"
	"github.com/adedayo/checkmate/pkg/report"
	"github.com/adedayo/checkmate/pkg/reports/pdf"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	showSource, asJSON, asPDF, asSARIF, runningCommentary bool
	exclusion                                             string
	sensitiveFiles, sensitiveFilesOnly                    bool
	calculateChecksum, verbose, reportIgnored             bool
	generateSampleExclusion, skipTestFiles                bool
	gitToken, gitTokenEnv, sshKeyPath                     string
	gitDepth                                              int
	insecureSkipTLS                                       bool

	searchFormat          string
	searchFailOnFindings  bool
	searchRedact          bool
	searchMinConfidence   string
	searchStaged          bool
	searchDiffOnly        bool
	searchStdin           bool
	searchFilename        string
	searchNoAutoExclusion bool
	searchDataPath        string
	searchNoDB            bool
	searchQuiet           bool
	searchNoIgnore        bool
	searchTrackedOnly     bool
)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
	Use:   "search <path | git url> [<path | git url>...]",
	Short: "Searches for secrets in local paths, staged Git changes, stdin, or remote Git repositories",
	Long: `Searches for secrets in files in local file system paths, staged Git index
changes (--staged), standard input (--stdin), or remote Git repositories.

Inside a Git repository, directory scans respect .gitignore by default while
always scanning Git-tracked files (even if they match .gitignore) and explicit
file arguments. Use --no-ignore to scan all files on disk, or --tracked-only
to restrict scanning to Git-tracked files.

Exit codes when --fail-on-findings is enabled:
  0  Clean (no findings at or above --min-confidence)
  1  One or more potential secrets found
  2  Operational, Git, target acquisition, or configuration error`,
	Example: `  # Scan a local directory (respects .gitignore inside a Git repo; JSON output)
  checkmate search /path/to/project

  # Scan all files on disk including untracked gitignored files (.env.local, dist/)
  checkmate search --no-ignore --format text --redact --fail-on-findings .

  # Scan only Git-tracked files (ideal for pre-push and CI repository audits)
  checkmate search --tracked-only --format text --redact --fail-on-findings .

  # Scan staged Git changes with redacted terminal report and non-zero exit on findings
  checkmate search --staged --format text --redact --fail-on-findings

  # AI-agent structured JSON envelope with redaction and gating exit code
  checkmate search --staged --format agent --fail-on-findings

  # Scan piped content from stdin using filename context
  git show :.env | checkmate search --stdin --filename .env --format text --redact --fail-on-findings

  # Generate SARIF 2.1.0 for GitHub Code Scanning
  checkmate search --format sarif /path/to/project > results.sarif`,
	Run: search,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().BoolVarP(&showSource, "source", "s", true, "Provide source code evidence in the diagnostic results")
	searchCmd.Flags().BoolVar(&calculateChecksum, "calculate-checksums", true, "Calculate checksums of secrets")
	searchCmd.Flags().StringVarP(&exclusion, "exclusion", "e", "", "Use provided exclusion yaml configuration")
	searchCmd.Flags().BoolVar(&asJSON, "json", true, "Generate JSON output")
	searchCmd.Flags().BoolVar(&asSARIF, "sarif", false, "Generate SARIF 2.1.0 output")
	searchCmd.Flags().BoolVar(&asPDF, "pdf", false, "Generate a PDF report")
	searchCmd.Flags().StringVar(&searchFormat, "format", "", "Output format: json, text, sarif, pdf, or agent (overrides --json/--sarif/--pdf)")
	searchCmd.Flags().BoolVar(&searchFailOnFindings, "fail-on-findings", false, "Exit with code 1 when unexcluded findings at or above --min-confidence are detected (exit 2 on errors)")
	searchCmd.Flags().BoolVar(&searchRedact, "redact", false, "Redact secret values in output while keeping SHA-256 checksums")
	searchCmd.Flags().StringVar(&searchMinConfidence, "min-confidence", "info", "Minimum confidence level to report/block on: info, low, medium, high, critical")
	searchCmd.Flags().BoolVar(&searchStaged, "staged", false, "Scan staged changes from the Git index instead of working-tree files")
	searchCmd.Flags().BoolVar(&searchDiffOnly, "diff-only", true, "When used with --staged, only report findings on added or modified lines")
	searchCmd.Flags().BoolVar(&searchStdin, "stdin", false, "Read content to scan from standard input")
	searchCmd.Flags().StringVar(&searchFilename, "filename", "stdin", "Virtual filename used with --stdin for extension, confidentiality, and exclusion matching")
	searchCmd.Flags().BoolVar(&searchNoAutoExclusion, "no-auto-exclusion", false, "Disable automatic discovery of repo-root .checkmate.yaml")
	searchCmd.Flags().StringVar(&searchDataPath, "data-path", "~/.checkmate", "Location of CheckMate data directory for optional read-only SQLite exceptions")
	searchCmd.Flags().BoolVar(&searchNoDB, "no-db", false, "Disable reading shared SQLite exceptions from --data-path")
	searchCmd.Flags().BoolVarP(&searchQuiet, "quiet", "q", false, "Suppress text output when no findings are detected")
	searchCmd.Flags().BoolVar(&searchNoIgnore, "no-ignore", false, "Disable .gitignore filtering on directory scans and scan all files on disk")
	searchCmd.Flags().BoolVar(&searchTrackedOnly, "tracked-only", false, "Scan only Git-tracked files (git ls-files --cached); exits 2 outside a Git repository")
	searchCmd.Flags().BoolVar(&sensitiveFiles, "sensitive-files", false, "List all registered sensitive files and their description")
	searchCmd.Flags().BoolVar(&sensitiveFilesOnly, "sensitive-files-only", false, "Only search for sensitive files (e.g. certificates, key stores etc.)")
	searchCmd.Flags().BoolVar(&runningCommentary, "running-commentary", false, "Generate a running commentary of results. Useful for analysis of large input data")
	searchCmd.Flags().BoolVar(&verbose, "verbose", false, "Generate verbose output such as current file being scanned as well as report about ignored files")
	searchCmd.Flags().BoolVar(&reportIgnored, "report-ignored", false, "Include ignored files and values in the reports")
	searchCmd.Flags().BoolVar(&generateSampleExclusion, "sample-exclusion", false, "Generates a sample exclusion YAML file content with descriptions")
	searchCmd.Flags().BoolVar(&skipTestFiles, "exclude-tests", false, "Skip test files during scan")
	searchCmd.Flags().StringVar(&gitToken, "git-token", "", "Personal access token or password for cloning private HTTPS git repositories")
	searchCmd.Flags().StringVar(&gitTokenEnv, "git-token-env", "", "Environment variable name containing a git HTTPS access token")
	searchCmd.Flags().StringVar(&sshKeyPath, "ssh-key", "", "Path to an SSH private key file for cloning SSH git repositories")
	searchCmd.Flags().IntVar(&gitDepth, "git-depth", 1, "Git clone depth (0 clones full history)")
	searchCmd.Flags().BoolVar(&insecureSkipTLS, "insecure-skip-tls", false, "Skip TLS certificate verification when cloning git repositories")
}

func buildCLIAuthResolver(token, tokenEnv, sshKey string) gitutils.AuthResolver {
	resolvedToken := strings.TrimSpace(token)
	if resolvedToken == "" && strings.TrimSpace(tokenEnv) != "" {
		resolvedToken = strings.TrimSpace(os.Getenv(strings.TrimSpace(tokenEnv)))
	}

	resolver := &gitutils.ChainedAuthResolver{}
	if resolvedToken != "" {
		resolver.ExplicitAuth = &gitutils.GitAuth{
			User:       gitutils.CHECKMATE_USER,
			Credential: resolvedToken,
		}
	}
	if strings.TrimSpace(sshKey) != "" {
		resolver.ExplicitSSH = &gitutils.SSHAuthConfig{
			PrivateKeyPath: strings.TrimSpace(sshKey),
			Passphrase:     os.Getenv("CHECKMATE_SSH_KEY_PASSPHRASE"),
		}
	}

	// Optionally load ~/.checkmate/config/GitServiceConfig.yaml if present.
	if home, err := homedir.Dir(); err == nil {
		cfgDir := filepath.Join(home, ".checkmate")
		cfgFile := filepath.Join(cfgDir, "config", gitutils.GIT_SERVICE_CONFIG_FILE)
		if _, err := os.Stat(cfgFile); err == nil {
			resolver.ConfigManager = gitutils.NewGitConfigManager(cfgDir)
		}
	}
	return resolver
}

func search(cmd *cobra.Command, args []string) {
	if code := runSearchCommand(cmd, args); code != 0 {
		os.Exit(code)
	}
}

func resolveSearchFormat(cmd *cobra.Command) (string, error) {
	if strings.TrimSpace(searchFormat) != "" {
		f := strings.ToLower(strings.TrimSpace(searchFormat))
		switch f {
		case "json", "text", "sarif", "pdf", "agent":
			return f, nil
		default:
			return "", fmt.Errorf("unsupported format %q (expected json, text, sarif, pdf, or agent)", searchFormat)
		}
	}

	jsonExplicit := cmd != nil && cmd.Flags().Changed("json")
	if asSARIF && !jsonExplicit {
		return "sarif", nil
	}
	if asPDF && !jsonExplicit {
		return "pdf", nil
	}
	if !asJSON && !asSARIF && !asPDF {
		return "text", nil
	}
	return "json", nil
}

func runSearchCommand(cmd *cobra.Command, args []string) int {
	return runSearchCommandIO(cmd, args, os.Stdin, os.Stdout, os.Stderr)
}

func runSearchCommandIO(cmd *cobra.Command, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	start := time.Now()

	if generateSampleExclusion {
		_, _ = fmt.Fprintf(stdout, "%s\n", diagnostics.GenerateSampleExclusion())
		return 0
	}

	if sensitiveFiles {
		_, _ = fmt.Fprintln(stderr, "Sensitive files")
		if x, err := json.MarshalIndent(common.GetSensitiveFilesDescriptors(), "", " "); err == nil {
			_, _ = fmt.Fprintf(stdout, "%s\n", x)
		} else {
			log.Printf("Marshall Error: %s", err.Error())
			_, _ = fmt.Fprint(stdout, "[]")
		}
		return 0
	}

	format, err := resolveSearchFormat(cmd)
	if err != nil {
		return emitSearchError(stdout, stderr, format, err.Error(), "Use --format json, text, sarif, pdf, or agent.")
	}

	if searchNoIgnore && searchTrackedOnly {
		return emitSearchError(stdout, stderr, format,
			"--no-ignore and --tracked-only are mutually exclusive",
			"Use --no-ignore to scan all files on disk, or --tracked-only to scan only Git-tracked files.")
	}
	if searchTrackedOnly && (searchStaged || searchStdin) {
		return emitSearchError(stdout, stderr, format,
			"--tracked-only cannot be combined with --staged or --stdin",
			"Use --staged for Git index blobs, --stdin for piped input, or --tracked-only for tracked working-tree files.")
	}

	if !searchStaged && !searchStdin && len(args) == 0 {
		if searchTrackedOnly {
			args = []string{"."}
		} else {
			_ = cmd.Usage()
			return 0
		}
	}

	minConf, err := precommit.ParseConfidence(searchMinConfidence)
	if err != nil {
		return emitSearchError(stdout, stderr, format, err.Error(), "Valid levels are info, low, medium, high, and critical.")
	}

	effectiveRedact := searchRedact
	if format == "agent" && (cmd == nil || !cmd.Flags().Changed("redact")) {
		effectiveRedact = true
	}

	ctx := context.Background()
	var issues []*diagnostics.SecurityDiagnostic
	filesScanned := 0
	mode := "paths"
	var ignoreMode string
	scopeLabel := "file(s)"

	switch {
	case searchStaged:
		mode = "staged-files"
		if searchDiffOnly {
			mode = "staged-diff"
		}
		ignoreMode = "staged"
		scopeLabel = "staged file(s)"
		res, err := precommit.ScanStaged(ctx, precommit.StagedScanOptions{
			DiffOnly:              searchDiffOnly,
			ShowSource:            showSource,
			CalculateChecksum:     calculateChecksum,
			ExcludeTestFiles:      skipTestFiles,
			ConfidentialFilesOnly: sensitiveFilesOnly,
			ReportIgnored:         reportIgnored,
			Verbose:               verbose,
			ExclusionOptions: &precommit.ExclusionOptions{
				ExplicitFile: exclusion,
				AutoDiscover: !searchNoAutoExclusion,
				DataPath:     searchDataPath,
				NoDB:         searchNoDB,
			},
		})
		if err != nil {
			return emitSearchError(stdout, stderr, format, err.Error(), "Ensure you are inside a Git repository when using --staged.")
		}
		issues = res.Diagnostics
		filesScanned = res.FilesScanned

	case searchStdin:
		mode = "stdin"
		ignoreMode = "none"
		scopeLabel = "input"
		repoRoot, _ := precommit.RepoRoot(ctx, "")
		if repoRoot == "" {
			repoRoot, _ = os.Getwd()
		}
		exclProvider, err := precommit.LoadExclusions(precommit.ExclusionOptions{
			RepoRoot:     repoRoot,
			ExplicitFile: exclusion,
			AutoDiscover: !searchNoAutoExclusion,
			DataPath:     searchDataPath,
			NoDB:         searchNoDB,
		})
		if err != nil {
			return emitSearchError(stdout, stderr, format, err.Error(), "Check the YAML syntax and regex patterns in your exclusion file.")
		}
		res, err := precommit.ScanReader(ctx, stdin, precommit.ReaderScanOptions{
			Filename:              searchFilename,
			ShowSource:            showSource,
			CalculateChecksum:     calculateChecksum,
			ExcludeTestFiles:      skipTestFiles,
			ConfidentialFilesOnly: sensitiveFilesOnly,
			Exclusions:            exclProvider,
		})
		if err != nil {
			return emitSearchError(stdout, stderr, format, err.Error(), "")
		}
		issues = res.Diagnostics
		filesScanned = res.FilesScanned

	default:
		repoRoot, _ := precommit.RepoRoot(ctx, "")
		if repoRoot == "" {
			repoRoot, _ = os.Getwd()
		}
		exclProvider, err := precommit.LoadExclusions(precommit.ExclusionOptions{
			RepoRoot:     repoRoot,
			ExplicitFile: exclusion,
			AutoDiscover: !searchNoAutoExclusion,
			DataPath:     searchDataPath,
			NoDB:         searchNoDB,
			Repositories: args,
		})
		if err != nil {
			return emitSearchError(stdout, stderr, format, err.Error(), "Check the YAML syntax and regex patterns in your exclusion file.")
		}

		respectGitIgnore := !searchNoIgnore && !searchTrackedOnly
		if searchTrackedOnly {
			mode = "tracked-files"
			ignoreMode = "tracked-only"
			scopeLabel = "tracked file(s)"
		} else if searchNoIgnore {
			ignoreMode = "none"
		} else if anyLocalDirInGit(ctx, args) {
			ignoreMode = "gitignore"
		} else {
			ignoreMode = "none"
		}

		aggregator := common.MakeSimpleAggregator()
		options := secrets.SecretSearchOptions{
			ShowSource:            showSource,
			CalculateChecksum:     calculateChecksum,
			Verbose:               verbose,
			ReportIgnored:         reportIgnored,
			ConfidentialFilesOnly: sensitiveFilesOnly,
			Exclusions:            exclProvider,
			ExcludeTestFiles:      skipTestFiles,
			AuthResolver:          buildCLIAuthResolver(gitToken, gitTokenEnv, sshKeyPath),
			CloneDepth:            gitDepth,
			FullHistory:           gitDepth == 0,
			InsecureSkipTLS:       insecureSkipTLS,
			RespectGitIgnore:      respectGitIgnore,
			TrackedOnly:           searchTrackedOnly,
		}
		issueChannel, paths, reportCh := secrets.SearchSecretsOnPathsWithReport(ctx, args, options, "", "", nil)

		for issue := range issueChannel {
			aggregator.AddDiagnostic(issue)
			if runningCommentary {
				if x, err := json.MarshalIndent(issue, "", " "); err == nil {
					_, _ = fmt.Fprintf(stdout, "\n%s\n", x)
				}
			}
		}
		files := <-paths
		acqReport := <-reportCh

		if searchTrackedOnly && acqReport.Failed > 0 {
			msg := acqReport.Failures[0].Message
			if msg == "" {
				msg = "target is not inside a Git repository"
			}
			return emitSearchError(stdout, stderr, format, msg,
				"Run --tracked-only inside a Git repository, or omit --tracked-only for non-Git directory scans.")
		}

		for _, f := range acqReport.Failures {
			_, _ = fmt.Fprintf(stderr, "Warning: failed to acquire %s (%s): %s\n", f.Target, f.ErrorKind, f.Message)
		}
		if acqReport.Succeeded == 0 && acqReport.Failed > 0 {
			errCode := 1
			if searchFailOnFindings {
				errCode = 2
			}
			msg := fmt.Sprintf("all %d scan target(s) failed to acquire", acqReport.Failed)
			if format == "agent" {
				_ = precommit.WriteAgentEnvelope(stdout, precommit.AgentEnvelope{
					Tool:       common.AppName,
					Version:    appVersion,
					Status:     "error",
					ExitCode:   errCode,
					Mode:       mode,
					IgnoreMode: ignoreMode,
					Error:      msg,
					Findings:   []precommit.AgentFinding{},
				})
			} else {
				_, _ = fmt.Fprintf(stderr, "Error: %s\n", msg)
			}
			return errCode
		}
		issues = aggregator.Aggregate()
		filesScanned = len(files)
	}

	issues = precommit.FilterByConfidence(issues, minConf, reportIgnored)
	if effectiveRedact {
		precommit.RedactDiagnostics(issues)
	}
	if issues == nil {
		issues = []*diagnostics.SecurityDiagnostic{}
	}

	exitCode := 0
	if searchFailOnFindings && precommit.CountBlockingFindings(issues, minConf) > 0 {
		exitCode = 1
	}

	duration := time.Since(start)
	switch format {
	case "agent":
		env := precommit.BuildAgentEnvelope(appVersion, mode, minConf, effectiveRedact, filesScanned, duration, exitCode, issues)
		env.IgnoreMode = ignoreMode
		if err := precommit.WriteAgentEnvelope(stdout, env); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error encoding agent output: %v\n", err)
			return 2
		}
	case "text":
		if err := precommit.WriteTextReport(stdout, issues, precommit.TextReportOptions{
			Quiet:        searchQuiet,
			HookMode:     searchFailOnFindings,
			FilesScanned: filesScanned,
			Duration:     duration,
			ScopeLabel:   scopeLabel,
		}); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing text report: %v\n", err)
			return 2
		}
	case "sarif":
		if err := report.GenerateSARIF(stdout, issues); err != nil {
			_, _ = fmt.Fprintf(stderr, "SARIF Generation Error: %s\n", err.Error())
			return 2
		}
	case "pdf":
		path, err := pdf.GenerateReport("", showSource, filesScanned, issues...)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %s%s\n", err.Error(), path)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "Report generated at %s\n", path)
	default: // json
		if x, err := json.MarshalIndent(issues, "", " "); err == nil {
			_, _ = fmt.Fprintf(stdout, "%s\n", x)
		} else {
			log.Printf("Marshall Error: %s", err.Error())
			_, _ = fmt.Fprint(stdout, "[]")
		}
		if asSARIF && searchFormat == "" {
			if err := report.GenerateSARIF(stdout, issues); err != nil {
				log.Printf("SARIF Generation Error: %s", err.Error())
			}
		}
		if asPDF && searchFormat == "" {
			path, err := pdf.GenerateReport("", showSource, filesScanned, issues...)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "Error: %s%s\n", err.Error(), path)
				return 2
			}
			_, _ = fmt.Fprintf(stdout, "Report generated at %s\n", path)
		}
	}

	return exitCode
}

func anyLocalDirInGit(ctx context.Context, paths []string) bool {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := util.GitWorktreeRoot(ctx, p); err == nil {
			return true
		}
	}
	return false
}

func emitSearchError(stdout, stderr io.Writer, format, msg, hint string) int {
	if format == "agent" {
		_ = precommit.WriteAgentEnvelope(stdout, precommit.AgentEnvelope{
			Tool:     common.AppName,
			Version:  appVersion,
			Status:   "error",
			ExitCode: 2,
			Error:    msg,
			Hint:     hint,
			Findings: []precommit.AgentFinding{},
		})
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "Error: %s\n", msg)
	if hint != "" {
		_, _ = fmt.Fprintf(stderr, "Hint: %s\n", hint)
	}
	return 2
}
