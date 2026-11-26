package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/precommit"
	"github.com/adedayo/checkmate/pkg/report"
	"github.com/spf13/cobra"
)

var (
	hookStaged          bool
	hookDiffOnly        bool
	hookFormat          string
	hookRedact          bool
	hookMinConfidence   string
	hookExclusion       string
	hookNoAutoExclusion bool
	hookDataPath        string
	hookNoDB            bool
	hookExcludeTests    bool
	hookQuiet           bool
	hookVerbose         bool
	hookNoIgnore        bool
	hookTrackedOnly     bool
	hookInstallForce    bool
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Run or manage CheckMate Git pre-commit hooks",
	Long: `Run CheckMate as a fast, non-interactive Git pre-commit hook or manage
hook installation in the current Git repository.

Exit codes for 'checkmate hook run':
  0  Clean (no blocking findings)
  1  One or more potential secrets detected
  2  Operational, Git, or configuration error`,
}

var hookRunCmd = &cobra.Command{
	Use:   "run [files...]",
	Short: "Scan staged Git changes or explicit files for pre-commit protection",
	Long: `Fast secret scanner tuned for Git pre-commit hooks and AI coding agents.

By default (when invoked with no file arguments), scans only staged Git index
blobs and filters modified files to added/modified lines, redacts matched values,
auto-discovers repo-root .checkmate.yaml, and exits non-zero (1) on findings at
or above --min-confidence (default: medium).

When file or directory arguments are supplied (for example via the pre-commit
framework with pass_filenames: true or in a pre-push script), directories inside
a Git repository respect .gitignore by default while still scanning tracked
files and explicit file arguments. Use --no-ignore to scan all files on disk,
or --tracked-only to scan only Git-tracked files.`,
	Example: `  # Standard Git pre-commit hook (scans staged Git index blobs and added lines)
  checkmate hook run

  # AI-agent structured JSON output on staged changes
  checkmate hook run --staged --format json

  # Pre-push hook scanning all Git-tracked files in the repository
  checkmate hook run --tracked-only

  # Pre-push hook scanning tracked files in specific subdirectories
  checkmate hook run --tracked-only --min-confidence high src scripts

  # Scan specific files passed by the pre-commit framework
  checkmate hook run src/config.go .env

  # Scan a working-tree directory including untracked gitignored files
  checkmate hook run --no-ignore src

  # Block only on High and Critical findings
  checkmate hook run --min-confidence high`,
	Run: func(cmd *cobra.Command, args []string) {
		if code := runHookCommand(cmd, args, os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
	},
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install CheckMate as the Git pre-commit hook in the current repository",
	Long:  `Installs an executable POSIX pre-commit hook invoking 'checkmate hook run --staged'. Honours worktrees and core.hooksPath.`,
	Run: func(cmd *cobra.Command, args []string) {
		hookPath, err := precommit.InstallHook(context.Background(), "", hookInstallForce)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Installed CheckMate pre-commit hook at %s\n", hookPath)
	},
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove a CheckMate-managed Git pre-commit hook from the current repository",
	Run: func(cmd *cobra.Command, args []string) {
		hookPath, err := precommit.UninstallHook(context.Background(), "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Removed CheckMate pre-commit hook at %s\n", hookPath)
	},
}

func init() {
	rootCmd.AddCommand(hookCmd)
	hookCmd.AddCommand(hookRunCmd, hookInstallCmd, hookUninstallCmd)

	hookRunCmd.Flags().BoolVar(&hookStaged, "staged", false, "Scan staged changes from the Git index (default when no files are passed)")
	hookRunCmd.Flags().BoolVar(&hookDiffOnly, "diff-only", true, "When scanning staged changes, only report findings on added or modified lines")
	hookRunCmd.Flags().StringVar(&hookFormat, "format", "text", "Output format: text, json, agent, or sarif")
	hookRunCmd.Flags().BoolVar(&hookRedact, "redact", true, "Redact raw secret values in output while keeping SHA-256 checksums")
	hookRunCmd.Flags().StringVar(&hookMinConfidence, "min-confidence", "medium", "Minimum confidence to report and block on: info, low, medium, high, critical")
	hookRunCmd.Flags().StringVarP(&hookExclusion, "exclusion", "e", "", "Use provided exclusion YAML configuration")
	hookRunCmd.Flags().BoolVar(&hookNoAutoExclusion, "no-auto-exclusion", false, "Disable automatic loading of repo-root .checkmate.yaml")
	hookRunCmd.Flags().StringVar(&hookDataPath, "data-path", "~/.checkmate", "Location of CheckMate data directory for optional read-only SQLite exceptions")
	hookRunCmd.Flags().BoolVar(&hookNoDB, "no-db", false, "Disable reading shared SQLite exceptions from --data-path")
	hookRunCmd.Flags().BoolVar(&hookExcludeTests, "exclude-tests", false, "Skip suspected test files during scan")
	hookRunCmd.Flags().BoolVarP(&hookQuiet, "quiet", "q", false, "Suppress output when no blocking findings are detected")
	hookRunCmd.Flags().BoolVar(&hookVerbose, "verbose", false, "Enable verbose logging to stderr")
	hookRunCmd.Flags().BoolVar(&hookNoIgnore, "no-ignore", false, "Disable .gitignore filtering on directory targets and scan all files on disk")
	hookRunCmd.Flags().BoolVar(&hookTrackedOnly, "tracked-only", false, "Scan only Git-tracked files (git ls-files --cached); suitable for pre-push hooks")

	hookInstallCmd.Flags().BoolVar(&hookInstallForce, "force", false, "Overwrite an existing non-CheckMate pre-commit hook")
}

func runHookCommand(cmd *cobra.Command, args []string, stdout, stderr io.Writer) int {
	format := strings.ToLower(strings.TrimSpace(hookFormat))
	switch format {
	case "", "text", "json", "agent", "sarif":
		if format == "" {
			format = "text"
		}
	default:
		return emitHookError(stdout, stderr, format,
			fmt.Sprintf("unsupported format %q (expected text, json, agent, or sarif)", hookFormat),
			"Use --format text for terminals or --format json for AI agents and CI.")
	}

	minConf, err := precommit.ParseConfidence(hookMinConfidence)
	if err != nil {
		return emitHookError(stdout, stderr, format, err.Error(),
			"Valid levels are info, low, medium, high, and critical.")
	}

	if hookNoIgnore && hookTrackedOnly {
		return emitHookError(stdout, stderr, format,
			"--no-ignore and --tracked-only are mutually exclusive",
			"Use --no-ignore to scan all files on disk, or --tracked-only to scan only Git-tracked files.")
	}
	if hookTrackedOnly && hookStaged {
		return emitHookError(stdout, stderr, format,
			"--tracked-only cannot be combined with --staged",
			"Use --staged for staged Git index blobs, or --tracked-only for tracked working-tree files.")
	}

	useStaged := hookStaged || (len(args) == 0 && !hookTrackedOnly)
	ctx := context.Background()

	var result *precommit.ScanResult
	mode := "files"
	ignoreMode := "none"
	scopeLabel := "file(s)"

	if useStaged {
		mode = "staged-files"
		if hookDiffOnly {
			mode = "staged-diff"
		}
		ignoreMode = "staged"
		scopeLabel = "staged file(s)"
		result, err = precommit.ScanStaged(ctx, precommit.StagedScanOptions{
			DiffOnly:          hookDiffOnly,
			ShowSource:        true,
			CalculateChecksum: true,
			ExcludeTestFiles:  hookExcludeTests,
			Verbose:           hookVerbose,
			ExclusionOptions: &precommit.ExclusionOptions{
				ExplicitFile: hookExclusion,
				AutoDiscover: !hookNoAutoExclusion,
				DataPath:     hookDataPath,
				NoDB:         hookNoDB,
			},
		})
		if err != nil {
			return emitHookError(stdout, stderr, format, err.Error(),
				"Run inside a Git repository or pass explicit file paths to scan.")
		}
	} else {
		start := time.Now()
		repoRoot, repoErr := precommit.RepoRoot(ctx, "")
		targets := args
		if hookTrackedOnly {
			mode = "tracked-files"
			ignoreMode = "tracked-only"
			scopeLabel = "tracked file(s)"
			if len(targets) == 0 {
				if repoErr != nil || repoRoot == "" {
					return emitHookError(stdout, stderr, format,
						"not inside a Git repository",
						"Run 'checkmate hook run --tracked-only' inside a Git repository.")
				}
				targets = []string{repoRoot}
			}
		}
		if repoRoot == "" {
			repoRoot, _ = os.Getwd()
		}
		exclProvider, err := precommit.LoadExclusions(precommit.ExclusionOptions{
			RepoRoot:     repoRoot,
			ExplicitFile: hookExclusion,
			AutoDiscover: !hookNoAutoExclusion,
			DataPath:     hookDataPath,
			NoDB:         hookNoDB,
			Repositories: targets,
		})
		if err != nil {
			return emitHookError(stdout, stderr, format, err.Error(),
				"Check the YAML syntax and regex patterns in your exclusion file.")
		}

		// Filter missing args cleanly (pre-commit may pass deleted files) and run parallel file scanner.
		existing := make([]string, 0, len(targets))
		for _, a := range targets {
			if _, statErr := os.Stat(a); statErr != nil {
				continue
			}
			existing = append(existing, a)
		}

		if !hookTrackedOnly {
			if hookNoIgnore {
				ignoreMode = "none"
			} else if anyLocalDirInGit(ctx, existing) {
				ignoreMode = "gitignore"
			} else {
				ignoreMode = "none"
			}
		}

		var issues []*diagnostics.SecurityDiagnostic
		filesScanned := 0
		if len(existing) > 0 {
			aggregator := common.MakeSimpleAggregator()
			options := secrets.SecretSearchOptions{
				ShowSource:        true,
				CalculateChecksum: true,
				Verbose:           hookVerbose,
				Exclusions:        exclProvider,
				ExcludeTestFiles:  hookExcludeTests,
				RespectGitIgnore:  !hookNoIgnore && !hookTrackedOnly,
				TrackedOnly:       hookTrackedOnly,
			}
			issueCh, pathsCh, reportCh := secrets.SearchSecretsOnPathsWithReport(ctx, existing, options, "", "", nil)
			for issue := range issueCh {
				aggregator.AddDiagnostic(issue)
			}
			files := <-pathsCh
			acqReport := <-reportCh
			if hookTrackedOnly && acqReport.Failed > 0 {
				msg := acqReport.Failures[0].Message
				if msg == "" {
					msg = "target is not inside a Git repository"
				}
				return emitHookError(stdout, stderr, format, msg,
					"Run --tracked-only inside a Git repository, or omit --tracked-only for non-Git targets.")
			}
			if acqReport.Succeeded == 0 && acqReport.Failed > 0 {
				return emitHookError(stdout, stderr, format,
					fmt.Sprintf("all %d scan target(s) failed to acquire", acqReport.Failed),
					"Verify that the specified paths exist and are readable.")
			}
			filesScanned = len(files)
			issues = aggregator.Aggregate()
			// Normalise paths relative to repoRoot when possible for concise output.
			if repoRoot != "" {
				for _, d := range issues {
					if d != nil && d.Location != nil {
						if abs, absErr := filepath.Abs(*d.Location); absErr == nil {
							if rel, relErr := filepath.Rel(repoRoot, abs); relErr == nil && !strings.HasPrefix(rel, "..") {
								relSlash := filepath.ToSlash(rel)
								d.Location = &relSlash
							}
						}
					}
				}
			}
		}

		result = &precommit.ScanResult{
			RepoRoot:     repoRoot,
			FilesScanned: filesScanned,
			Diagnostics:  issues,
			Duration:     time.Since(start),
		}
	}

	filtered := precommit.FilterByConfidence(result.Diagnostics, minConf, false)
	if hookRedact {
		precommit.RedactDiagnostics(filtered)
	}

	exitCode := 0
	if len(filtered) > 0 {
		exitCode = 1
	}

	switch format {
	case "json", "agent":
		env := precommit.BuildAgentEnvelope(appVersion, mode, minConf, hookRedact, result.FilesScanned, result.Duration, exitCode, filtered)
		env.IgnoreMode = ignoreMode
		if err := precommit.WriteAgentEnvelope(stdout, env); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing JSON output: %v\n", err)
			return 2
		}
	case "sarif":
		if err := report.GenerateSARIF(stdout, filtered); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error generating SARIF output: %v\n", err)
			return 2
		}
	default:
		if err := precommit.WriteTextReport(stdout, filtered, precommit.TextReportOptions{
			Quiet:        hookQuiet,
			HookMode:     true,
			FilesScanned: result.FilesScanned,
			Duration:     result.Duration,
			ScopeLabel:   scopeLabel,
		}); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing report: %v\n", err)
			return 2
		}
	}

	return exitCode
}

func emitHookError(stdout, stderr io.Writer, format, msg, hint string) int {
	if format == "json" || format == "agent" {
		env := precommit.AgentEnvelope{
			Tool:     common.AppName,
			Version:  appVersion,
			Status:   "error",
			ExitCode: 2,
			Error:    msg,
			Hint:     hint,
			Findings: []precommit.AgentFinding{},
		}
		_ = precommit.WriteAgentEnvelope(stdout, env)
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "CheckMate error: %s\n", msg)
	if hint != "" {
		_, _ = fmt.Fprintf(stderr, "Hint: %s\n", hint)
	}
	return 2
}
