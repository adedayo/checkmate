package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/gitservice/account"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/precommit"
	"github.com/adedayo/checkmate/pkg/report"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	accountServiceID       string
	accountGitToken        string
	accountGitTokenEnv     string
	accountAnonymous       bool
	accountIncludeForks    bool
	accountIncludeArchived bool
	accountIncludeDisabled bool
	accountIncludeNames    []string
	accountExcludeNames    []string
	accountMaxRepos        int
	accountFormat          string

	// Scan-only flags
	accountGitDepth       int
	accountFullHistory    bool
	accountRetainCode     bool
	accountCloneDir       string
	accountRedact         bool
	accountFailOnFindings bool
	accountMinConfidence  string
	accountExclusion      string
	accountNoDB           bool
	accountDataPath       string
	accountExcludeTests   bool
	accountQuiet          bool
	accountVerbose        bool
	accountInsecureTLS    bool

	// Test hook overrides (empty in production).
	accountTestRESTBaseURL     string
	accountTestGraphQLEndpoint string
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Discover and scan all repositories owned by a GitHub account or organisation",
	Long: `Resolve a GitHub user or organisation (for example https://github.com/adedayo
or github:adedayo) into its complete, canonically sorted repository set and
optionally scan all repositories in a single pass.

Anonymous resolution works with zero configuration over the GitHub REST API
(60 requests/hour per IP, public repositories only). Supplying a token via
--git-token, --git-token-env, GITHUB_TOKEN, or --service uses GraphQL
(5,000 points/hour) and includes private repositories.`,
}

var accountResolveCmd = &cobra.Command{
	Use:   "resolve <account-ref>",
	Short: "Resolve an account into its filtered, sorted repository list without cloning",
	Long: `Resolves a GitHub account URL (https://github.com/<login>), shorthand
(github:<login>), or login into its filtered repository set without cloning or
scanning any code. Anonymous results are visibly marked as potentially
incomplete because private repositories are not visible without credentials.`,
	Example: `  # Resolve public repositories of an account with zero setup
  checkmate account resolve https://github.com/adedayo

  # Resolve as JSON including rate-limit and exclusion counts
  checkmate account resolve github:adedayo --format json

  # Resolve an organisation including forks and filtering by name glob
  checkmate account resolve https://github.com/acme --include-forks --include "api-*" --exclude "*-legacy"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if code := runAccountResolveCommand(args[0], os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
	},
}

var accountScanCmd = &cobra.Command{
	Use:   "scan <account-ref>",
	Short: "Resolve an account and scan all matching repositories in one pass",
	Long: `Resolves all matching repositories for a GitHub user or organisation and
scans them as a single multi-repository scan.

Clones default to shallow working-tree checkouts (--git-depth 1) and are
deleted automatically when the scan finishes unless --retain-code is set.
Retaining checkouts keeps plaintext repository copies on disk.`,
	Example: `  # Scan all public repositories of a GitHub account (redacted text report)
  checkmate account scan https://github.com/adedayo --format text --redact

  # Scan an organisation with a token from GITHUB_TOKEN and gate CI on findings
  checkmate account scan github:acme --format agent --fail-on-findings --min-confidence high`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if code := runAccountScanCommand(cmd, args[0], os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
	},
}

func init() {
	rootCmd.AddCommand(accountCmd)
	accountCmd.AddCommand(accountResolveCmd, accountScanCmd)

	for _, c := range []*cobra.Command{accountResolveCmd, accountScanCmd} {
		c.Flags().StringVar(&accountServiceID, "service", "", "Configured CheckMate Git service ID to authenticate with")
		c.Flags().StringVar(&accountGitToken, "git-token", "", "Personal access token for authenticated GitHub resolution and cloning")
		c.Flags().StringVar(&accountGitTokenEnv, "git-token-env", "", "Environment variable name containing a GitHub access token")
		c.Flags().BoolVar(&accountAnonymous, "anonymous", false, "Force anonymous REST resolution (ignore environment and saved tokens)")
		c.Flags().BoolVar(&accountIncludeForks, "include-forks", false, "Include forked repositories (excluded by default)")
		c.Flags().BoolVar(&accountIncludeArchived, "include-archived", false, "Include archived repositories (excluded by default)")
		c.Flags().BoolVar(&accountIncludeDisabled, "include-disabled", false, "Include disabled repositories (excluded by default)")
		c.Flags().StringSliceVar(&accountIncludeNames, "include", nil, "Repository name glob pattern(s) to include (repeatable)")
		c.Flags().StringSliceVar(&accountExcludeNames, "exclude", nil, "Repository name glob pattern(s) to exclude; beats --include (repeatable)")
		c.Flags().IntVar(&accountMaxRepos, "max-repos", 0, "Maximum repositories allowed before failing (default 500 or CHECKMATE_ACCOUNT_MAX_REPOS)")
	}

	accountResolveCmd.Flags().StringVar(&accountFormat, "format", "text", "Output format: text or json")

	accountScanCmd.Flags().StringVar(&accountFormat, "format", "text", "Output format: text, json, sarif, or agent")
	accountScanCmd.Flags().IntVar(&accountGitDepth, "git-depth", 1, "Git clone depth (1 shallow default; 0 clones full history)")
	accountScanCmd.Flags().BoolVar(&accountFullHistory, "full-history", false, "Clone full Git history (equivalent to --git-depth 0)")
	accountScanCmd.Flags().BoolVar(&accountRetainCode, "retain-code", false, "Keep checked-out repositories on disk after scan (warning: retains plaintext code)")
	accountScanCmd.Flags().StringVar(&accountCloneDir, "clone-dir", "", "Directory for repository checkouts (defaults to a temporary 0700 directory)")
	accountScanCmd.Flags().BoolVar(&accountRedact, "redact", true, "Redact secret values in output while keeping SHA-256 checksums")
	accountScanCmd.Flags().BoolVar(&accountFailOnFindings, "fail-on-findings", false, "Exit with code 1 when blocking findings are detected (exit 2 on errors)")
	accountScanCmd.Flags().StringVar(&accountMinConfidence, "min-confidence", "medium", "Minimum confidence level to report/block on: info, low, medium, high, critical")
	accountScanCmd.Flags().StringVarP(&accountExclusion, "exclusion", "e", "", "Use provided exclusion YAML configuration")
	accountScanCmd.Flags().StringVar(&accountDataPath, "data-path", "~/.checkmate", "Location of CheckMate data directory for optional read-only SQLite exceptions")
	accountScanCmd.Flags().BoolVar(&accountNoDB, "no-db", false, "Disable reading shared SQLite exceptions from --data-path")
	accountScanCmd.Flags().BoolVar(&accountExcludeTests, "exclude-tests", false, "Skip suspected test files during scan")
	accountScanCmd.Flags().BoolVarP(&accountQuiet, "quiet", "q", false, "Suppress text output when no findings are detected")
	accountScanCmd.Flags().BoolVar(&accountVerbose, "verbose", false, "Enable verbose logging")
	accountScanCmd.Flags().BoolVar(&accountInsecureTLS, "insecure-skip-tls", false, "Skip TLS certificate verification when cloning git repositories")
}

func buildAccountResolver() *account.Resolver {
	token := strings.TrimSpace(accountGitToken)
	if token == "" && strings.TrimSpace(accountGitTokenEnv) != "" {
		token = strings.TrimSpace(os.Getenv(strings.TrimSpace(accountGitTokenEnv)))
	}
	var cfgMgr gitutils.GitConfigManager
	if !accountAnonymous {
		if home, err := homedir.Dir(); err == nil && home != "" {
			cfgFile := filepath.Join(home, ".checkmate", "config", gitutils.GIT_SERVICE_CONFIG_FILE)
			if _, err := os.Stat(cfgFile); err == nil {
				cfgMgr = gitutils.NewGitConfigManager(filepath.Join(home, ".checkmate"))
			}
		}
	}
	return account.NewResolver(account.ResolveOptions{
		MaxRepos:              accountMaxRepos,
		Token:                 token,
		AnonymousOnly:         accountAnonymous,
		ConfigManager:         cfgMgr,
		GitHubRESTBaseURL:     accountTestRESTBaseURL,
		GitHubGraphQLEndpoint: accountTestGraphQLEndpoint,
	})
}

func buildAccountFilter() account.AccountFilter {
	f := account.DefaultAccountFilter()
	f.IncludeForks = accountIncludeForks
	f.IncludeArchived = accountIncludeArchived
	f.IncludeDisabled = accountIncludeDisabled
	f.IncludeNames = accountIncludeNames
	f.ExcludeNames = accountExcludeNames
	return f
}

func runAccountResolveCommand(rawRef string, stdout, stderr io.Writer) int {
	format := strings.ToLower(strings.TrimSpace(accountFormat))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		_, _ = fmt.Fprintf(stderr, "Error: unsupported format %q (expected text or json)\n", accountFormat)
		return 2
	}

	ref, err := account.ParseAccountRef(rawRef)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if strings.TrimSpace(accountServiceID) != "" {
		ref.ServiceID = strings.TrimSpace(accountServiceID)
	}

	res, err := buildAccountResolver().Resolve(context.Background(), ref, buildAccountFilter())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if format == "json" {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error encoding JSON: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", data)
		return 0
	}

	writeAccountResolutionText(stdout, res)
	return 0
}

func writeAccountResolutionText(w io.Writer, res account.AccountResolution) {
	authLabel := "anonymous (public only)"
	if res.Authenticated {
		authLabel = "authenticated"
		if res.ServiceID != "" {
			authLabel = fmt.Sprintf("authenticated (service: %s)", res.ServiceID)
		}
	}
	_, _ = fmt.Fprintf(w, "Account: %s:%s (%s) [%s]\n", res.Ref.Provider, res.Ref.Login, res.AccountType, authLabel)
	if res.PotentiallyIncomplete {
		_, _ = fmt.Fprintf(w, "WARNING: Result is potentially incomplete: %s\n", res.IncompletenessReason)
	}
	_, _ = fmt.Fprintf(w, "Repositories: %d (estimated total size: %s)\n", len(res.Repositories), formatByteSize(res.TotalSizeBytes))
	if len(res.ExcludedCounts) > 0 {
		keys := make([]string, 0, len(res.ExcludedCounts))
		for k := range res.ExcludedCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, res.ExcludedCounts[k]))
		}
		_, _ = fmt.Fprintf(w, "Excluded: %s\n", strings.Join(parts, ", "))
	}
	if res.RateLimit.Limit > 0 {
		_, _ = fmt.Fprintf(w, "Rate limit: %d/%d remaining\n", res.RateLimit.Remaining, res.RateLimit.Limit)
	}
	if len(res.Repositories) > 0 {
		_, _ = fmt.Fprintln(w)
		for _, repo := range res.Repositories {
			vis := "public"
			if repo.Private {
				vis = "private"
			}
			sizeStr := "unknown"
			if repo.SizeBytes >= 0 {
				sizeStr = formatByteSize(repo.SizeBytes)
			}
			_, _ = fmt.Fprintf(w, "  %-32s  %-7s  %10s  %s\n", repo.Name, vis, sizeStr, repo.Location)
		}
	}
}

func runAccountScanCommand(cmd *cobra.Command, rawRef string, stdout, stderr io.Writer) int {
	start := time.Now()
	format := strings.ToLower(strings.TrimSpace(accountFormat))
	if format == "" {
		format = "text"
	}
	switch format {
	case "text", "json", "sarif", "agent":
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unsupported format %q (expected text, json, sarif, or agent)\n", accountFormat)
		return 2
	}

	minConf, err := precommit.ParseConfidence(accountMinConfidence)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	ref, err := account.ParseAccountRef(rawRef)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if strings.TrimSpace(accountServiceID) != "" {
		ref.ServiceID = strings.TrimSpace(accountServiceID)
	}

	ctx := context.Background()
	res, err := buildAccountResolver().Resolve(ctx, ref, buildAccountFilter())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	// Pre-scan disclosure of repository count, estimated size, and anonymous incompleteness.
	_, _ = fmt.Fprintf(stderr, "Resolved %d repository(ies) for %s:%s (estimated size: %s)\n",
		len(res.Repositories), res.Ref.Provider, res.Ref.Login, formatByteSize(res.TotalSizeBytes))
	if res.PotentiallyIncomplete {
		_, _ = fmt.Fprintf(stderr, "WARNING: Result is potentially incomplete: %s\n", res.IncompletenessReason)
	}

	if len(res.Repositories) == 0 {
		return emitAccountScanOutput(stdout, stderr, format, minConf, accountRedact, 0, time.Since(start), nil, res)
	}

	cloneBase := strings.TrimSpace(accountCloneDir)
	tempCreated := false
	if cloneBase == "" {
		tmp, err := os.MkdirTemp("", "checkmate-account-*")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error creating temporary checkout directory: %v\n", err)
			return 2
		}
		_ = os.Chmod(tmp, 0o700)
		cloneBase = tmp
		tempCreated = true
	}
	if tempCreated && !accountRetainCode {
		defer func() { _ = os.RemoveAll(cloneBase) }()
	}

	targets := make([]string, 0, len(res.Repositories))
	for _, r := range res.Repositories {
		targets = append(targets, r.Location)
	}

	exclProvider, err := precommit.LoadExclusions(precommit.ExclusionOptions{
		ExplicitFile: accountExclusion,
		AutoDiscover: false,
		DataPath:     accountDataPath,
		NoDB:         accountNoDB,
		Repositories: targets,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error loading exclusions: %v\n", err)
		return 2
	}

	depth := accountGitDepth
	fullHist := accountFullHistory || depth == 0
	var authResolver gitutils.AuthResolver
	if !accountAnonymous {
		authResolver = buildCLIAuthResolver(accountGitToken, accountGitTokenEnv, "")
	}

	options := secrets.SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Verbose:           accountVerbose,
		Exclusions:        exclProvider,
		ExcludeTestFiles:  accountExcludeTests,
		AuthResolver:      authResolver,
		CloneDepth:        depth,
		FullHistory:       fullHist,
		KeepCheckouts:     accountRetainCode,
		CloneBaseDir:      cloneBase,
		InsecureSkipTLS:   accountInsecureTLS,
	}

	aggregator := common.MakeSimpleAggregator()
	issueCh, pathsCh, reportCh := secrets.SearchSecretsOnPathsWithReport(ctx, targets, options, "", "", nil)
	for issue := range issueCh {
		aggregator.AddDiagnostic(issue)
	}
	files := <-pathsCh
	acqReport := <-reportCh

	for _, f := range acqReport.Failures {
		_, _ = fmt.Fprintf(stderr, "Warning: failed to acquire %s (%s): %s\n", f.Target, f.ErrorKind, f.Message)
	}
	if acqReport.Succeeded == 0 && acqReport.Failed > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: all %d repository(ies) failed to acquire\n", acqReport.Failed)
		return 2
	}

	issues := aggregator.Aggregate()
	issues = precommit.FilterByConfidence(issues, minConf, false)
	if accountRedact {
		precommit.RedactDiagnostics(issues)
	}
	return emitAccountScanOutput(stdout, stderr, format, minConf, accountRedact, len(files), time.Since(start), issues, res)
}

func emitAccountScanOutput(
	stdout, stderr io.Writer,
	format string,
	minConf diagnostics.Confidence,
	redacted bool,
	filesScanned int,
	duration time.Duration,
	issues []*diagnostics.SecurityDiagnostic,
	res account.AccountResolution,
) int {
	if issues == nil {
		issues = []*diagnostics.SecurityDiagnostic{}
	}
	exitCode := 0
	if accountFailOnFindings && precommit.CountBlockingFindings(issues, minConf) > 0 {
		exitCode = 1
	}

	switch format {
	case "agent":
		env := precommit.BuildAgentEnvelope(appVersion, "account-scan", minConf, redacted, filesScanned, duration, exitCode, issues)
		env.IgnoreMode = "none"
		if res.PotentiallyIncomplete {
			env.Hint = res.IncompletenessReason
		}
		if err := precommit.WriteAgentEnvelope(stdout, env); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing agent JSON: %v\n", err)
			return 2
		}
	case "sarif":
		if err := report.GenerateSARIF(stdout, issues); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error generating SARIF: %v\n", err)
			return 2
		}
	case "json":
		payload := struct {
			Account  account.AccountResolution         `json:"account"`
			Findings []*diagnostics.SecurityDiagnostic `json:"findings"`
		}{
			Account:  res,
			Findings: issues,
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error encoding JSON: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", data)
	default: // text
		if res.PotentiallyIncomplete && !accountQuiet {
			_, _ = fmt.Fprintf(stdout, "Note: %s\n", res.IncompletenessReason)
		}
		if err := precommit.WriteTextReport(stdout, issues, precommit.TextReportOptions{
			Quiet:        accountQuiet,
			HookMode:     accountFailOnFindings,
			FilesScanned: filesScanned,
			Duration:     duration,
			ScopeLabel:   fmt.Sprintf("file(s) across %d repository(ies)", len(res.Repositories)),
		}); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing text report: %v\n", err)
			return 2
		}
	}
	return exitCode
}

func formatByteSize(bytes int64) string {
	if bytes <= 0 {
		return "0 B"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
