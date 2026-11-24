package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var describeFormat string

type cliManifest struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName"`
	Version     string            `json:"version"`
	Summary     string            `json:"summary"`
	ExitCodes   map[string]string `json:"exitCodes"`
	Guardrails  []string          `json:"guardrails"`
	Recipes     []cliRecipe       `json:"recipes"`
	Suppression cliSuppression    `json:"suppression"`
	Integrations cliIntegrations  `json:"integrations"`
	Commands    []cliCommandSpec  `json:"commands"`
}

type cliRecipe struct {
	Goal        string `json:"goal"`
	Command     string `json:"command"`
	Notes       string `json:"notes,omitempty"`
}

type cliSuppression struct {
	InlineSameLine   string   `json:"inlineSameLine"`
	InlineNextLine   string   `json:"inlineNextLine"`
	RepoConfigFile   string   `json:"repoConfigFile"`
	PreferredFields  []string `json:"preferredFields"`
	SharedDatabase   string   `json:"sharedDatabase"`
}

type cliIntegrations struct {
	MCPServer       string `json:"mcpServer"`
	MCPEphemeral    string `json:"mcpEphemeral"`
	LSPServer       string `json:"lspServer"`
	PreCommitHook   string `json:"preCommitHook"`
	PreCommitConfig string `json:"preCommitConfig"`
}

type cliCommandSpec struct {
	Name    string        `json:"name"`
	Use     string        `json:"use"`
	Short   string        `json:"short"`
	Aliases []string      `json:"aliases,omitempty"`
	Flags   []cliFlagSpec `json:"flags,omitempty"`
}

type cliFlagSpec struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
	Usage     string `json:"usage"`
}

var describeCmd = &cobra.Command{
	Use:     "describe",
	Aliases: []string{"capabilities", "agent-info"},
	Short:   "Output a machine-readable capability manifest for AI agents and automation",
	Long: `Outputs a structured, self-describing manifest of CheckMate's CLI commands,
flags, exit codes, suppression mechanisms, MCP/LSP integrations, and recommended
agent workflows. Designed to run immediately with zero scan-engine startup cost.`,
	Example: `  # Machine-readable JSON manifest (default)
  checkmate describe

  # Compact Markdown guide for LLM context or AGENTS.md
  checkmate describe --format markdown`,
	Run: func(cmd *cobra.Command, args []string) {
		if code := runDescribeCommand(os.Stdout, os.Stderr, describeFormat); code != 0 {
			os.Exit(code)
		}
	},
}

func init() {
	rootCmd.AddCommand(describeCmd)
	describeCmd.Flags().StringVar(&describeFormat, "format", "json", "Output format: json or markdown")
}

func runDescribeCommand(stdout, stderr io.Writer, format string) int {
	manifest := buildCLIManifest()
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error encoding manifest: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", data)
		return 0
	case "markdown", "md", "text":
		_, _ = fmt.Fprint(stdout, renderManifestMarkdown(manifest))
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unsupported describe format %q (expected json or markdown)\n", format)
		return 2
	}
}

func buildCLIManifest() cliManifest {
	return cliManifest{
		Name:        common.AppName,
		DisplayName: common.AppDisplayName,
		Version:     appVersion,
		Summary:     "Fast, offline, deterministic hard-coded secrets scanner with Git pre-commit hooks, SARIF 2.1.0, LSP 3.17, and MCP support.",
		ExitCodes: map[string]string{
			"0": "Scan succeeded with zero blocking findings (or non-gating command succeeded).",
			"1": "Scan succeeded and found one or more unexcluded secrets at or above --min-confidence (when --fail-on-findings is enabled or via 'checkmate hook run').",
			"2": "Operational, Git, target acquisition, or configuration error (for example invalid --exclusion YAML or running --staged outside a Git repo).",
		},
		Guardrails: []string{
			"Always pass --redact (or use --format agent / 'checkmate hook run') so raw secret values are never echoed into agent transcripts or CI logs.",
			"Use 'checkmate hook run --format json' or 'checkmate search --staged --format agent --fail-on-findings' before git commit to scan exact Git index blobs rather than unstaged working-tree files.",
			"Never suppress a finding without verifying it is a false positive. Prefer SHA-256 hash suppressions in .checkmate.yaml over plaintext strings.",
			"All CLI commands are strictly non-interactive and write machine-readable payloads exclusively to stdout and diagnostics/errors to stderr.",
		},
		Recipes: []cliRecipe{
			{
				Goal:    "Check staged Git changes before committing (AI agent JSON envelope)",
				Command: "checkmate hook run --staged --format json",
				Notes:   "Reads Git index blobs directly, filters to added/modified lines, redacts secrets, exits 0 (clean), 1 (findings), or 2 (error).",
			},
			{
				Goal:    "Check specific files with redacted structured output and gating exit code",
				Command: "checkmate search --format agent --redact --fail-on-findings --min-confidence medium <file1> <file2>",
				Notes:   "Auto-discovers repo-root .checkmate.yaml and respects inline checkmate:ignore comments.",
			},
			{
				Goal:    "Scan content piped via stdin before writing or staging a file",
				Command: "checkmate search --stdin --filename .env --format agent --redact --fail-on-findings",
				Notes:   "Uses --filename for extension, dotfile (.env*), confidentiality, and exclusion matching.",
			},
			{
				Goal:    "Install CheckMate as the repository's Git pre-commit hook",
				Command: "checkmate hook install",
				Notes:   "Honours worktrees and core.hooksPath. Refuses to overwrite unmanaged hooks unless --force is passed.",
			},
			{
				Goal:    "Start ephemeral MCP server for interactive multi-step triage",
				Command: "checkmate mcp serve --ephemeral",
				Notes:   "Exposes checkmate_scan, checkmate_get_worklist, checkmate_triage_batch, and checkmate_apply_suppression_rule over stdio.",
			},
			{
				Goal:    "Generate SARIF 2.1.0 for CI / GitHub Code Scanning",
				Command: "checkmate search --format sarif . > results.sarif",
				Notes:   "Writes clean SARIF 2.1.0 to stdout without mixing JSON.",
			},
		},
		Suppression: cliSuppression{
			InlineSameLine:  "checkmate:ignore",
			InlineNextLine:  "checkmate:ignore-next-line",
			RepoConfigFile:  ".checkmate.yaml",
			PreferredFields: []string{"PerFileExcludedHashes", "GloballyExcludedHashes", "PathExclusionRegExs"},
			SharedDatabase:  "~/.checkmate/checkmate.db (read-only when present; opt out with --no-db)",
		},
		Integrations: cliIntegrations{
			MCPServer:       "checkmate mcp serve",
			MCPEphemeral:    "checkmate mcp serve --ephemeral",
			LSPServer:       "checkmate lspServe",
			PreCommitHook:   "checkmate hook install",
			PreCommitConfig: ".pre-commit-hooks.yaml (ids: checkmate-staged, checkmate-files)",
		},
		Commands: collectCommandSpecs(rootCmd),
	}
}

func collectCommandSpecs(root *cobra.Command) []cliCommandSpec {
	var specs []cliCommandSpec
	var walk func(cmd *cobra.Command, prefix string)
	walk = func(cmd *cobra.Command, prefix string) {
		for _, sub := range cmd.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			fullName := strings.TrimSpace(prefix + " " + sub.Name())
			spec := cliCommandSpec{
				Name:    fullName,
				Use:     sub.Use,
				Short:   sub.Short,
				Aliases: sub.Aliases,
			}
			sub.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Hidden {
					return
				}
				spec.Flags = append(spec.Flags, cliFlagSpec{
					Name:      f.Name,
					Shorthand: f.Shorthand,
					Type:      f.Value.Type(),
					Default:   f.DefValue,
					Usage:     f.Usage,
				})
			})
			specs = append(specs, spec)
			walk(sub, fullName)
		}
	}
	walk(root, root.Name())
	return specs
}

func renderManifestMarkdown(m cliManifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s CLI Guide (v%s)\n\n", m.DisplayName, m.Version)
	fmt.Fprintf(&b, "%s\n\n", m.Summary)

	b.WriteString("## Exit Codes\n\n")
	for _, code := range []string{"0", "1", "2"} {
		fmt.Fprintf(&b, "- `%s`: %s\n", code, m.ExitCodes[code])
	}

	b.WriteString("\n## Recommended Agent Commands\n\n")
	for _, r := range m.Recipes {
		fmt.Fprintf(&b, "- **%s**: `%s`\n", r.Goal, r.Command)
		if r.Notes != "" {
			fmt.Fprintf(&b, "  %s\n", r.Notes)
		}
	}

	b.WriteString("\n## Suppression Mechanisms\n\n")
	fmt.Fprintf(&b, "- Same-line inline comment: `%s`\n", m.Suppression.InlineSameLine)
	fmt.Fprintf(&b, "- Preceding-line inline comment: `%s`\n", m.Suppression.InlineNextLine)
	fmt.Fprintf(&b, "- Repository config (auto-discovered): `%s` (prefer `%s`)\n",
		m.Suppression.RepoConfigFile, strings.Join(m.Suppression.PreferredFields, "`, `"))
	fmt.Fprintf(&b, "- Shared local exceptions DB: %s\n", m.Suppression.SharedDatabase)

	b.WriteString("\n## Agent Guardrails\n\n")
	for _, g := range m.Guardrails {
		fmt.Fprintf(&b, "- %s\n", g)
	}

	b.WriteString("\n## Integrations\n\n")
	fmt.Fprintf(&b, "- MCP (persistent): `%s`\n", m.Integrations.MCPServer)
	fmt.Fprintf(&b, "- MCP (ephemeral): `%s`\n", m.Integrations.MCPEphemeral)
	fmt.Fprintf(&b, "- LSP 3.17: `%s`\n", m.Integrations.LSPServer)
	fmt.Fprintf(&b, "- Git hook install: `%s`\n", m.Integrations.PreCommitHook)
	fmt.Fprintf(&b, "- pre-commit framework: %s\n", m.Integrations.PreCommitConfig)
	return b.String()
}
