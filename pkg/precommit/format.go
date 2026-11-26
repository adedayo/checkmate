package precommit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// ParseConfidence parses a case-insensitive confidence level name.
func ParseConfidence(s string) (diagnostics.Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return diagnostics.Info, nil
	case "low":
		return diagnostics.Low, nil
	case "medium", "med":
		return diagnostics.Medium, nil
	case "high":
		return diagnostics.High, nil
	case "critical", "crit":
		return diagnostics.Critical, nil
	default:
		return diagnostics.Info, fmt.Errorf("invalid confidence level %q (expected info, low, medium, high, or critical)", s)
	}
}

// FilterByConfidence returns only findings at or above minConfidence.
// Excluded (ReportIgnored) diagnostics are preserved when includeExcluded is true.
func FilterByConfidence(diags []*diagnostics.SecurityDiagnostic, minConfidence diagnostics.Confidence, includeExcluded bool) []*diagnostics.SecurityDiagnostic {
	if len(diags) == 0 {
		return []*diagnostics.SecurityDiagnostic{}
	}
	out := make([]*diagnostics.SecurityDiagnostic, 0, len(diags))
	for _, d := range diags {
		if d == nil {
			continue
		}
		if d.Excluded && !includeExcluded {
			continue
		}
		if d.Justification.Headline.Confidence >= minConfidence {
			out = append(out, d)
		}
	}
	return out
}

// CountBlockingFindings counts unexcluded findings at or above minConfidence.
func CountBlockingFindings(diags []*diagnostics.SecurityDiagnostic, minConfidence diagnostics.Confidence) int {
	n := 0
	for _, d := range diags {
		if d == nil || d.Excluded {
			continue
		}
		if d.Justification.Headline.Confidence >= minConfidence {
			n++
		}
	}
	return n
}

// RedactSecret masks a secret string while preserving small edge hints for
// developer identification (first 4 + last 4 chars for values > 12 bytes).
func RedactSecret(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 {
		first, last := trimmed[0], trimmed[len(trimmed)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
			trimmed = trimmed[1 : len(trimmed)-1]
		}
	}
	n := len(trimmed)
	switch {
	case n == 0:
		return ""
	case n <= 8:
		return "****"
	case n <= 12:
		return trimmed[:2] + "****" + trimmed[n-2:]
	default:
		return trimmed[:4] + "****" + trimmed[n-4:]
	}
}

// RedactDiagnostics masks the Source field of every diagnostic in place while
// leaving SHA256 intact.
func RedactDiagnostics(diags []*diagnostics.SecurityDiagnostic) {
	for _, d := range diags {
		if d == nil || d.Source == nil {
			continue
		}
		masked := RedactSecret(*d.Source)
		d.Source = &masked
	}
}

// TextReportOptions controls terminal text output formatting.
type TextReportOptions struct {
	Quiet        bool
	HookMode     bool
	FilesScanned int
	Duration     time.Duration
	ScopeLabel   string // e.g. "staged file(s)" or "file(s)"
}

// WriteTextReport writes a concise, developer-friendly terminal summary.
func WriteTextReport(w io.Writer, diags []*diagnostics.SecurityDiagnostic, opts TextReportOptions) error {
	scope := opts.ScopeLabel
	if scope == "" {
		scope = "file(s)"
	}

	if len(diags) == 0 {
		if opts.Quiet {
			return nil
		}
		_, err := fmt.Fprintf(w, "CheckMate: no secrets found in %d %s (%dms)\n",
			opts.FilesScanned, scope, opts.Duration.Milliseconds())
		return err
	}

	if _, err := fmt.Fprintf(w, "CheckMate found %d potential secret(s) in %d %s (%dms):\n\n",
		len(diags), opts.FilesScanned, scope, opts.Duration.Milliseconds()); err != nil {
		return err
	}

	for _, d := range diags {
		if d == nil {
			continue
		}
		conf := strings.ToUpper(d.Justification.Headline.Confidence.String())
		loc := "<unknown>"
		if d.Location != nil && *d.Location != "" {
			loc = *d.Location
		}
		pos := ""
		if d.Range.Start.Line > 0 || d.Range.Start.Character > 0 || d.Range.End.Line > 0 || d.Range.End.Character > 0 {
			pos = fmt.Sprintf(":%d:%d", d.Range.Start.Line+1, d.Range.Start.Character+1)
		}
		desc := d.Justification.Headline.Description
		if desc == "" && d.ProviderID != nil {
			desc = *d.ProviderID
		}

		if _, err := fmt.Fprintf(w, "  [%-8s] %s%s  %s\n", conf, loc, pos, desc); err != nil {
			return err
		}

		var details []string
		if d.Source != nil && *d.Source != "" {
			details = append(details, fmt.Sprintf("match: %s", singleLinePreview(*d.Source, 80)))
		}
		if d.SHA256 != nil && *d.SHA256 != "" {
			details = append(details, fmt.Sprintf("sha256: %s", *d.SHA256))
		}
		if len(details) > 0 {
			if _, err := fmt.Fprintf(w, "             %s\n", strings.Join(details, "  ")); err != nil {
				return err
			}
		}
	}

	if opts.HookMode {
		if _, err := fmt.Fprintln(w, "\nCommit blocked. To suppress a verified false positive, add its sha256 to .checkmate.yaml or append 'checkmate:ignore' to the line."); err != nil {
			return err
		}
	}
	return nil
}

func singleLinePreview(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// AgentFinding is a compact, deterministic finding structure designed for AI
// coding agents and automated tooling.
type AgentFinding struct {
	Location    string   `json:"location"`
	Line        int64    `json:"line,omitempty"`
	Column      int64    `json:"column,omitempty"`
	Confidence  string   `json:"confidence"`
	RuleID      string   `json:"ruleId,omitempty"`
	Description string   `json:"description"`
	Match       string   `json:"match,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// AgentEnvelope is the structured JSON output emitted by `--format agent`
// (and `checkmate hook run --format json`) so AI agents can immediately
// determine status, exit semantics, redacted findings, and safe next actions.
type AgentEnvelope struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version,omitempty"`
	Status        string         `json:"status"` // "clean" | "findings_detected" | "error"
	ExitCode      int            `json:"exitCode"`
	Mode          string         `json:"mode,omitempty"`
	IgnoreMode    string         `json:"ignoreMode,omitempty"` // "gitignore" | "tracked-only" | "none" | "staged"
	FilesScanned  int            `json:"filesScanned"`
	DurationMs    int64          `json:"durationMs"`
	MinConfidence string         `json:"minConfidence,omitempty"`
	Redacted      bool           `json:"redacted"`
	FindingsCount int            `json:"findingsCount"`
	Findings      []AgentFinding `json:"findings"`
	Error         string         `json:"error,omitempty"`
	Hint          string         `json:"hint,omitempty"`
	NextSteps     []string       `json:"nextSteps,omitempty"`
}

// BuildAgentEnvelope converts scan diagnostics into an AgentEnvelope.
func BuildAgentEnvelope(version, mode string, minConf diagnostics.Confidence, redacted bool, filesScanned int, duration time.Duration, exitCode int, diags []*diagnostics.SecurityDiagnostic) AgentEnvelope {
	findings := make([]AgentFinding, 0, len(diags))
	for _, d := range diags {
		if d == nil {
			continue
		}
		af := AgentFinding{
			Confidence:  d.Justification.Headline.Confidence.String(),
			Description: d.Justification.Headline.Description,
		}
		if d.Location != nil {
			af.Location = *d.Location
		}
		if d.ProviderID != nil {
			af.RuleID = *d.ProviderID
		}
		if d.Range.Start.Line > 0 || d.Range.Start.Character > 0 || d.Range.End.Line > 0 || d.Range.End.Character > 0 {
			af.Line = d.Range.Start.Line + 1
			af.Column = d.Range.Start.Character + 1
		}
		if d.Source != nil {
			af.Match = *d.Source
		}
		if d.SHA256 != nil {
			af.SHA256 = *d.SHA256
		}
		if d.Tags != nil && len(*d.Tags) > 0 {
			af.Tags = append([]string(nil), (*d.Tags)...)
		}
		findings = append(findings, af)
	}

	status := "clean"
	var nextSteps []string
	if len(findings) > 0 {
		status = "findings_detected"
		nextSteps = []string{
			"Inspect each finding location without printing or committing raw secret values.",
			"For genuine secrets: remove them from code, move them to environment variables or a secret manager, and rotate exposed credentials.",
			"For verified false positives: suppress by sha256 in .checkmate.yaml (PerFileExcludedHashes or GloballyExcludedHashes) or append 'checkmate:ignore' on the line.",
		}
	}

	return AgentEnvelope{
		Tool:          "checkmate",
		Version:       version,
		Status:        status,
		ExitCode:      exitCode,
		Mode:          mode,
		FilesScanned:  filesScanned,
		DurationMs:    duration.Milliseconds(),
		MinConfidence: minConf.String(),
		Redacted:      redacted,
		FindingsCount: len(findings),
		Findings:      findings,
		NextSteps:     nextSteps,
	}
}

// WriteAgentEnvelope marshals env as indented JSON to w.
func WriteAgentEnvelope(w io.Writer, env AgentEnvelope) error {
	if env.Findings == nil {
		env.Findings = []AgentFinding{}
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", data)
	return err
}

