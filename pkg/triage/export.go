package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/report"
	csvreport "github.com/adedayo/checkmate/pkg/reports/csv"
	"github.com/adedayo/checkmate/pkg/reports/pdf"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"gopkg.in/yaml.v3"
)

// ExportRequest configures a sanitised scan export.
type ExportRequest struct {
	ScanID            string `json:"scanId"`
	Format            string `json:"format,omitempty"`            // "json" (default) | "sarif" | "csv" | "pdf" | "checkmate_yaml"
	IncludeSuppressed bool   `json:"includeSuppressed,omitempty"` // default false (actionable findings only)
	OutputPath        string `json:"outputPath,omitempty"`
}

// ExportResult returns the sanitised summary, exported finding count, and
// either inline content (text formats) or outputPath (when written to disk / PDF).
type ExportResult struct {
	ScanID           string                  `json:"scanId"`
	ProjectID        string                  `json:"projectId"`
	Format           string                  `json:"format"`
	FindingCount     int                     `json:"findingCount"`
	OutputPath       string                  `json:"outputPath,omitempty"`
	Content          string                  `json:"content,omitempty"`
	SanitisedSummary *store.SanitisedSummary `json:"sanitisedSummary"`
}

// SanitisedReportJSON is the structured JSON export payload.
type SanitisedReportJSON struct {
	ScanID           string                  `json:"scanId"`
	ProjectID        string                  `json:"projectId"`
	SanitisedSummary *store.SanitisedSummary `json:"sanitisedSummary"`
	Findings         []*store.StoredFinding  `json:"findings"`
}

// ExportSanitised renders the triaged, sanitised scan output in the requested format.
func (s *Service) ExportSanitised(_ context.Context, req ExportRequest) (*ExportResult, error) {
	if req.ScanID == "" {
		return nil, fmt.Errorf("scanId is required")
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "json"
	}

	projectID, err := s.store.GetScanProjectID(req.ScanID)
	if err != nil {
		return nil, err
	}

	findings, err := s.store.GetScanFindings(req.ScanID)
	if err != nil {
		return nil, err
	}
	summary, err := s.store.GetSanitisedSummary(req.ScanID)
	if err != nil {
		return nil, err
	}

	filtered := filterFindingsForExport(findings, req.IncludeSuppressed)

	var content string
	switch format {
	case "json":
		payload := SanitisedReportJSON{
			ScanID:           req.ScanID,
			ProjectID:        projectID,
			SanitisedSummary: summary,
			Findings:         filtered,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return nil, err
		}
		content = string(b)

	case "sarif":
		var buf bytes.Buffer
		if err := report.GenerateSARIFWithOptions(&buf, findings, report.SARIFOptions{
			IncludeSuppressed: req.IncludeSuppressed,
		}); err != nil {
			return nil, err
		}
		content = buf.String()

	case "csv":
		var buf bytes.Buffer
		diags := storedFindingsToDiagnostics(filtered)
		if err := csvreport.WriteSecurityDiagnosticCSVReport(&buf, diags); err != nil {
			return nil, err
		}
		content = buf.String()

	case "pdf":
		diags := storedFindingsToDiagnostics(filtered)
		outPath := req.OutputPath
		if outPath == "" {
			outPath = filepath.Join(os.TempDir(), fmt.Sprintf("checkmate-sanitised-%s.pdf", req.ScanID))
		}
		generatedPath, err := pdf.GenerateReport(outPath, true, 0, diags...)
		if err != nil {
			return nil, fmt.Errorf("generate PDF report: %w", err)
		}
		return &ExportResult{
			ScanID:           req.ScanID,
			ProjectID:        projectID,
			Format:           format,
			FindingCount:     len(filtered),
			OutputPath:       generatedPath,
			SanitisedSummary: summary,
		}, nil

	case "checkmate_yaml":
		exceptions, err := s.store.ListExceptions(projectID)
		if err != nil {
			return nil, err
		}
		def := buildExcludeDefinitionFromExceptions(exceptions)
		b, err := yaml.Marshal(def)
		if err != nil {
			return nil, err
		}
		content = string(b)

	default:
		return nil, fmt.Errorf("unsupported export format %q (supported: json, sarif, csv, pdf, checkmate_yaml)", req.Format)
	}

	res := &ExportResult{
		ScanID:           req.ScanID,
		ProjectID:        projectID,
		Format:           format,
		FindingCount:     len(filtered),
		SanitisedSummary: summary,
	}

	if req.OutputPath != "" {
		if err := os.MkdirAll(filepath.Dir(req.OutputPath), 0755); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}
		if err := os.WriteFile(req.OutputPath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("write export file %s: %w", req.OutputPath, err)
		}
		res.OutputPath = req.OutputPath
	} else {
		res.Content = content
	}

	return res, nil
}

func filterFindingsForExport(findings []*store.StoredFinding, includeSuppressed bool) []*store.StoredFinding {
	out := make([]*store.StoredFinding, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		isSuppressed := f.Suppressed || f.TriageStatus == sdk.TriageStatusFalsePositive
		if isSuppressed && !includeSuppressed {
			continue
		}
		out = append(out, f)
	}
	return out
}

func storedFindingsToDiagnostics(findings []*store.StoredFinding) []*diagnostics.SecurityDiagnostic {
	diags := make([]*diagnostics.SecurityDiagnostic, 0, len(findings))
	for _, f := range findings {
		loc := f.File
		sha := f.SecretChecksum
		src := f.SourceContext
		line := int64(f.Line)
		if line > 0 {
			line--
		}
		col := int64(f.Column)
		if col > 0 {
			col--
		}
		diags = append(diags, &diagnostics.SecurityDiagnostic{
			ID: f.FindingID,
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: f.RuleID,
					Confidence:  confidenceFromString(string(f.Confidence)),
				},
			},
			Range: code.Range{
				Start: code.Position{Line: line, Character: col},
			},
			Location:     &loc,
			SHA256:       &sha,
			Source:       &src,
			Excluded:     f.Suppressed,
			AIAnnotation: f.AIAnnotation,
		})
	}
	return diags
}

func confidenceFromString(s string) diagnostics.Confidence {
	switch strings.ToUpper(s) {
	case "CRITICAL", "CONFIRMED":
		return diagnostics.Critical
	case "HIGH":
		return diagnostics.High
	case "MEDIUM":
		return diagnostics.Medium
	case "LOW":
		return diagnostics.Low
	case "INFO":
		return diagnostics.Info
	default:
		return diagnostics.High
	}
}

func buildExcludeDefinitionFromExceptions(exceptions []*store.Exception) diagnostics.ExcludeDefinition {
	def := diagnostics.ExcludeDefinition{
		GloballyExcludedRegExs:  []string{},
		GloballyExcludedStrings: []string{},
		GloballyExcludedHashes:  []string{},
		PathExclusionRegExs:     []string{},
		PerFileExcludedStrings:  map[string][]string{},
		PerFileExcludedHashes:   map[string][]string{},
		PathRegexExcludedRegExs: map[string][]string{},
	}

	for _, exc := range exceptions {
		if exc == nil || exc.Status != "active" || exc.Scope == nil {
			continue
		}
		sc := exc.Scope
		switch sc.Type {
		case "globalHash", "value":
			if sc.SecretChecksum != "" {
				def.GloballyExcludedHashes = append(def.GloballyExcludedHashes, sc.SecretChecksum)
			}
		case "globalString":
			if sc.StringMatch != "" {
				def.GloballyExcludedStrings = append(def.GloballyExcludedStrings, sc.StringMatch)
			}
		case "globalRegex":
			if sc.RegexMatch != "" {
				def.GloballyExcludedRegExs = append(def.GloballyExcludedRegExs, sc.RegexMatch)
			}
		case "pathRegex":
			if sc.RegexMatch != "" {
				def.PathExclusionRegExs = append(def.PathExclusionRegExs, sc.RegexMatch)
			}
		case "pathString":
			if sc.Path != "" && sc.StringMatch != "" {
				def.PerFileExcludedStrings[sc.Path] = append(def.PerFileExcludedStrings[sc.Path], sc.StringMatch)
			}
		case "pathHash":
			if sc.Path != "" && sc.SecretChecksum != "" {
				def.PerFileExcludedHashes[sc.Path] = append(def.PerFileExcludedHashes[sc.Path], sc.SecretChecksum)
			}
		case "pathRegexRegex":
			if sc.Path != "" && sc.RegexMatch != "" {
				def.PathRegexExcludedRegExs[sc.Path] = append(def.PathRegexExcludedRegExs[sc.Path], sc.RegexMatch)
			}
		}
	}

	return def
}
