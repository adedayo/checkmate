package lsp

import (
	"crypto/sha256"
	"fmt"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

var diagnosticSource = common.AppDisplayName

// convertDiagnostic maps an internal SecurityDiagnostic into an LSP 3.17
// Diagnostic with accurate severity, 0-based range, rule code, CheckMate
// source, and structured data for Quick Fix Code Actions.
func convertDiagnostic(in *diagnostics.SecurityDiagnostic, filePath string) Diagnostic {
	ruleID := in.Justification.Headline.Description
	conf := in.Justification.Headline.Confidence

	reasons := []string{
		fmt.Sprintf("Problem: %s (Confidence: %s).", ruleID, conf.String()),
	}
	if len(in.Justification.Reasons) > 0 {
		reasons = append(reasons, "Analysis:")
		for i, reason := range in.Justification.Reasons {
			reasons = append(reasons, fmt.Sprintf("  %d. %s (%s confidence).", i+1, reason.Description, reason.Confidence.String()))
		}
	}

	checksum := ""
	if in.SHA256 != nil {
		checksum = *in.SHA256
	}
	loc := filePath
	if loc == "" && in.Location != nil {
		loc = *in.Location
	}

	line := int(in.Range.Start.Line) + 1
	col := int(in.Range.Start.Character) + 1
	findingID := in.ID
	if findingID == "" {
		findingID = computeStableFindingID(ruleID, "", loc, line, col, checksum)
	}

	return Diagnostic{
		Range:    convertRange(in.Range),
		Severity: convertConfidence(conf),
		Code:     ruleID,
		Source:   diagnosticSource,
		Message:  strings.Join(reasons, "\n"),
		Data: &DiagnosticData{
			FindingID:      findingID,
			SecretChecksum: checksum,
			RuleID:         ruleID,
		},
	}
}

func computeStableFindingID(rule, repo, file string, line, column int, checksum string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s:%s:%d:%d:%s", rule, repo, file, line, column, checksum)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func convertRange(in code.Range) Range {
	startLine := int(in.Start.Line)
	startChar := int(in.Start.Character)
	endLine := int(in.End.Line)
	endChar := int(in.End.Character)
	if startLine < 0 {
		startLine = 0
	}
	if startChar < 0 {
		startChar = 0
	}
	if endLine < startLine {
		endLine = startLine
	}
	if endLine == startLine && endChar < startChar {
		endChar = startChar
	}
	return Range{
		Start: Position{Line: startLine, Character: startChar},
		End:   Position{Line: endLine, Character: endChar},
	}
}

func convertConfidence(confidence diagnostics.Confidence) DiagnosticSeverity {
	switch confidence {
	case diagnostics.Critical, diagnostics.High:
		return SeverityError
	case diagnostics.Medium:
		return SeverityWarning
	case diagnostics.Low:
		return SeverityInformation
	default:
		return SeverityHint
	}
}

