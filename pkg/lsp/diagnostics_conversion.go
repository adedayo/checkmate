package lsp

import (
	"fmt"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/code"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	lspCode "github.com/adedayo/go-lsp/pkg/code"
	"github.com/adedayo/go-lsp/pkg/lsp"
)

var (
	source = fmt.Sprintf("\n%s ", common.AppDisplayName)
)

func convert(in diagnostics.SecurityDiagnostic) lsp.Diagnostic {

	reasons := []string{fmt.Sprintf("Problem: %s. Confidence Level: %s.",
		in.Justification.Headline.Description,
		in.Justification.Headline.Confidence.String()),
		"Analysis:"}
	for i, reason := range in.Justification.Reasons {
		reasons = append(reasons, fmt.Sprintf("\t %d. %s. %s confidence.", i+1, reason.Description, reason.Confidence.String()))
	}
	out := lsp.Diagnostic{
		Range:    copyCode(in.Range),
		Severity: convertConfidence(in.Justification.Headline.Confidence),
		Code:     &lsp.DiagnosticCode{StringID: in.Justification.Headline.Description},
		Message:  strings.Join(reasons, "\n"),
		Source:   &source,
	}
	return out
}

func copyCode(in code.Range) lspCode.Range {
	out := lspCode.Range{}
	out.Start.Line = int64(in.Start.Line)
	out.Start.Character = int64(in.Start.Character)
	out.End.Line = int64(in.End.Line)
	out.End.Character = int64(in.End.Character)

	return out
}

func convertConfidence(confidence diagnostics.Confidence) *lsp.DiagnosticSeverity {
	var x lsp.DiagnosticSeverity = 4 //Hint
	switch confidence {
	case diagnostics.High:
		x = 1 //Error
	case diagnostics.Medium:
		x = 2 //Warning
	case diagnostics.Low:
		x = 3 //Informational
	}
	return &x
}
