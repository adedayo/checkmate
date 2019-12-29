package lsp

import (
	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common/code"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	lspCode "github.com/adedayo/go-lsp/pkg/code"
	"github.com/adedayo/go-lsp/pkg/lsp"
)

func convert(in diagnostics.SecurityDiagnostic) lsp.Diagnostic {
	source := common.AppName
	out := lsp.Diagnostic{
		Range:    copyCode(in.Range),
		Severity: convertConfidence(in.Justification.Headline.Confidence),
		Code:     &lsp.DiagnosticCode{StringID: in.Justification.Headline.Description},
		Message:  in.Justification.Headline.Description,
		Source:   &source,
	}
	return out
}

func copyCode(in code.Range) lspCode.Range {
	out := lspCode.Range{}
	out.Start.Line = in.Start.Line
	out.Start.Character = in.Start.Character
	out.End.Line = in.End.Line
	out.End.Character = in.End.Character

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
