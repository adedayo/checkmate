package common

import (
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/common/util"
	"path/filepath"
	"strings"
)

//IsConfidentialFile indicates whether a file is potentially confidential based on its name or extension, with a narrative indicating
//what sort of file it may be if it is potentially condidential
func IsConfidentialFile(path string) (bool, string) {
	// var narrative string
	// var truth bool
	baseName := filepath.Base(path)
	if narrative, present := DangerousFileNames[baseName]; present {
		return present, narrative
	}
	extension := filepath.Ext(path)

	if narrative, present := CertsAndKeyStores[extension]; present {
		return present, narrative

	}

	if narrative, present := DangerousExtensions[extension]; present {
		return present, narrative

	}
	if narrative, present := FinancialAndAccountingExtensions[extension]; present {
		return present, narrative

	}

	return false, ""
}

func makeMap(elements string) map[string]struct{} {
	result := make(map[string]struct{})
	var nothing struct{}
	for _, s := range strings.Split(elements, ",") {
		result["."+s] = nothing
	}
	return result
}

//SourceToSecurityDiagnostics is an interface that describes an object that can consume source and generate security diagnostics
type SourceToSecurityDiagnostics interface {
	util.SourceConsumer
	diagnostics.SecurityDiagnosticsProvider
}

//PathToSecurityDiagnostics is an interface that describes an object that can consume a file path or URI and generate security diagnostics
type PathToSecurityDiagnostics interface {
	util.PathConsumer
	diagnostics.SecurityDiagnosticsProvider
}

//RegisterDiagnosticsConsumer registers a callback to consume diagnostics
func RegisterDiagnosticsConsumer(callback func(d diagnostics.SecurityDiagnostic), providers ...diagnostics.SecurityDiagnosticsProvider) {
	consumer := c{
		callback: callback,
	}
	for _, p := range providers {
		p.AddConsumers(consumer)
	}
}

type c struct {
	callback func(d diagnostics.SecurityDiagnostic)
}

func (n c) ReceiveDiagnostic(diagnostic diagnostics.SecurityDiagnostic) {
	n.callback(diagnostic)
}

//DiagnosticsAggregator implements a strategy for aggregating diagnostics, e.g. removing duplicates, overlap, less sever issues etc.
type DiagnosticsAggregator interface {
	AddDiagnostic(diagnostic diagnostics.SecurityDiagnostic)
	Aggregate() []diagnostics.SecurityDiagnostic //Called when aggregation strategy is required to be run
}

type simpleDiagnosticAggregator struct {
	// input       chan diagnostics.SecurityDiagnostic
	diagnostics []diagnostics.SecurityDiagnostic
}

func (sda *simpleDiagnosticAggregator) AddDiagnostic(diagnostic diagnostics.SecurityDiagnostic) {
	sda.diagnostics = append(sda.diagnostics, diagnostic)
}

func (sda *simpleDiagnosticAggregator) Aggregate() (agg []diagnostics.SecurityDiagnostic) {
	excluded := make(map[int]bool)
	diagnostics := sda.diagnostics
	for i, di := range diagnostics {
		for j, dj := range diagnostics {
			if j != i {
				if dj.Range.Contains(di.Range) && di.Justification.Headline.Confidence <= dj.Justification.Headline.Confidence {
					excluded[i] = true
					break
				}
			}
		}
	}

	for i, di := range diagnostics {
		if !excluded[i] {
			agg = append(agg, di)
		}
	}
	return
}

//MakeSimpleAggregator creates a diagnostics aggregator that removes diagnostics whose range is completely
//overlapped by another diagnostic's range
func MakeSimpleAggregator() DiagnosticsAggregator {
	return &simpleDiagnosticAggregator{}
}
