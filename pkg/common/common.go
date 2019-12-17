package common

import (
	"path/filepath"
	"strings"

	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/common/util"
)

//IsConfidentialFile indicates whether a file is potentially confidential based on its name or extension, with a narrative indicating
//what sort of file it may be if it is potentially condidential
func IsConfidentialFile(path string) (bool, string) {
	// var narrative string
	// var truth bool
	extension := filepath.Ext(path)
	baseName := strings.TrimSuffix(filepath.Base(path), extension)
	if narrative, present := DangerousFileNames[baseName]; present {
		return present, narrative
	}

	if narrative, present := CertsAndKeyStores[extension]; present {
		return present, narrative
	}

	if narrative, present := DangerousExtensions[extension]; present {
		return present, narrative
	}

	if narrative, present := FinancialAndAccountingExtensions[extension]; present && !excludeName(baseName) {
		return present, narrative
	}

	return false, ""
}

func excludeName(basname string) bool {
	switch strings.ToLower(basname) {
	case "readme", "changelog":
		return true
	}
	return false
}

func appendMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k := range m {
			if v, present := result[k]; present {
				data := []string{}
				if strings.TrimSpace(m[k]) != "" {
					data = append(data, m[k])
				}
				if strings.TrimSpace(v) != "" {
					data = append(data, v)
				}
				result[k] = strings.Join(data, " or ")
			} else {
				result[k] = m[k]
			}
		}
	}
	return result
}

func makeMap(elements string) map[string]string {
	result := make(map[string]string)
	var nothing string
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
