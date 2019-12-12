package common

import (
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/common/util"
	"strings"
)

var (
	//AppName is the application name
	AppName        = "checkmate"
	sourceFileExts = "java,scala,groovy,jsp,do,jad,c,cc,cxx,cpp,cp,c++,bcc,php2,php,c--,hc,hpp,hxx,m,swift,h,cs,c#,vb,vba,vbs,aspx,py,pyt,rb,erb,lua,asmx,f,f95,ash,tcl,ml,pl,cbl"
	//SourceFileExtensions extensions for source code
	SourceFileExtensions = makeMap(sourceFileExts)
	//TextFileExtensions file name extensions for textual files
	TextFileExtensions = makeMap("txt,xml,docx,xlsx,pptx,odt,fodt,ods,fods,odp,fodp,odb,js,json,yml,yaml,md,cnf,conf,config,sh,zsh,bash,cmd,sql,bat,pp,key,csr,crt,pem,csv,cf,pre,htm,html," + sourceFileExts)
)

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

//RegisterDiagnosticsConsumer registers a callback to consume diagnostics
func RegisterDiagnosticsConsumer(callback func(d diagnostics.SecurityDiagnostic), providers ...SourceToSecurityDiagnostics) {
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
