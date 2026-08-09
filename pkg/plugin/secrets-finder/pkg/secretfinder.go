package secrets

import (
	"io"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// FindSecret locates secrets contained in a source that implements `io.Reader` interface using a `MatchProvider`
func FindSecret(rif util.RepositoryIndexedFile, source io.Reader, matcher MatchProvider, shouldProvideSourceInDiagnostics bool) chan *diagnostics.SecurityDiagnostic {
	out := make(chan *diagnostics.SecurityDiagnostic)
	aggregator := common.MakeSimpleAggregator()
	collector := func(diagnostic *diagnostics.SecurityDiagnostic) {
		aggregator.AddDiagnostic(diagnostic)
	}

	go func() {
		defer func() {
			for _, d := range aggregator.Aggregate() {
				out <- d
			}
			close(out)
		}()
		consumers := matcher.GetFinders()

		providers := []diagnostics.SecurityDiagnosticsProvider{}
		for _, c := range consumers {
			providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
		}
		common.RegisterDiagnosticsConsumer(collector, providers...)
		sourceConsumers := []util.ResourceConsumer{}
		for _, c := range consumers {
			sourceConsumers = append(sourceConsumers, c.(util.ResourceConsumer))
		}
		util.NewResourceMultiplexer(rif, &source, shouldProvideSourceInDiagnostics, sourceConsumers...)
	}()
	return out
}
