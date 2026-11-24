package secrets

// ScanContext holds the reusable, per-worker state needed to scan files.
//
// Motivation
//
// The engine previously built a complete finder set for every single file:
// GetFinderForFileType constructed a fresh defaultMatchProvider containing all
// 222 imported Gitleaks rules, the built-in vendor rules and the
// language-specific assignment/string finders. Measured on the reference
// corpus that is 460 allocations, 64KB and ~25-38µs per file — spent before a
// single byte is matched, and accounting for roughly half of all allocations
// during a scan.
//
// A ScanContext builds each provider variant exactly once and reuses it across
// every file the owning worker handles. Per-file state (the file itself and
// its line index) is supplied through the resource multiplexer for each file,
// so the finders themselves stay immutable after construction.
//
// Concurrency
//
// A ScanContext is NOT safe for concurrent use. It is deliberately
// single-threaded state: the parallel engine gives each worker its own
// context, which is what makes reuse safe without locking. Sharing one across
// goroutines would reintroduce exactly the cross-file interference that the
// old global finder cache suffered from.

import (
	"io"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// finderClass identifies a group of file extensions that share a MatchProvider.
type finderClass string

const (
	classJava    finderClass = "java"
	classCPP     finderClass = "cpp"
	classXML     finderClass = "xml"
	classYAML    finderClass = "yaml"
	classRuby    finderClass = "ruby"
	classERuby   finderClass = "eruby"
	classConf    finderClass = "conf"
	classDefault finderClass = "default"
)

// classForExtension maps a file extension onto its finder class. It mirrors
// the switch in GetFinderForFileType exactly; the two must stay in step, which
// TestScanContextMatchesGetFinderForFileType enforces.
func classForExtension(fileType string) finderClass {
	switch strings.ToLower(fileType) {
	case ".java", ".scala", ".kt", ".go":
		return classJava
	case ".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp", ".hxx":
		return classCPP
	case ".xml":
		return classXML
	case ".yaml", ".yml", ".json":
		return classYAML
	case ".rb":
		return classRuby
	case ".erb":
		return classERuby
	case ".conf":
		return classConf
	default:
		return classDefault
	}
}

// ScanContext is a reusable set of secret finders plus the plumbing needed to
// collect their output. Create one per worker with NewScanContext and call
// FindSecretsInFile for each file.
type ScanContext struct {
	options   SecretSearchOptions
	providers map[finderClass]MatchProvider
	// consumers caches the ResourceConsumer view of each provider's finders so
	// the type assertions are not repeated for every file.
	//
	// The gate is element zero of each of these slices. See newRuleGate for
	// why the position matters.
	consumers map[finderClass][]util.ResourceConsumer
	// gate is shared across all classes because only one class is used per
	// file and the gate is refreshed from that file's content before any
	// finder sees it.
	gate *ruleGate
	// inlineIgnore tracks 0-based line numbers suppressed via inline
	// `checkmate:ignore` or `checkmate:ignore-next-line` directives.
	inlineIgnore *inlineIgnoreTracker
	// aggregator is the collector for the file currently being scanned. The
	// diagnostic callbacks registered once at construction read it through the
	// context, which is how a single registration can serve every file without
	// the consumer list growing per file.
	aggregator common.DiagnosticsAggregator
}

// NewScanContext creates a reusable per-worker scan context whose extension
// provider classes are constructed lazily on first use.
//
// Lazy construction keeps short-lived single-file or small-diff scans (such as
// git pre-commit hooks) from paying to wire up all 8 finder classes when only
// one or two file types are scanned, while retaining full reuse across files.
func NewScanContext(options SecretSearchOptions) *ScanContext {
	return &ScanContext{
		options:      options,
		providers:    make(map[finderClass]MatchProvider, 8),
		consumers:    make(map[finderClass][]util.ResourceConsumer, 8),
		gate:         newRuleGate(options),
		inlineIgnore: &inlineIgnoreTracker{},
	}
}

var allFinderClasses = []finderClass{
	classJava, classCPP, classXML, classYAML,
	classRuby, classERuby, classConf, classDefault,
}

func (sc *ScanContext) ensureClass(class finderClass) {
	if _, ok := sc.consumers[class]; ok {
		return
	}

	var provider MatchProvider
	switch class {
	case classJava:
		provider = NewJavaFinder(sc.options)
	case classCPP:
		provider = NewCPPSecretsFinders(sc.options)
	case classXML:
		provider = NewXMLSecretsFinders(sc.options)
	case classYAML:
		provider = NewYamlSecretsFinders(sc.options)
	case classRuby:
		provider = NewRubySecretsFinders(sc.options)
	case classERuby:
		provider = NewERubySecretsFinders(sc.options)
	case classConf:
		provider = NewConfigurationSecretsFinder(sc.options)
	default:
		provider = defaultFinder(sc.options)
	}

	collect := func(diagnostic *diagnostics.SecurityDiagnostic) {
		// aggregator is nil only if a finder broadcasts outside a
		// FindSecretsInFile call, which would be a bug; drop rather than panic.
		if sc.aggregator != nil {
			sc.aggregator.AddDiagnostic(diagnostic)
		}
	}

	finders := provider.GetFinders()
	diagProviders := make([]diagnostics.SecurityDiagnosticsProvider, 0, len(finders))

	// The gate must be the first consumer: the multiplexer invokes
	// consumers in order, so it has to compute the candidate set for the
	// content before any rule is asked whether it may run.
	resourceConsumers := make([]util.ResourceConsumer, 0, len(finders)+2)
	resourceConsumers = append(resourceConsumers, sc.gate, sc.inlineIgnore)

	for _, f := range finders {
		diagProviders = append(diagProviders, f.(diagnostics.SecurityDiagnosticsProvider))
		resourceConsumers = append(resourceConsumers, f.(util.ResourceConsumer))

		// Attach the gate to every finder that can carry one. Vendor rules
		// resolve to a real gate index and are skipped outright when their
		// literal is absent; the generic assignment and string finders
		// resolve to -1 and always run, but still need the gate so that
		// the vendor classification they perform per candidate value
		// (detectSecret → isVendorSecret) is gated too. That path was the
		// dominant cost in the engine while it was not.
		if gf, ok := f.(gatedFinder); ok {
			gf.attachGate(sc.gate)
		}
	}
	common.RegisterDiagnosticsConsumer(collect, diagProviders...)

	sc.providers[class] = provider
	sc.consumers[class] = resourceConsumers
}

func (sc *ScanContext) providerFor(class finderClass) MatchProvider {
	sc.ensureClass(class)
	return sc.providers[class]
}

// FindSecretsInFile scans a single file and returns its aggregated
// diagnostics.
//
// This is the reusing equivalent of FindSecret: same finders, same aggregation
// and overlap-removal semantics, but without constructing a provider or
// registering consumers per file. Unlike FindSecret it returns a slice rather
// than a channel — the results are fully aggregated before being returned in
// either case, so the channel bought nothing but an extra goroutine and
// unbuffered handoff per file.
func (sc *ScanContext) FindSecretsInFile(rif util.RepositoryIndexedFile, source io.Reader,
	fileType string, provideSource bool) []*diagnostics.SecurityDiagnostic {

	class := classForExtension(fileType)
	sc.ensureClass(class)
	consumers := sc.consumers[class]

	sc.inlineIgnore.Reset()
	sc.aggregator = common.MakeSimpleAggregator()
	defer func() { sc.aggregator = nil }()

	// The multiplexer supplies per-file state (line index, repository-indexed
	// file, source toggle) to each consumer before streaming the content.
	util.NewResourceMultiplexer(rif, &source, provideSource, consumers...)

	return sc.inlineIgnore.Filter(sc.aggregator.Aggregate())
}

// Options returns the search options this context was built with.
func (sc *ScanContext) Options() SecretSearchOptions {
	return sc.options
}
