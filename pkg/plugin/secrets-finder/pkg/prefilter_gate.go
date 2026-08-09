package secrets

import (
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/util"
	"github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg/prefilter"
)

// vendorMatcher is the shared, immutable prefilter automaton over the vendor
// rule set.
//
// Built lazily and exactly once. It is read-only after construction, so every
// scan worker shares this one instance; only the per-worker candidate Set is
// mutable. Building it costs a few milliseconds and a few megabytes, which is
// why it must not be per worker, and OnceValue rather than init() keeps that
// cost off the startup path of commands that never scan.
var vendorMatcher = sync.OnceValue(func() *prefilter.Matcher {
	return prefilter.Build(vendorSecrets)
})

// prefilterEnabled reports whether rule gating should be applied.
//
// The environment variable is an operator escape hatch: if the prefilter is
// ever suspected of hiding a finding, CHECKMATE_DISABLE_PREFILTER=1 restores
// the exhaustive behaviour without a rebuild or a downgrade. It is also what
// lets the equivalence test run the same corpus both ways.
func prefilterEnabled(options SecretSearchOptions) bool {
	if options.DisablePrefilter {
		return false
	}
	if v, ok := os.LookupEnv("CHECKMATE_DISABLE_PREFILTER"); ok {
		if disabled, err := strconv.ParseBool(v); err == nil && disabled {
			return false
		}
	}
	return true
}

// ruleGate decides, once per file, which vendor rules can possibly match.
//
// # Why this is a ResourceConsumer
//
// The gate needs the file content before any rule runs, and the content is
// delivered by the resource multiplexer. Rather than change the multiplexer's
// signature or read the file a second time, the gate registers as an ordinary
// consumer and is placed *first* in the consumer list. The multiplexer invokes
// consumers synchronously in their declared order, so by the time any finder's
// Consume is called, candidates for that same content are already computed.
//
// That ordering is load-bearing, and ScanContext is the only thing that
// constructs a gate, which is what keeps the invariant local enough to hold.
// TestPrefilterGateRunsBeforeFinders pins it.
//
// # Chunked sources
//
// For sources above MaxInMemoryFileSize the multiplexer delivers several
// chunks. The gate simply recomputes per chunk, which is correct: a rule is
// admitted for the chunk it might match in. It cannot match across a chunk
// boundary in any case, because the multiplexer hands each chunk to the rules
// independently.
type ruleGate struct {
	matcher *prefilter.Matcher
	set     *prefilter.Set
	// classifySet is a second, independent candidate set used by
	// detectSecret's vendor classification.
	//
	// It is separate from `set` because the two are computed over different
	// inputs: `set` covers the whole file, this one covers a single extracted
	// candidate secret. Sharing one would let classification clobber the
	// file-level set halfway through a file's finders.
	//
	// Like `set`, it is per-worker and reused across candidates, so
	// classification allocates nothing.
	classifySet *prefilter.Set
	// active is false when gating is disabled, in which case allows() is
	// always true and no automaton pass is made at all.
	active bool
}

func newRuleGate(options SecretSearchOptions) *ruleGate {
	if !prefilterEnabled(options) {
		if options.Verbose {
			logPrefilterOnce.Do(func() {
				log.Printf("secrets: prefilter disabled; all %d vendor rules will be evaluated against every file",
					len(vendorSecrets))
			})
		}
		return &ruleGate{active: false}
	}
	m := vendorMatcher()

	if options.Verbose {
		// Logged once per process, not per worker. The residual count is the
		// number that predicts scan cost on ordinary source, since those rules
		// run against every file regardless of content — so it is the useful
		// thing to surface when someone is investigating slow scans.
		logPrefilterOnce.Do(func() {
			log.Printf("secrets: prefilter active; %d of %d vendor rules carry a provable literal, %d residual (always evaluated)",
				m.NumRules()-len(m.Residual()), m.NumRules(), len(m.Residual()))
		})
	}

	return &ruleGate{matcher: m, set: m.NewSet(), classifySet: m.NewSet(), active: true}
}

// vendorCandidates returns the rules that could match this candidate secret,
// or nil when gating is disabled (meaning "evaluate everything").
//
// # Why this makes its own automaton pass rather than reusing the file's set
//
// The file-level set is a valid superset for any substring of the file, so
// reusing it looks free — and it very nearly is. But detectSecret does not
// classify the substring; it classifies `strings.ToLower(substring)`, and the
// two foldings do not agree. The automaton folds ASCII only, while
// strings.ToLower is Unicode-aware: U+212A KELVIN SIGN lowercases to an
// ordinary ASCII "k", which the automaton would never have seen when it read
// the raw file. A rule seeded on a literal containing "k" could then match the
// lowered candidate while absent from the file's candidate set — an
// under-admission, which is the one error the prefilter must never make,
// because it loses findings silently.
//
// Running the automaton over the exact string the regexes will be given
// removes the argument entirely rather than relying on it holding. The cost is
// one linear pass per candidate, against the hundreds of full regex
// evaluations it replaces.
func (g *ruleGate) vendorCandidates(data string) *prefilter.Set {
	if g == nil || !g.active {
		return nil
	}
	g.matcher.Candidates([]byte(data), g.classifySet)
	return g.classifySet
}

// logPrefilterOnce keeps the startup summary to a single line per process
// rather than one per worker.
var logPrefilterOnce sync.Once

// allows reports whether the rule at ruleIndex could match the current
// content. A negative index means "not a gated rule", which is the case for
// every generic finder and for any vendor rule the prefilter could not prove a
// seed for.
func (g *ruleGate) allows(ruleIndex int) bool {
	if !g.active || ruleIndex < 0 {
		return true
	}
	return g.set.Has(ruleIndex)
}

// indexOf returns the gate index for a provider ID, or -1 if the rule is not
// gated.
func (g *ruleGate) indexOf(providerID string) int {
	if !g.active {
		return -1
	}
	if i, ok := g.matcher.IndexOf(providerID); ok {
		return i
	}
	return -1
}

// Consume computes the candidate set for this content. It is the only method
// that does any work; the gate produces no diagnostics of its own.
func (g *ruleGate) Consume(startIndex int64, source string) {
	if !g.active {
		return
	}
	// The conversion is a no-op copy in practice: Go recognises the
	// []byte(string) pattern in a call argument that does not retain the
	// slice, and Candidates only reads it.
	g.matcher.Candidates([]byte(source), g.set)
}

func (g *ruleGate) ConsumePath(util.RepositoryIndexedFile)       {}
func (g *ruleGate) SetLineIndex(*util.LineIndex)                 {}
func (g *ruleGate) SetRepositoryFile(util.RepositoryIndexedFile) {}
func (g *ruleGate) ShouldProvideSourceInDiagnostics(bool)        {}
func (g *ruleGate) End()                                         {}
