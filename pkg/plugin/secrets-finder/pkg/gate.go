package secrets

// The gate stage.
//
// Every path consumer used to open the file with the same set of cheap
// questions already answered privately: is this a test file, is it excluded,
// what is its extension, is it a confidential file. With two consumers
// registered — confidentialFilesFinder and pathBasedSourceSecretFinder — each
// of those questions was asked twice per file, and the two most expensive of
// them (a leading-`.*` case-insensitive regex and a linear walk of the
// exclusion regex list) are pure functions of the path.
//
// pathGate computes them once per file and hands the verdicts to every
// consumer. It is deliberately a *value* carrying answers rather than a
// component that decides what to do with them: the two consumers report
// ignored files differently (different provider IDs, different payloads), and
// collapsing that here would change the diagnostics the engine emits.

import (
	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	util "github.com/adedayo/checkmate/pkg/core/util"
)

// pathGate holds the per-file verdicts shared by all path consumers.
//
// Ordered by ascending cost of computation, which is also the order in which
// consumers ask for them.
type pathGate struct {
	//Path is the file as reported by the walk.
	Path string
	//Ext is filepath.Ext(Path), lowercase-sensitive exactly as before.
	Ext string
	//IsTestFile is the historic "path contains test" verdict. See isTestPath.
	IsTestFile bool
	//ExcludedPath is the exclusion provider's verdict for the path.
	ExcludedPath bool
	//Confidential and ConfidentialWhy are common.IsConfidentialFile's verdict.
	Confidential    bool
	ConfidentialWhy string
}

// newPathGate answers the cheap per-file questions once.
func newPathGate(rif util.RepositoryIndexedFile, exclusions diagnostics.ExclusionProvider) *pathGate {
	path := rif.File

	g := &pathGate{
		Path:       path,
		Ext:        fileExtension(path),
		IsTestFile: isTestPath(path),
	}

	//A nil provider is not expected on the scan path — the options always
	//carry one — but a nil-check is cheaper than the panic that would
	//otherwise reach a user mid-scan, and "exclude nothing" is the safe
	//direction: it can only add findings, never silently drop them.
	if exclusions != nil {
		g.ExcludedPath = exclusions.ShouldExcludePath(path)
	}

	g.Confidential, g.ConfidentialWhy = common.IsConfidentialFile(path)

	return g
}

// gatedPathConsumer is a path consumer that can accept pre-computed gate
// verdicts instead of recomputing them.
//
// Consumers still implement ConsumePath, so they remain usable with the plain
// multiplexer (and in tests) — ConsumePath simply builds a gate of its own.
type gatedPathConsumer interface {
	util.PathConsumer
	consumePathGated(rif util.RepositoryIndexedFile, gate *pathGate)
}

// gatedPathMultiplexer computes the gate once per file and passes it to each
// consumer, in the order they were registered.
//
// Order is preserved deliberately: consumers broadcast diagnostics as they go,
// and the aggregation downstream resolves overlapping findings by arrival
// order in some paths. Changing consumer order here would change output.
type gatedPathMultiplexer struct {
	exclusions diagnostics.ExclusionProvider
	consumers  []util.PathConsumer
}

// newGatedPathMultiplexer builds a multiplexer that shares one gate evaluation
// across all consumers.
func newGatedPathMultiplexer(exclusions diagnostics.ExclusionProvider,
	consumers ...util.PathConsumer) util.PathMultiplexer {
	m := &gatedPathMultiplexer{exclusions: exclusions}
	m.SetPathConsumers(consumers...)
	return m
}

func (m *gatedPathMultiplexer) SetPathConsumers(consumers ...util.PathConsumer) {
	m.consumers = consumers
}

func (m *gatedPathMultiplexer) ConsumePath(rif util.RepositoryIndexedFile) {
	gate := newPathGate(rif, m.exclusions)
	for _, c := range m.consumers {
		if gc, ok := c.(gatedPathConsumer); ok {
			gc.consumePathGated(rif, gate)
			continue
		}
		//A consumer that predates the gate still works; it just pays for its
		//own checks.
		c.ConsumePath(rif)
	}
}

// fileExtension is filepath.Ext without the function call overhead in the hot
// path: the extension is the suffix from the final dot, and a separator seen
// first means there is none.
func fileExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		switch path[i] {
		case '/', '\\':
			return ""
		case '.':
			return path[i:]
		}
	}
	return ""
}

// isTestPath reports whether the path is treated as a test file.
//
// This replaces testFile.MatchString, which compiled to
// `(?i:.*test.*)` — an unanchored, case-insensitive substring search wrapped in
// two leading/trailing `.*`. The regex engine cannot know the pattern is that
// simple, so it paid full machinery for what is a substring scan, on every
// file, twice.
//
// The rewrite is *not* a plain strings.Contains on a lowercased path, though
// that is the obvious translation and is what the design proposed. Go's `(?i)`
// applies full Unicode simple case folding, so `(?i:s)` also matches U+017F
// (LATIN SMALL LETTER LONG S) — `(?i:.*test.*)` genuinely matches "teſt", and
// strings.ToLower leaves U+017F alone, so the obvious translation loses that
// path's "test" tag. It is the same trap the prefilter's seed extraction hit
// in Phase 4.2, and the direction of the error is the bad one: a file silently
// stops being recognised as a test file.
//
// So: an allocation-free ASCII fold scan for the overwhelmingly common case,
// and the original regex — not a paraphrase of it — for the vanishingly rare
// path that contains a non-ASCII byte and did not already match.
func isTestPath(path string) bool {
	if containsASCIIFold(path, "test") {
		return true
	}
	if isASCII(path) {
		return false
	}
	return testFile.MatchString(path)
}

// containsASCIIFold reports whether lower occurs in s under ASCII
// case-insensitive comparison. lower must already be lowercase ASCII.
//
// Unlike strings.Contains(strings.ToLower(s), lower) this allocates nothing:
// the lowercased copy of every scanned path was itself a per-file allocation.
func containsASCIIFold(s, lower string) bool {
	n := len(lower)
	if n == 0 {
		return true
	}
	if len(s) < n {
		return false
	}

	first := lower[0]
	for i := 0; i <= len(s)-n; i++ {
		if toLowerASCII(s[i]) != first {
			continue
		}
		j := 1
		for ; j < n; j++ {
			if toLowerASCII(s[i+j]) != lower[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

func toLowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// containsWhitespace reports whether s contains a character matched by the
// regex `\s`.
//
// Go's `\s` is the Perl class [\t\n\f\r ] — ASCII only, and notably *not*
// including \v — so a five-way byte comparison is exactly equivalent.
//
// It replaces two shapes on the matching hot path:
//
//	space.FindAllStringIndex(s, -1) == nil   // "has no whitespace"
//	space.FindStringSubmatchIndex(s) != nil  // "has whitespace"
//
// The first is the expensive one: FindAllStringIndex builds a slice of every
// match in the string purely to compare the result against nil, so a value
// full of spaces allocated one two-element slice per space. Both are called
// per candidate match, which on a base64 blob is a great many times.
//
// TestWhitespaceCheckMatchesRegex pins the equivalence over random input.
func containsWhitespace(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\f', '\r':
			return true
		}
	}
	return false
}

// exclusionPruneDirs adapts an exclusion provider to the walker's PruneDirs
// predicate, so a subtree the operator has genuinely excluded is never
// descended into rather than being rejected once per contained file.
//
// It returns nil — meaning "no pruning" — unless the provider can prove a
// directory-level verdict. See diagnostics.DirectoryPruner for why only some
// exclusion patterns can produce one, and Phase 5.10 for why we refuse to
// guess: pruning a directory removes its files from the scan outright, so an
// unsound prune loses real findings silently.
func exclusionPruneDirs(exclusions diagnostics.ExclusionProvider) func(path, name string) bool {
	pruner, ok := exclusions.(diagnostics.DirectoryPruner)
	if !ok || !pruner.HasPrunableDirectories() {
		return nil
	}

	return func(path, _ string) bool {
		return pruner.ShouldPruneDirectory(path)
	}
}
