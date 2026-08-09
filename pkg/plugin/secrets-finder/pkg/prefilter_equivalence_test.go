package secrets

// Phase 4 — prefilter equivalence and gating guards.
//
// The prefilter is the only optimisation in this change that can, if wrong,
// silently *remove* findings rather than merely slow things down or crash.
// Every other phase either produces the same output or fails loudly. So it
// gets its own equivalence gate in addition to the golden baseline.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/util"
)

// TestPrefilterEquivalence scans the whole reference corpus twice — once with
// rule gating on, once with it off — and asserts the finding sets are
// byte-identical.
//
// This is a stronger statement than the golden baseline. The baseline says the
// gated engine matches a recording; this says the gated and ungated engines
// agree with each other *right now*, over the same corpus, so a seed-extraction
// mistake cannot hide behind a baseline that was recorded after the mistake was
// introduced.
func TestPrefilterEquivalence(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	repoA := filepath.Join(root, "repo-a")
	repoB := filepath.Join(root, "repo-b")

	gated := baselineOptions()
	gated.DisablePrefilter = false

	ungated := baselineOptions()
	ungated.DisablePrefilter = true

	withPrefilter := runScan(t, gated, repoA, repoB)
	withoutPrefilter := runScan(t, ungated, repoA, repoB)

	if len(withoutPrefilter.Findings) == 0 {
		t.Fatal("corpus produced no findings; the comparison would be vacuous")
	}

	a, err := serialiseCanonical(canonicaliseAll(root, withPrefilter.Findings))
	if err != nil {
		t.Fatalf("serialising prefiltered findings: %v", err)
	}
	b, err := serialiseCanonical(canonicaliseAll(root, withoutPrefilter.Findings))
	if err != nil {
		t.Fatalf("serialising unfiltered findings: %v", err)
	}

	if string(a) != string(b) {
		t.Errorf("prefilter changed the finding set: %d findings with, %d without.\n"+
			"The prefilter must only ever skip rules that could not have matched, "+
			"so any difference is an unsound seed.\n"+
			"Reproduce the unfiltered run with CHECKMATE_DISABLE_PREFILTER=1.",
			len(withPrefilter.Findings), len(withoutPrefilter.Findings))
	}
}

// TestPrefilterGateRunsBeforeFinders pins the ordering invariant the gate
// depends on.
//
// The gate is a ResourceConsumer that must be invoked before any finder, since
// finders read the candidate set it computes. If it were ever reordered — or
// if the multiplexer began dispatching consumers concurrently, as it once did
// — every gated rule would read a stale or empty set and findings would vanish
// silently. Nothing else in the codebase would notice.
func TestPrefilterGateRunsBeforeFinders(t *testing.T) {
	sc := NewScanContext(baselineOptions())

	for class, consumers := range sc.consumers {
		if len(consumers) == 0 {
			t.Errorf("class %q has no consumers", class)
			continue
		}
		if _, ok := consumers[0].(*ruleGate); !ok {
			t.Errorf("class %q: first consumer is %T, want *ruleGate. "+
				"The gate must run before any finder reads the candidate set.",
				class, consumers[0])
		}
	}
}

// TestGatedFindersSkipOnlyWhenSeedAbsent checks the gate decision directly,
// rather than inferring it from the finding set.
//
// A gate that returned true for everything would pass the equivalence test
// perfectly while delivering no speed-up at all, so equivalence alone cannot
// tell us the gate works — only that it is not harmful.
func TestGatedFindersSkipOnlyWhenSeedAbsent(t *testing.T) {
	sc := NewScanContext(baselineOptions())
	gate := sc.gate

	if !gate.active {
		t.Fatal("gate inactive with default options; prefiltering is off when it should be on")
	}

	// Content with no vendor seeds: only residual rules may be admitted.
	gate.Consume(0, "package main\n\nfunc main() { println(\"hello\") }\n")
	clean := gate.set.Count()

	// Content carrying a GitHub token seed: strictly more rules admitted.
	gate.Consume(0, "token := \"ghp_"+strings.Repeat("a", 36)+"\"\n")
	seeded := gate.set.Count()

	if clean >= seeded {
		t.Errorf("gate admitted %d rules on clean source and %d on seeded source; "+
			"expected strictly more for the seeded content", clean, seeded)
	}

	total := gate.matcher.NumRules()
	if clean >= total {
		t.Errorf("gate admitted %d of %d rules on clean source; "+
			"the prefilter is not actually filtering anything", clean, total)
	}
	t.Logf("clean source admits %d of %d rules (%.1f%% skipped)",
		clean, total, 100*float64(total-clean)/float64(total))
}

// TestDisablePrefilterViaEnvironment covers the operator escape hatch. If the
// environment variable silently did nothing, the documented way to rule the
// prefilter out of an investigation would be useless exactly when it is
// needed.
func TestDisablePrefilterViaEnvironment(t *testing.T) {
	if !prefilterEnabled(baselineOptions()) {
		t.Fatal("prefilter should be enabled by default")
	}

	t.Setenv("CHECKMATE_DISABLE_PREFILTER", "1")
	if prefilterEnabled(baselineOptions()) {
		t.Error("CHECKMATE_DISABLE_PREFILTER=1 did not disable the prefilter")
	}

	t.Setenv("CHECKMATE_DISABLE_PREFILTER", "0")
	if !prefilterEnabled(baselineOptions()) {
		t.Error("CHECKMATE_DISABLE_PREFILTER=0 should leave the prefilter enabled")
	}

	// A malformed value must not silently disable a correctness-relevant
	// optimisation escape hatch in either direction; it is ignored.
	t.Setenv("CHECKMATE_DISABLE_PREFILTER", "yes-please")
	if !prefilterEnabled(baselineOptions()) {
		t.Error("an unparseable value should be ignored, leaving the default")
	}
}

// TestGateIsInertWhenDisabled asserts that disabling gating costs nothing and
// admits everything, so the escape hatch genuinely restores exhaustive
// behaviour.
func TestGateIsInertWhenDisabled(t *testing.T) {
	opts := baselineOptions()
	opts.DisablePrefilter = true

	sc := NewScanContext(opts)
	if sc.gate.active {
		t.Fatal("gate is active despite DisablePrefilter")
	}

	// Every index, including ones that would be gated, must be allowed.
	for _, i := range []int{-1, 0, 1, 50, 224} {
		if !sc.gate.allows(i) {
			t.Errorf("disabled gate rejected rule index %d", i)
		}
	}

	// And no finder should have been given a gate index.
	for class, consumers := range sc.consumers {
		for _, c := range consumers {
			if sf, ok := c.(*secretStringFinder); ok && sf.gateIndex != -1 {
				t.Errorf("class %q: finder %q has gate index %d with prefiltering disabled",
					class, sf.providerID, sf.gateIndex)
			}
		}
	}
}

// BenchmarkScanFileGated measures the end-to-end per-file win, which is the
// number this phase exists to move.
func BenchmarkScanFileGated(b *testing.B) {
	content := strings.Repeat(
		"func handler(w http.ResponseWriter, r *http.Request) {\n"+
			"\tid := r.URL.Query().Get(\"id\")\n"+
			"\tif err := store.Load(ctx, id); err != nil {\n"+
			"\t\thttp.Error(w, err.Error(), 500)\n\t}\n}\n", 100)

	rif := util.RepositoryIndexedFile{RepositoryIndex: 0, File: "bench.go"}

	for _, tc := range []struct {
		name     string
		disabled bool
	}{
		{"prefilter", false},
		{"exhaustive", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			opts := baselineOptions()
			opts.DisablePrefilter = tc.disabled
			sc := NewScanContext(opts)

			b.SetBytes(int64(len(content)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sc.FindSecretsInFile(rif, strings.NewReader(content), ".go", false)
			}
		})
	}
}
