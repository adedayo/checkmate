package secrets

// Phase 0 harness — the golden-corpus equivalence gate.
//
// This is the safety net for the entire 003-scan-engine-performance change.
// Every subsequent phase (streaming walker, worker pool, prefilter, whole-file
// reads, streaming sinks) must leave TestScanEquivalence green.
//
// Recording a new baseline:
//
//	go test ./pkg/plugin/secrets-finder/pkg/ -run TestScanEquivalence -record
//
// The baseline MUST only ever be re-recorded deliberately, with the reason
// stated in the commit message. The one sanctioned re-record during this change
// is Phase 1's RepositoryIndex correction (see proposal.md).

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

var record = flag.Bool("record", false,
	"re-record the golden scan baseline instead of asserting against it")

const goldenPath = "testdata/golden/reference-corpus.json"

// TestScanEquivalence asserts that the engine's finding set over the reference
// corpus is byte-identical to the recorded baseline.
//
// Note the corpus is materialised into a neutrally-named temp directory (see
// corpus_test.go); locations are made relative to that root before comparison,
// so the baseline is portable.
func TestScanEquivalence(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())

	// Both roots are passed as separate scan paths so RepositoryIndex 0 and 1
	// are both exercised. This is what makes the stale-vendorFinders defect
	// visible in the baseline.
	repoA := filepath.Join(root, "repo-a")
	repoB := filepath.Join(root, "repo-b")

	run := runScan(t, baselineOptions(), repoA, repoB)
	if len(run.Findings) == 0 {
		t.Fatal("reference corpus produced no findings; the harness is not " +
			"exercising the engine and would give a false-green baseline")
	}

	actual, err := serialiseCanonical(canonicaliseAll(root, run.Findings))
	if err != nil {
		t.Fatalf("serialising findings: %v", err)
	}

	if *record {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("creating golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, actual, 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
		t.Logf("recorded baseline: %d findings across %d files -> %s",
			len(run.Findings), len(run.Files), goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file (run with -record to create it): %v", err)
	}

	if !bytes.Equal(expected, actual) {
		// Write the actual output next to the golden file so the diff can be
		// inspected directly rather than reconstructed from test output.
		actualPath := goldenPath + ".actual"
		_ = os.WriteFile(actualPath, actual, 0o644)
		t.Fatalf("scan results diverged from the recorded baseline.\n"+
			"  expected: %s\n"+
			"  actual:   %s\n"+
			"Run `diff %s %s` to inspect.\n"+
			"This change is performance-only: any divergence is a defect "+
			"unless it is the sanctioned RepositoryIndex correction.",
			goldenPath, actualPath, goldenPath, actualPath)
	}
}

// TestCanonicalOrderIsTotal guards the comparison mechanism itself.
//
// Once scanning is parallelised, emission order becomes nondeterministic. If
// canonicalKey were not a total order over the corpus, equal keys would sort
// arbitrarily and TestScanEquivalence would flake — masking real regressions
// behind spurious failures, or worse, passing by luck. This asserts up front
// that no two distinct findings share a key.
func TestCanonicalOrderIsTotal(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	run := runScan(t, baselineOptions(),
		filepath.Join(root, "repo-a"), filepath.Join(root, "repo-b"))

	findings := canonicaliseAll(root, run.Findings)
	seen := make(map[string]canonicalFinding, len(findings))
	for _, f := range findings {
		k := canonicalKey(f)
		if prev, dup := seen[k]; dup {
			t.Errorf("canonical key collision — ordering is not total:\n"+
				"  key:   %q\n  first: %+v\n  second: %+v", k, prev, f)
		}
		seen[k] = f
	}
}

// TestCanonicaliseIsStable asserts canonicalisation is deterministic and
// order-independent: shuffling the input must not change the output. This is
// precisely the property the parallel engine will rely on.
func TestCanonicaliseIsStable(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	run := runScan(t, baselineOptions(), filepath.Join(root, "repo-a"))

	forward, err := serialiseCanonical(canonicaliseAll(root, run.Findings))
	if err != nil {
		t.Fatalf("serialising forward: %v", err)
	}

	// Reverse the emission order — the cheapest permutation that would break
	// any accidental reliance on input ordering.
	rev := make([]*diagnostics.SecurityDiagnostic, len(run.Findings))
	for i, d := range run.Findings {
		rev[len(run.Findings)-1-i] = d
	}

	backward, err := serialiseCanonical(canonicaliseAll(root, rev))
	if err != nil {
		t.Fatalf("serialising backward: %v", err)
	}

	if !bytes.Equal(forward, backward) {
		t.Error("canonicalisation is order-dependent; the equivalence test " +
			"would flake once scanning is parallelised")
	}
}
