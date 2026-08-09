package secrets

// Phase 0 harness — determinism guards.
//
// These tests exist because the golden baseline caught the engine producing
// different results on identical input across process invocations. The root
// cause was Go's randomised map iteration order feeding structures whose order
// is semantically observable:
//
//   - makeVendorSecretsFinders ranged over `vendorSecrets`, so the finder
//     slice order varied per run. diagnostics.SubsumeOverlapping breaks ties
//     with "keep the earlier index", so the surviving finding's ProviderID,
//     Range and Source all depended on that order.
//   - setupSecretStringsIndicators ranged over `indexedEncodedSecretPatterns`
//     to build a regex ALTERNATION, so the compiled patterns themselves
//     differed per run.
//   - refineConnectURIDetection returned on the first matching connector.
//   - unique() returned map order into serialised exclusion definitions.
//
// The golden test only catches this probabilistically (it needs two runs that
// happen to differ). These tests catch it deterministically, in-process.

import (
	"bytes"
	"path/filepath"
	"sort"
	"testing"
)

// TestVendorFinderOrderIsDeterministic asserts vendor finders are constructed
// in sorted provider-ID order.
//
// This matters beyond tidiness: because SubsumeOverlapping resolves ties by
// position, finder order decides which rule is credited with an overlapping
// secret. That rule name flows into the derived finding ID, so a randomised
// order means the same secret gets a different identity between scans —
// violating the stable-finding-identity guarantee in project.md.
func TestVendorFinderOrderIsDeterministic(t *testing.T) {
	opts := baselineOptions()

	finders := makeVendorSecretsFinders(opts)
	if len(finders) == 0 {
		t.Fatal("no vendor finders constructed")
	}

	ids := make([]string, 0, len(finders))
	for _, f := range finders {
		sf, ok := f.(*secretStringFinder)
		if !ok {
			t.Fatalf("unexpected vendor finder type %T", f)
		}
		ids = append(ids, sf.providerID)
	}

	if !sort.StringsAreSorted(ids) {
		t.Errorf("vendor finder provider IDs are not in sorted order; "+
			"finding attribution will vary between runs.\ngot: %v", ids)
	}
}

// TestSecretStringIndicatorsAreDeterministic asserts the generated alternation
// is stable. The value is computed once at package init, so this checks the
// generator rather than the cached result.
func TestSecretStringIndicatorsAreDeterministic(t *testing.T) {
	first := setupSecretStringsIndicators()
	for i := 0; i < 50; i++ {
		if got := setupSecretStringsIndicators(); got != first {
			t.Fatalf("secret string indicator alternation is unstable:\n"+
				"first: %s\ngot:   %s", first, got)
		}
	}
}

// TestConnectorOrderIsDeterministic asserts connector resolution is stable and
// prefers the most specific connector.
func TestConnectorOrderIsDeterministic(t *testing.T) {
	// `postgresql://` matches both the `postgres` and `postgresql` patterns.
	const uri = "postgresql://user:secretpass@db.internal:5432/app"

	first := refineConnectURIDetection(uri)
	for i := 0; i < 50; i++ {
		if got := refineConnectURIDetection(uri); got != first {
			t.Fatalf("connector description is unstable: %q vs %q", first, got)
		}
	}

	if want := "Postgres Database Connection URI Secret"; first != want {
		t.Errorf("expected the most specific connector to win.\ngot:  %q\nwant: %q",
			first, want)
	}
}

// TestScanIsRepeatable asserts that scanning the same corpus repeatedly within
// one process yields identical results.
//
// This is the guard that originally exposed the defects listed above. The
// golden test only catches them probabilistically — it needs two runs that
// happen to differ — whereas repeated scanning surfaces any state that leaks
// between scans. It is also the property parallel scanning will depend on.
func TestScanIsRepeatable(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	repoA := filepath.Join(root, "repo-a")
	repoB := filepath.Join(root, "repo-b")
	opts := baselineOptions()

	var first []byte
	for i := 0; i < 5; i++ {
		run := runScan(t, opts, repoA, repoB)
		got, err := serialiseCanonical(canonicaliseAll(root, run.Findings))
		if err != nil {
			t.Fatalf("serialising scan %d: %v", i, err)
		}
		if i == 0 {
			first = got
			continue
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("scan %d differed from the first scan in the same "+
				"process — state is leaking between scans", i)
		}
	}
}

// TestVendorSecretEvaluationOrderIsSorted pins the evaluation order shared by
// isVendorSecret and vendor finder construction.
//
// Multiple vendor rules match the same value (a `ghp_…` token matches both
// CheckMate's own GitHub rule and the imported Gitleaks one). isVendorSecret is
// first-match-wins and the description it returns determines the evidence
// confidence, which drives overlap resolution — so this order decides which
// finding survives and what its ID is.
func TestVendorSecretEvaluationOrderIsSorted(t *testing.T) {
	if !sort.StringsAreSorted(sortedVendorSecretIDs) {
		t.Error("vendor secret evaluation order is not sorted")
	}
	if len(sortedVendorSecretIDs) != len(vendorSecrets) {
		t.Errorf("evaluation order covers %d rules but %d are registered",
			len(sortedVendorSecretIDs), len(vendorSecrets))
	}

	const token = "ghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00"
	desc, ok := isVendorSecret(token, nil)
	if !ok {
		t.Fatalf("expected %q to be recognised as a vendor secret", token)
	}
	for i := 0; i < 50; i++ {
		if d, _ := isVendorSecret(token, nil); d != desc {
			t.Fatalf("vendor description is unstable: %q vs %q", desc, d)
		}
	}

	//The same, gated. Gating may only remove rules that could not have
	//matched, so it must not be able to change which rule wins — and this
	//token deliberately matches more than one.
	gate := newRuleGate(SecretSearchOptions{})
	gatedDesc, ok := isVendorSecret(token, gate.vendorCandidates(token))
	if !ok {
		t.Fatalf("gated: expected %q to be recognised as a vendor secret", token)
	}
	if gatedDesc != desc {
		t.Errorf("prefilter changed the winning vendor rule: %q ungated vs %q gated",
			desc, gatedDesc)
	}
}

// TestUniquePreservesOrder asserts `unique` is order-preserving rather than
// map-ordered, since its output is serialised into persisted scan configs.
func TestUniquePreservesOrder(t *testing.T) {
	in := []string{"c", "a", "b", "a", "d", "c"}
	want := []string{"c", "a", "b", "d"}

	got := unique(in)
	if len(got) != len(want) {
		t.Fatalf("unique(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unique(%v) = %v, want %v", in, got, want)
		}
	}
}
