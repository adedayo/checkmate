package common

// Phase 12 — overlap resolution.
//
// removeOverlappingIssues was replaced by an O(n) sweep over the sorted
// findings. The replacement is only acceptable if it is *exactly* equivalent:
// which finding survives determines its ProviderID, Justification, Range,
// Source and therefore its derived finding ID, which is what links a finding
// across scans for triage and exception handling. A subtly different survivor
// is not a cosmetic difference — it silently breaks that identity, and
// resurrects findings a user has already dismissed.
//
// So the reference implementation is kept here, in the tests, and the two are
// compared over randomised input.

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// removeOverlappingIssuesReference is the original O(n²) implementation,
// verbatim apart from the sort being hoisted out by the caller.
//
// It is the specification. If it and the sweep ever disagree, the sweep is
// wrong.
func removeOverlappingIssuesReference(diags []*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	excluded := make([]bool, len(diags))
	out := make([]*diagnostics.SecurityDiagnostic, 0)
	for i, di := range diags {
		for j, dj := range diags {
			if j != i {
				if dj.RawRange.Contains(&di.RawRange) &&
					di.Justification.Headline.Confidence <= dj.Justification.Headline.Confidence &&
					!di.RawRange.Contains(&dj.RawRange) {
					excluded[i] = true
					break
				}
			}
		}
	}
	for i, di := range diags {
		if !excluded[i] {
			out = append(out, di)
		}
	}
	return out
}

func makeDiagnostic(id string, start, end int64, conf diagnostics.Confidence) *diagnostics.SecurityDiagnostic {
	provider := id
	return &diagnostics.SecurityDiagnostic{
		ProviderID: &provider,
		RawRange:   diagnostics.CharRange{StartIndex: start, EndIndex: end},
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: id,
				Confidence:  conf,
			},
		},
	}
}

// TestRemoveOverlappingIssuesDifferential is the gate on Phase 12.
//
// The generated ranges are deliberately small and dense — offsets in [0,24),
// five confidence levels — because the interesting cases are collisions:
// identical ranges, nested ranges, ranges sharing exactly one endpoint, and
// equal confidences. Sparse random ranges rarely contain one another and would
// make the test vacuous while appearing thorough.
func TestRemoveOverlappingIssuesDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260807))

	confidences := []diagnostics.Confidence{
		diagnostics.Info, diagnostics.Low, diagnostics.Medium,
		diagnostics.High, diagnostics.Critical,
	}

	for trial := 0; trial < 3000; trial++ {
		n := rng.Intn(12)
		input := make([]*diagnostics.SecurityDiagnostic, 0, n)
		for i := 0; i < n; i++ {
			start := int64(rng.Intn(24))
			//A mix of empty, short and long spans, so that equal ranges and
			//zero-width ranges both occur often.
			end := start + int64(rng.Intn(6))
			input = append(input, makeDiagnostic(
				fmt.Sprintf("rule-%d", i), start, end,
				confidences[rng.Intn(len(confidences))]))
		}

		//Both sides must see the same order: the sweep depends on it, and the
		//reference is order-independent, so sorting once up front compares the
		//resolution logic rather than the sort.
		sorted := make([]*diagnostics.SecurityDiagnostic, len(input))
		copy(sorted, input)
		diagnostics.SortDiagnosticsDeterministically(sorted)

		reference := removeOverlappingIssuesReference(sorted)

		subject := make([]*diagnostics.SecurityDiagnostic, len(input))
		copy(subject, input)
		got := removeOverlappingIssues(subject)

		if !reflect.DeepEqual(reference, got) {
			t.Fatalf("trial %d: sweep and reference disagree\ninput:     %s\nreference: %s\nsweep:     %s",
				trial, describe(sorted), describe(reference), describe(got))
		}
	}
}

// TestRemoveOverlappingIssuesHandCases pins the boundaries the differential
// test relies on the random generator to reach, so that a change to the
// generator cannot quietly stop covering them.
func TestRemoveOverlappingIssuesHandCases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []*diagnostics.SecurityDiagnostic
		keep  []string
	}{
		{
			name: "strict containment with equal confidence subsumes the inner",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("outer", 0, 10, diagnostics.Medium),
				makeDiagnostic("inner", 2, 5, diagnostics.Medium),
			},
			keep: []string{"outer"},
		},
		{
			name: "inner survives when strictly more confident",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("outer", 0, 10, diagnostics.Low),
				makeDiagnostic("inner", 2, 5, diagnostics.High),
			},
			keep: []string{"outer", "inner"},
		},
		{
			name: "identical ranges contain each other, so neither is dropped",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("a", 3, 8, diagnostics.Medium),
				makeDiagnostic("b", 3, 8, diagnostics.Medium),
			},
			keep: []string{"a", "b"},
		},
		{
			name: "shared start, longer span wins",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("long", 4, 12, diagnostics.Medium),
				makeDiagnostic("short", 4, 6, diagnostics.Medium),
			},
			keep: []string{"long"},
		},
		{
			name: "shared end, earlier start wins",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("early", 1, 9, diagnostics.Medium),
				makeDiagnostic("late", 5, 9, diagnostics.Medium),
			},
			keep: []string{"early"},
		},
		{
			name: "zero width range at offset zero is not self-excluding",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("point", 0, 0, diagnostics.Info),
			},
			keep: []string{"point"},
		},
		{
			name: "disjoint findings all survive",
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("a", 0, 2, diagnostics.Medium),
				makeDiagnostic("b", 4, 6, diagnostics.Medium),
				makeDiagnostic("c", 8, 10, diagnostics.Medium),
			},
			keep: []string{"a", "b", "c"},
		},
		{
			name: "containment is judged against the original set, not the survivors",
			//`mid` is dropped by `outer`, but `inner` must still be dropped by
			//`mid` — exclusion does not cascade, and a sweep that consulted
			//only survivors would keep `inner`.
			input: []*diagnostics.SecurityDiagnostic{
				makeDiagnostic("outer", 0, 20, diagnostics.Medium),
				makeDiagnostic("mid", 2, 12, diagnostics.Medium),
				makeDiagnostic("inner", 4, 6, diagnostics.Medium),
			},
			keep: []string{"outer"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := removeOverlappingIssues(tc.input)
			kept := make([]string, 0, len(got))
			for _, d := range got {
				kept = append(kept, *d.ProviderID)
			}
			if !reflect.DeepEqual(kept, tc.keep) {
				t.Errorf("kept %v, want %v", kept, tc.keep)
			}
		})
	}
}

// TestRemoveOverlappingIssuesIsLinear is the guard on the defect itself.
//
// A bound on wall-clock would be flaky; what matters is the *shape*. Ten times
// the findings must not cost a hundred times the work, which is what the double
// loop did. The fixture that motivated this — 83,888 findings in one file —
// took 15.2s under the old implementation and would fail this outright.
func TestRemoveOverlappingIssuesIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}

	build := func(n int) []*diagnostics.SecurityDiagnostic {
		//Non-overlapping findings: nothing is excluded, so every element is
		//swept and the timing reflects the algorithm rather than early exits.
		out := make([]*diagnostics.SecurityDiagnostic, 0, n)
		for i := 0; i < n; i++ {
			start := int64(i) * 10
			out = append(out, makeDiagnostic(fmt.Sprintf("r%d", i), start, start+4, diagnostics.Medium))
		}
		return out
	}

	small := time.Duration(0)
	large := time.Duration(0)
	const (
		smallN = 2_000
		largeN = 20_000
	)

	//Best of three: this runs alongside whatever else the machine is doing,
	//and the failure being guarded against is a factor of ten, not of two.
	for i := 0; i < 3; i++ {
		s := time.Now()
		removeOverlappingIssues(build(smallN))
		if d := time.Since(s); small == 0 || d < small {
			small = d
		}

		s = time.Now()
		removeOverlappingIssues(build(largeN))
		if d := time.Since(s); large == 0 || d < large {
			large = d
		}
	}

	//Linear would be 10×. Quadratic would be 100×. Allow a generous 25× for
	//sort overhead, allocation and cache effects, which still fails loudly on
	//a return to the double loop.
	if ratio := float64(large) / float64(small); ratio > 25 {
		t.Errorf("overlap resolution grew %.1f× for a 10× increase in findings (%v → %v); "+
			"this is the quadratic behaviour Phase 12 removed", ratio, small, large)
	}
}

func describe(diags []*diagnostics.SecurityDiagnostic) string {
	out := "["
	for i, d := range diags {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s(%d-%d,%s)", *d.ProviderID,
			d.RawRange.StartIndex, d.RawRange.EndIndex,
			d.Justification.Headline.Confidence)
	}
	return out + "]"
}
