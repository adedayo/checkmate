package secrets

import (
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg/prefilter"
)

// minFilterableFraction is the share of vendor rules that must carry a
// provable mandatory literal.
//
// The prefilter's whole value is that most rules are skipped on most files, so
// a drop here is a silent performance regression: correctness tests stay green
// while scans get slower. Measured at 93.3% (210 of 225) when the prefilter
// landed; the threshold sits a little below that so that adding a handful of
// generic rules does not fail the build, but a structural regression does.
const minFilterableFraction = 0.90

// TestPrefilterCoversMostVendorRules guards the throughput property against
// the real rule set rather than hand-written samples.
func TestPrefilterCoversMostVendorRules(t *testing.T) {
	m := prefilter.Build(vendorSecrets)

	total := m.NumRules()
	if total == 0 {
		t.Fatal("no vendor rules loaded; the rule table failed to initialise")
	}

	residual := len(m.Residual())
	filterable := float64(total-residual) / float64(total)

	t.Logf("%d vendor rules: %d filterable, %d residual (%.1f%%)",
		total, total-residual, residual, 100*filterable)

	if filterable < minFilterableFraction {
		t.Errorf("only %.1f%% of vendor rules are filterable, want at least %.1f%%.\nResidual rules:\n  %s",
			100*filterable, 100*minFilterableFraction,
			strings.Join(m.Residual(), "\n  "))
	}
}

// TestHighValueRulesAreFilterable pins the specific rules that dominate real
// scans. These are the tokens that actually appear in leaked-credential
// reports, so losing the filter on one of them matters far more than the
// aggregate percentage suggests.
func TestHighValueRulesAreFilterable(t *testing.T) {
	m := prefilter.Build(vendorSecrets)

	// Substrings of the rule descriptions used as IDs, since the full
	// descriptions are long prose.
	wanted := []string{
		"GitHub OAuth Access Token",
		"GitHub Personal Access Token",
		"GitHub Refresh Token",
		"GitLab",
		"Slack",
		"Stripe",
		"PyPI",
	}

	for _, want := range wanted {
		t.Run(want, func(t *testing.T) {
			var found bool
			for _, id := range m.RuleIDs() {
				if !strings.Contains(id, want) {
					continue
				}
				found = true
				if len(m.SeedsFor(id)) == 0 {
					t.Errorf("rule %q is residual; expected a provable seed", id)
				}
			}
			if !found {
				t.Skipf("no rule matching %q in the current rule set", want)
			}
		})
	}
}

// BenchmarkPrefilterScan measures the per-byte cost of the automaton pass.
// It has to be small relative to a single regex pass for the whole exercise to
// be worthwhile, since it is paid on every file whether or not anything is
// skipped.
func BenchmarkPrefilterScan(b *testing.B) {
	m := prefilter.Build(vendorSecrets)
	set := m.NewSet()

	// Ordinary source with no secrets: the case that must be fast, because it
	// is almost every file in a real repository.
	data := []byte(strings.Repeat(
		"func handler(w http.ResponseWriter, r *http.Request) {\n"+
			"\tid := r.URL.Query().Get(\"id\")\n"+
			"\tif err := store.Load(ctx, id); err != nil {\n"+
			"\t\thttp.Error(w, err.Error(), 500)\n\t}\n}\n", 200))

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Candidates(data, set)
	}
	b.StopTimer()

	b.ReportMetric(float64(set.Count()), "candidates")
	b.ReportMetric(float64(m.NumRules()), "rules")
}
