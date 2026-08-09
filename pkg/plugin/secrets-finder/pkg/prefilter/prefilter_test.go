package prefilter

import (
	"regexp"
	"strings"
	"testing"
)

// TestRequiredLiteralExtraction pins the proof rules. Each case states what
// the extractor must conclude and, more importantly, why.
func TestRequiredLiteralExtraction(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    []string
		wantOK  bool
	}{
		{
			name:    "plain literal",
			pattern: `ghp_[0-9a-zA-Z]{36}`,
			want:    []string{"ghp_"},
			wantOK:  true,
		},
		{
			name:    "literal is lowercased for the folding automaton",
			pattern: `AKIA[0-9A-Z]{16}`,
			want:    []string{"akia"},
			wantOK:  true,
		},
		{
			name:    "case-insensitive rules are still filterable",
			pattern: `(?i)beamer_api_[0-9a-f]{32}`,
			want:    []string{"beamer_api_"},
			wantOK:  true,
		},
		{
			name:    "alternation contributes every branch",
			pattern: `(ghp_|gho_|ghu_)[0-9a-zA-Z]{36}`,
			want:    []string{"gho_", "ghp_", "ghu_"},
			wantOK:  true,
		},
		{
			// The critical soundness case. "secret" is required, "prefix" is
			// not, and an extractor that returned "prefix" would skip the rule
			// on input matching the other branch.
			name:    "optional branch does not create a requirement",
			pattern: `(prefix)?secretvalue`,
			want:    []string{"secretvalue"},
			wantOK:  true,
		},
		{
			name:    "alternation with an unconstrained branch yields nothing",
			pattern: `(ghp_[a-z]+|[0-9]{32})`,
			wantOK:  false,
		},
		{
			name:    "starred literal is not required",
			pattern: `(token)*[0-9a-f]{32}`,
			wantOK:  false,
		},
		{
			name:    "optional literal is not required",
			pattern: `(token)?[0-9a-f]{32}`,
			wantOK:  false,
		},
		{
			name:    "plus requires at least one occurrence",
			pattern: `(?:token_)+[0-9a-f]{32}`,
			want:    []string{"token_"},
			wantOK:  true,
		},
		{
			name:    "bounded repeat with zero minimum is not required",
			pattern: `(?:abcd){0,3}[0-9]{32}`,
			wantOK:  false,
		},
		{
			name:    "character classes constrain shape, not identity",
			pattern: `[0-9a-fA-F]{32}`,
			wantOK:  false,
		},
		{
			name:    "concatenation picks the strongest element",
			pattern: `ab[0-9]*_private_key_[0-9]+`,
			want:    []string{"_private_key_"},
			wantOK:  true,
		},
		{
			name:    "literal shorter than the minimum is rejected",
			pattern: `id[0-9]{32}`,
			wantOK:  false,
		},
		{
			name:    "a short branch poisons an otherwise good alternation",
			pattern: `(longenough_|ab)[0-9]{32}`,
			wantOK:  false,
		},
		{
			// Non-ASCII is fine: the automaton is byte-oriented, so a seed is
			// just the UTF-8 encoding. Only ASCII letters are case-folded.
			name:    "non-ascii literals are encoded as utf-8",
			pattern: `Ünicöde_secret`,
			want:    []string{"Ünicöde_secret"},
			wantOK:  true,
		},
		{
			// The fold orbit of 's' includes U+017F LATIN SMALL LETTER LONG S,
			// so (?i)_pass_ genuinely matches "_paſs_". A seed set of just
			// {"_pass_"} would miss that input and silently drop the finding.
			name:    "folded s emits its non-ascii orbit member",
			pattern: `(?i)_pass_[0-9]{20}`,
			want:    []string{"_pass_", "_pasſ_", "_paſs_", "_paſſ_"},
			wantOK:  true,
		},
		{
			// Likewise 'k' folds to U+212A KELVIN SIGN.
			name:    "folded k emits its non-ascii orbit member",
			pattern: `(?i)_akey_[0-9]{20}`,
			want:    []string{"_akey_", "_a\u212aey_"},
			wantOK:  true,
		},
		{
			// Six expanding runes (five 's', one 'k') would be 64 alternatives,
			// over budget. Rather than lose the rule to the residual set, the
			// longest non-expanding run is used instead -- still mandatory,
			// because any substring of a mandatory literal is mandatory.
			name:    "orbit explosion falls back to the longest clean run",
			pattern: `(?i)aws_secrets_access_key\s*=\s*[0-9a-zA-Z/+]{40}`,
			want:    []string{"ecret"},
			wantOK:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractSeeds(tc.pattern)
			if ok != tc.wantOK {
				t.Fatalf("extractSeeds(%q) ok = %v, want %v (seeds %q)",
					tc.pattern, ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("extractSeeds(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestExtractedSeedsAreActuallyMandatory is the property behind every
// individual case above, checked directly: if the extractor claims a seed set
// for a rule, then no string matched by that rule can avoid the whole set.
//
// It works by deleting the seeds from candidate strings and asserting the
// pattern no longer matches.
func TestExtractedSeedsAreActuallyMandatory(t *testing.T) {
	patterns := []string{
		`ghp_[0-9a-zA-Z]{36}`,
		`(ghp_|gho_|ghu_)[0-9a-zA-Z]{36}`,
		`(?i)aws_secret_access_key\s*=\s*[0-9a-zA-Z/+]{40}`,
		`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
		`xox[baprs]-[0-9a-zA-Z-]{10,}`,
	}

	for _, p := range patterns {
		seeds, ok := extractSeeds(p)
		if !ok {
			continue
		}
		re := regexp.MustCompile(p)

		for _, seed := range seeds {
			// Any match must contain at least one seed, so a string with all
			// seeds stripped out must not match.
			probe := strings.Repeat("a", 200) + seed + strings.Repeat("0", 200)
			stripped := probe
			for _, s := range seeds {
				stripped = removeFold(stripped, s)
			}
			if re.MatchString(stripped) {
				t.Errorf("pattern %q matched input with all seeds %q removed; seed set is not mandatory",
					p, seeds)
			}
		}
	}
}

func removeFold(s, sub string) string {
	for {
		i := strings.Index(strings.ToLower(s), strings.ToLower(sub))
		if i < 0 {
			return s
		}
		s = s[:i] + s[i+len(sub):]
	}
}

func TestMatcherFindsSeedsAndAlwaysReturnsResidual(t *testing.T) {
	rules := map[string]*regexp.Regexp{
		"github-pat":  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		"aws-key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"generic-hex": regexp.MustCompile(`[0-9a-f]{32}`), // no seed -> residual
	}
	m := Build(rules)

	if got := m.Residual(); len(got) != 1 || got[0] != "generic-hex" {
		t.Fatalf("Residual() = %q, want [generic-hex]", got)
	}

	got := m.CandidateIDs([]byte("token := ghp_" + strings.Repeat("a", 36)))
	want := map[string]bool{"github-pat": true, "generic-hex": true}
	if len(got) != len(want) {
		t.Fatalf("CandidateIDs = %q, want keys of %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected candidate %q", id)
		}
	}

	// A file with no seeds at all must still return the residual set, and
	// nothing more -- that is where the throughput win comes from.
	empty := m.CandidateIDs([]byte("package main\n\nfunc main() {}\n"))
	if len(empty) != 1 || empty[0] != "generic-hex" {
		t.Errorf("CandidateIDs on clean source = %q, want [generic-hex]", empty)
	}
}

// TestMatcherIsCaseInsensitive guards the fold, which is what allows the many
// (?i) vendor rules to be filtered rather than made residual.
func TestMatcherIsCaseInsensitive(t *testing.T) {
	m := Build(map[string]*regexp.Regexp{
		"slack": regexp.MustCompile(`(?i)slack_token`),
	})
	for _, in := range []string{"slack_token", "SLACK_TOKEN", "SlAcK_ToKeN"} {
		if got := m.CandidateIDs([]byte(in)); len(got) != 1 {
			t.Errorf("CandidateIDs(%q) = %q, want [slack]", in, got)
		}
	}
}

// TestOverlappingSeedsAreAllReported covers the Aho-Corasick output
// propagation along fail links. Without it, a seed that is a suffix of another
// is silently never reported and its rule is wrongly skipped.
func TestOverlappingSeedsAreAllReported(t *testing.T) {
	m := Build(map[string]*regexp.Regexp{
		"long":  regexp.MustCompile(`xsecret_value[0-9]`),
		"short": regexp.MustCompile(`secret_value[0-9]`),
	})
	got := m.CandidateIDs([]byte("--xsecret_value1--"))
	if len(got) != 2 {
		t.Errorf("CandidateIDs = %q, want both long and short", got)
	}
}

// TestBuildIsDeterministic guards against the map-iteration class of defect
// that phase 0 had to unpick across six separate sites.
func TestBuildIsDeterministic(t *testing.T) {
	rules := map[string]*regexp.Regexp{
		"a": regexp.MustCompile(`alpha_[0-9]{8}`),
		"b": regexp.MustCompile(`bravo_[0-9]{8}`),
		"c": regexp.MustCompile(`[0-9a-f]{32}`),
		"d": regexp.MustCompile(`(delta_|dover_)[0-9]{8}`),
	}
	first := Build(rules)
	for i := 0; i < 20; i++ {
		next := Build(rules)
		if strings.Join(first.RuleIDs(), ",") != strings.Join(next.RuleIDs(), ",") {
			t.Fatalf("rule order differs between builds")
		}
		if strings.Join(first.Residual(), ",") != strings.Join(next.Residual(), ",") {
			t.Fatalf("residual set differs between builds")
		}
		if len(first.trans) != len(next.trans) {
			t.Fatalf("automaton size differs between builds: %d vs %d",
				len(first.trans), len(next.trans))
		}
	}
}
