package secrets

// Phase 11 — gating the vendor *classification* path.
//
// Phase 4 gated rule discovery: which vendor finders run against a file. It did
// not gate `detectSecret` → `isVendorSecret`, which evaluates the entire vendor
// rule set against every candidate secret in order to *describe* it. The rule
// set was therefore prefiltered in one place and exhaustive in another, and the
// worst case is set by the ungated path — so on adversarial input the prefilter
// bought nothing at all. It was 94.95% of a 74-second scan of a single 2MB file.
//
// These tests guard the property that makes the fix safe: gating may only
// remove rules that could not have matched, so the description returned must be
// identical either way.

import (
	"strings"
	"testing"
)

// classificationCandidates is the corpus of candidate values these tests agree
// on: real vendor tokens, near-misses, and the shapes that reach detectSecret
// from ordinary source.
func classificationCandidates() []string {
	return []string{
		"ghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00",
		"xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
		"sk_live_abcdefghijklmnopqrstuvwx",
		"live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://user:hunter2@db.example.com:5432/app",
		"mongodb+srv://admin:s3cr3t@cluster0.example.net/test",
		"-----BEGIN RSA PRIVATE KEY-----",
		"c2luZ2xlLWxpbmUtanNvbi1zZWNyZXQtdmFsdWU=",
		"correct horse battery staple",
		"hunter2",
		"",
		"true",
		"0123456789abcdef",
		"ghp_",                                       // the seed alone, with nothing that completes the rule
		"GHP_016C4CBB1C0FFFFFFFFFFFFFFFFFFFFFFFFF00", // uppercased
		strings.Repeat("A", 4096),
		strings.Repeat("ghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00 ", 8),
	}
}

// TestVendorClassificationGatingIsSound is the core guarantee: for every
// candidate, the gated and ungated classifications agree exactly.
//
// Both the description and the boolean matter. A gated run that returned
// `false` where the ungated run returned a vendor description would downgrade a
// real, identified token — a `ghp_…` GitHub token, say — to the generic entropy
// branch, losing its Critical confidence. The finding would still be reported,
// which is what makes this failure mode quiet: the scan looks fine, and only
// the severity is wrong.
func TestVendorClassificationGatingIsSound(t *testing.T) {
	gate := newRuleGate(SecretSearchOptions{})
	if !gate.active {
		t.Fatal("prefilter is disabled in this environment; the test would be vacuous")
	}

	for _, candidate := range classificationCandidates() {
		//detectSecret lowercases before classifying, so the comparison is made
		//on the string isVendorSecret actually receives.
		data := strings.ToLower(candidate)

		wantDesc, wantOK := isVendorSecret(data, nil)
		gotDesc, gotOK := isVendorSecret(data, gate.vendorCandidates(data))

		if wantOK != gotOK || wantDesc != gotDesc {
			t.Errorf("gating changed the classification of %.60q:\n"+
				"  ungated: %q (%v)\n"+
				"  gated:   %q (%v)\n"+
				"The prefilter may only skip rules that could not have matched.",
				candidate, wantDesc, wantOK, gotDesc, gotOK)
		}
	}
}

// FuzzVendorClassificationGating extends the soundness property to arbitrary
// input.
//
// The seeds are the interesting cases; the fuzzer's job is the ones nobody
// thought of — in particular inputs that carry a rule's literal in a form the
// automaton folds differently from the regex.
func FuzzVendorClassificationGating(f *testing.F) {
	for _, candidate := range classificationCandidates() {
		f.Add(candidate)
	}
	//Non-ASCII seeds, which is where the folding argument is at risk.
	f.Add("\u212Aey_id=AKIAIOSFODNN7EXAMPLE") // KELVIN SIGN
	f.Add("İghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00")
	f.Add("ghp_ÅÄÖ")

	gate := newRuleGate(SecretSearchOptions{})

	f.Fuzz(func(t *testing.T, candidate string) {
		if !gate.active {
			t.Skip("prefilter disabled")
		}
		data := strings.ToLower(candidate)

		wantDesc, wantOK := isVendorSecret(data, nil)
		gotDesc, gotOK := isVendorSecret(data, gate.vendorCandidates(data))

		if wantOK != gotOK || wantDesc != gotDesc {
			t.Fatalf("gating changed the classification of %q: ungated %q (%v), gated %q (%v)",
				candidate, wantDesc, wantOK, gotDesc, gotOK)
		}
	})
}

// TestClassificationGateUsesTheClassifiedString documents *why* the gate makes
// its own automaton pass over the candidate rather than reusing the set already
// computed for the whole file.
//
// Reusing the file-level set looks free and very nearly is: any substring of
// the file can only contain literals the file contains, so the file's candidate
// set is a valid superset. But detectSecret does not classify the substring, it
// classifies strings.ToLower(substring) — and the two lowercasings disagree.
// The automaton folds ASCII only; strings.ToLower is Unicode-aware. This test
// pins the concrete case, so that anyone tempted by the cheaper design can see
// what it would cost.
//
// The failure it prevents is under-admission: a rule absent from the file's
// candidate set but matching the lowered value, skipped, and the finding
// silently downgraded.
func TestClassificationGateUsesTheClassifiedString(t *testing.T) {
	const kelvin = "\u212A" // KELVIN SIGN

	lowered := strings.ToLower(kelvin)
	if lowered != "k" {
		t.Fatalf("assumption broken: strings.ToLower(%q) = %q, expected ASCII %q",
			kelvin, lowered, "k")
	}

	//The automaton's own folding leaves it alone: foldASCII only maps A-Z, so
	//no byte of the Kelvin sign can become "k". The two lowercasings therefore
	//disagree on exactly this input, which is the point.
	if strings.Contains(strings.Map(foldASCIIRune, kelvin), "k") {
		t.Fatal("assumption broken: ASCII folding should not produce \"k\" from the Kelvin sign")
	}

	//Concretely: a value whose Unicode-lowercased form contains a rule literal
	//that neither its raw form nor its ASCII-folded form contains.
	raw := kelvin + "ey=AKIAIOSFODNN7EXAMPLE"
	if !strings.Contains(strings.ToLower(raw), "key") {
		t.Fatal("assumption broken: the fixture should contain \"key\" only after Unicode lowering")
	}
	if strings.Contains(strings.Map(foldASCIIRune, raw), "key") {
		t.Fatal("assumption broken: ASCII folding should not reveal \"key\" here")
	}

	gate := newRuleGate(SecretSearchOptions{})
	if !gate.active {
		t.Skip("prefilter disabled")
	}

	//The guarantee under test: whatever the folding does, gating on the
	//classified string agrees with no gating at all.
	data := strings.ToLower(raw)
	wantDesc, wantOK := isVendorSecret(data, nil)
	gotDesc, gotOK := isVendorSecret(data, gate.vendorCandidates(data))
	if wantOK != gotOK || wantDesc != gotDesc {
		t.Errorf("classification disagreed on a Unicode-folding case: ungated %q (%v), gated %q (%v)",
			wantDesc, wantOK, gotDesc, gotOK)
	}
}

// foldASCIIRune mirrors the automaton's ASCII-only case folding, for the
// comparison above.
func foldASCIIRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// TestClassificationGateSetIsIndependentOfFileSet guards the other way the fix
// could go wrong: the classification pass must not clobber the file-level
// candidate set.
//
// The file's set is computed once, before any finder runs, and every gated
// finder reads it for the rest of the file. Classification happens *between*
// those reads — once per candidate value. If the two shared a Set, classifying
// a value would overwrite the file's candidates with the candidates of that one
// short string, and every subsequent vendor rule in the file would be skipped.
// Findings would vanish, in a way no equivalence test on a single-finding
// fixture would catch.
func TestClassificationGateSetIsIndependentOfFileSet(t *testing.T) {
	gate := newRuleGate(SecretSearchOptions{})
	if !gate.active {
		t.Skip("prefilter disabled")
	}

	const token = "ghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00"

	//Establish the file-level set, as the multiplexer does before finders run.
	gate.Consume(0, "token = \""+token+"\"\n")

	index := gate.indexOf(vendorRuleFor(t, token))
	if index < 0 {
		t.Skip("the sample token's rule is not prefilterable")
	}
	if !gate.allows(index) {
		t.Fatal("the file's own token was not admitted by the file-level set")
	}

	//Now classify something entirely unrelated, which admits none of the same
	//rules.
	gate.vendorCandidates("correct horse battery staple")

	if !gate.allows(index) {
		t.Error("classifying a candidate clobbered the file-level candidate set; " +
			"every vendor rule after the first classified value in a file would be skipped")
	}
}

// vendorRuleFor returns the description of the rule that matches value, for
// tests that need a known-gated rule index.
func vendorRuleFor(t *testing.T, value string) string {
	t.Helper()
	desc, ok := isVendorSecret(strings.ToLower(value), nil)
	if !ok {
		t.Fatalf("%q is not recognised as a vendor secret", value)
	}
	return desc
}
