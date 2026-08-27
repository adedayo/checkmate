package secrets

// Phase 10 — offset-independence of findings.
//
// # What this file establishes
//
// `TestChunkBoundarySuppressionIsNotLost` below is a real regression guard: it
// reproduces, in 4,200 synthetic bytes, the divergence found against a real
// dependency tree, and it **fails against the pre-change engine** (which
// reports the finding) and passes against the current one (which does not).
// It was reduced by `tools/boundarydiff` under openspec change 004.
//
// The two property tests after it are weaker and are labelled as such: they
// pass against both engines, so they do not reproduce anything. They are kept
// as forward-looking assertions about offset-independence.
//
// # The mechanism, now established
//
// Phase 10.5 scanned a real 22,542-file dependency tree and found 53 stable
// finding differences. Every affected file exceeded 4,096 bytes — the old
// dataChunkSize — and no smaller file differed at all. The 003 record left the
// cause as an inference from that correlation, because two manual attempts to
// synthesise it (50 cases sweeping a secret across the seam, 11 reproducing
// one file's shape) produced zero divergence.
//
// Those attempts failed because they were looking for the wrong thing. They
// swept a **well-formed secret** across the boundary, and a well-formed secret
// is reported by both engines wherever it sits. The divergence is the opposite
// case: a **false positive that whole-file context suppresses**.
//
// Reduction of `testdata/boundary/css-select-filters.js` (145 lines to 3,
// holding every byte offset fixed so chunk geometry could not change) isolated
// three necessary ingredients:
//
//  1. a double-quote character before the seam;
//  2. a `// ... :root` comment after it;
//  3. a `filters["root"](...)` match after it.
//
// Remove any one and both engines agree. The old reader consumed each chunk in
// a separate `Consume` call, so a suppression rule needing to see both (1) and
// (3) could not fire when the seam fell between them, and the false positive
// survived. The whole-file engine sees both and suppresses it.
//
// Moving the quote across the seam confirms this directly: with the quote at
// bytes 3,101 / 3,763 / 4,018 the engines diverge; at 4,064 / 4,101 / 4,189
// they agree. The flip is exactly at the newline-aligned chunk split (byte
// 4,063, the end of line 108) — not at 4,096, because `readChunks` walks back
// to the last newline. So the divergence tracks the *real* seam, which is
// stronger evidence than a correlation with the nominal chunk size.
//
// This also refutes the two hypotheses recorded in the 004 design. It is not
// the `largeChunk` accumulation branch: the reproducer has short lines and
// never enters it. It is not entropy scored over a truncated window: the
// finding is a fixed-string match, and its SHA-256 is identical either side.
//
// # Why the reference corpus could not catch it
//
// Every corpus fixture except the deliberately-adversarial ones is smaller
// than 4KB, so no fixture ever contained a chunk boundary. The adversarial
// fixtures do, but they are single-line by construction and are asserted on
// for time rather than content. The missing shape was "a multi-line file over
// 4KB with a suppressible false positive after byte 4096".

import (
	"fmt"
	"strings"
	"testing"
)

// oldChunkSize is the pre-change dataChunkSize. This is deliberately a literal
// rather than a reference to the current constant: the point is to probe the
// offset where the historic implementation placed a seam, and the test must
// keep probing it even if the current buffer size changes.
const oldChunkSize = 4096

// buildCrossSeamSuppressionCase returns the minimised reproducer.
//
// Shape: a quote in the first chunk, inert padding across the seam, then a
// comment and a `filters["root"]` match in the second. `withQuote` controls
// ingredient (1) and is the single variable the test flips.
//
// The padding is blank rather than plausible-looking code on purpose. That is
// the reverse of the advice on buildFileWithMatchAtOffset below, and the
// difference matters: here the padding must contribute *nothing*, because the
// whole claim is that three specific lines are sufficient. Delta debugging
// established that blank padding preserves the divergence, so anything richer
// would only reintroduce the doubt about what is really responsible.
func buildCrossSeamSuppressionCase(withQuote bool) string {
	var b strings.Builder

	if withQuote {
		b.WriteString("    \"x\"\n")
	} else {
		b.WriteString("       \n")
	}

	// Push the match past the seam. The exact count is not delicate — any
	// padding that carries the match beyond 4,096 bytes reproduces it — but it
	// is asserted below rather than assumed.
	for i := 0; i < 100; i++ {
		b.WriteString(strings.Repeat(" ", 40) + "\n")
	}

	b.WriteString("            // Equivalent to :root\n")
	b.WriteString("            return filters[\"root\"](next, rule, options);\n")

	return b.String()
}

// TestChunkBoundarySuppressionIsNotLost is the regression guard.
//
// It asserts that the `filters["root"]` false positive is suppressed when a
// quote precedes it, *even though* the two sit either side of the historic
// 4KB seam. The pre-change engine fails this: it reports the finding, because
// its two chunks were matched independently and the suppressing context never
// reached the match. Verified by running both engines under
// tools/boundarydiff — pre-change reports 1 finding, current reports 0.
func TestChunkBoundarySuppressionIsNotLost(t *testing.T) {
	withQuote := buildCrossSeamSuppressionCase(true)

	// Guard the precondition. If this fixture ever stops straddling the seam,
	// the test would pass for an unrelated reason — the divergence would
	// vanish because its precondition had gone, not because the defect had.
	// That is the specific failure mode this whole change was written to
	// avoid, so it is asserted, not assumed.
	if len(withQuote) <= oldChunkSize {
		t.Fatalf("fixture is %d bytes, which no longer exceeds the historic "+
			"chunk size of %d; it cannot contain a seam and the test is vacuous",
			len(withQuote), oldChunkSize)
	}
	if idx := strings.Index(withQuote, "filters["); idx <= oldChunkSize {
		t.Fatalf("the match sits at byte %d, inside the first chunk; the "+
			"fixture must place it beyond byte %d to exercise the seam",
			idx, oldChunkSize)
	}

	countRootFindings := func(t *testing.T, content string) int {
		t.Helper()
		root := materialiseCorpus(t, []corpusFile{{
			Path:    "repo-a/src/filters.js",
			Content: content,
		}})
		return len(runScan(t, baselineOptions(), root).Findings)
	}

	// The control. Without the quote, both engines report the finding, so a
	// non-zero count here proves the fixture reaches a rule at all and that
	// the zero below is suppression rather than the scanner ignoring the file.
	if got := countRootFindings(t, buildCrossSeamSuppressionCase(false)); got == 0 {
		t.Fatal("control fixture produced no findings at all; the assertion " +
			"below would pass vacuously, proving nothing")
	}

	if got := countRootFindings(t, withQuote); got != 0 {
		t.Errorf(""+
			"cross-seam suppression was lost: got %d findings, want 0.\n"+
			"A quote before the historic 4KB seam must still suppress the "+
			"filters[\"root\"] false positive after it. Reporting it means "+
			"matching context is once again confined to a read buffer, which "+
			"is the pre-change chunked-read defect; see openspec change 004.",
			got)
	}
}

// buildFileWithMatchAtOffset returns a multi-line file whose secret assignment
// begins at approximately the requested byte offset.
//
// The padding is real-looking code rather than a repeated filler line, because
// the generic finders are context-sensitive: padding with an obviously inert
// repeated string changes which heuristics fire and can make a boundary test
// pass by finding nothing at all on either side of the seam. (That is exactly
// how the first attempt at reproducing this by hand failed — a synthetic file
// produced zero findings for both engines, which looks like agreement and
// proves nothing.)
func buildFileWithMatchAtOffset(offset int, secret string) string {
	var b strings.Builder
	for i := 0; b.Len() < offset; i++ {
		fmt.Fprintf(&b, "func helper%d(value int) int { return value * %d }\n", i, i+1)
	}
	fmt.Fprintf(&b, "const credential%d = \"%s\"\n", 0, secret)
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "func trailer%d(value int) int { return value + %d }\n", i, i)
	}
	return b.String()
}

// TestFindingsDoNotDependOnChunkBoundary is the core property: the same secret,
// in the same surrounding context, must be found identically wherever it sits
// in the file.
//
// The offsets straddle the historic 4KB seam and its multiples. Note this
// passes on the pre-change engine too, so it does not demonstrate the
// difference found in Phase 10.5 — TestChunkBoundarySuppressionIsNotLost does
// that. This only fixes the property going forward.
func TestFindingsDoNotDependOnChunkBoundary(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"

	offsets := []int{
		512,                   // comfortably inside the first chunk
		oldChunkSize - 64,     // just before the first seam
		oldChunkSize + 64,     // just after it — where divergence appeared
		2*oldChunkSize - 64,   // just before the second seam
		2*oldChunkSize + 64,   // just after it
		3*oldChunkSize + 1024, // well past several seams
	}

	type result struct {
		offset  int
		summary []string
	}
	var results []result

	for _, offset := range offsets {
		root := materialiseCorpus(t, []corpusFile{{
			Path:    "repo-a/src/config.go",
			Content: buildFileWithMatchAtOffset(offset, secret),
		}})

		run := runScan(t, baselineOptions(), root)

		var summary []string
		for _, f := range run.Findings {
			// Position is deliberately excluded: the secret genuinely does sit
			// at a different offset in each variant, so positions must differ.
			// What must not differ is which rules fired and with what verdict.
			providerID := ""
			if f.ProviderID != nil {
				providerID = *f.ProviderID
			}
			summary = append(summary, fmt.Sprintf("%s/%s",
				providerID, f.Justification.Headline.Confidence.String()))
		}
		summary = sortedCopy(summary)
		results = append(results, result{offset: offset, summary: summary})
	}

	if len(results[0].summary) == 0 {
		t.Fatal("no findings at the control offset; the fixture is not " +
			"exercising any rule, so agreement between offsets would be vacuous")
	}

	want := results[0]
	for _, got := range results[1:] {
		if strings.Join(got.summary, "|") != strings.Join(want.summary, "|") {
			t.Errorf(""+
				"finding set depends on the secret's byte offset.\n"+
				"  at offset %d: %v\n"+
				"  at offset %d: %v\n"+
				"A file's findings must not depend on where a read buffer "+
				"boundary happens to fall. This is the pre-change chunked-read "+
				"defect; see baseline.md, Phase 10.",
				want.offset, want.summary, got.offset, got.summary)
		}
	}
}

// TestWholeFileAndChunkedPathsAgree pins the two read paths against each other
// at the size threshold that selects between them.
//
// The whole-file path is used below MaxInMemoryFileSize and the chunked path
// above it, so a file either side of that threshold exercises different code
// for the same content shape. Both must produce the same verdict for the same
// embedded secret.
func TestWholeFileAndChunkedPathsAgree(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"

	// A match placed just past a seam, in a small file (whole-file path) and
	// again with enough trailing bulk that reading is chunked.
	small := buildFileWithMatchAtOffset(oldChunkSize+64, secret)

	var large strings.Builder
	large.WriteString(small)
	for large.Len() < 2*oldChunkSize {
		large.WriteString("func filler(value int) int { return value }\n")
	}

	summarise := func(t *testing.T, content string) []string {
		t.Helper()
		root := materialiseCorpus(t, []corpusFile{{
			Path:    "repo-a/src/config.go",
			Content: content,
		}})
		run := runScan(t, baselineOptions(), root)

		var out []string
		for _, f := range run.Findings {
			providerID := ""
			if f.ProviderID != nil {
				providerID = *f.ProviderID
			}
			out = append(out, fmt.Sprintf("%s/%s",
				providerID, f.Justification.Headline.Confidence.String()))
		}
		return sortedCopy(out)
	}

	smallSummary := summarise(t, small)
	largeSummary := summarise(t, large.String())

	if len(smallSummary) == 0 {
		t.Fatal("no findings in the smaller fixture; comparison would be vacuous")
	}

	// The larger file has more content and may legitimately yield more
	// findings, so the assertion is containment: everything the smaller file
	// found must still be found when the same bytes are read by the other path.
	missing := missingFrom(smallSummary, largeSummary)
	if len(missing) > 0 {
		t.Errorf(""+
			"findings present in the whole-file read path are absent once the "+
			"same content is read in chunks: %v\n"+
			"whole-file: %v\nchunked:    %v",
			missing, smallSummary, largeSummary)
	}
}

// sortedCopy returns a sorted copy, so comparisons do not depend on the order
// findings happened to arrive in.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// missingFrom returns the members of want that do not appear in got, counting
// multiplicity, so a lost duplicate is reported rather than masked.
func missingFrom(want, got []string) []string {
	remaining := make(map[string]int, len(got))
	for _, g := range got {
		remaining[g]++
	}
	var missing []string
	for _, w := range want {
		if remaining[w] > 0 {
			remaining[w]--
			continue
		}
		missing = append(missing, w)
	}
	return missing
}
