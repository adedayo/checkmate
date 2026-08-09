package secrets

// Phase 10 — offset-independence of findings.
//
// # What this file does and does not establish
//
// **These tests pass against the pre-change engine as well as the current one.
// They therefore do NOT reproduce the difference described below, and are not
// a regression guard for it.** They are kept as a forward-looking property
// test: they assert something that must remain true, and would catch a future
// change that reintroduced offset-dependent matching in the straightforward
// case. Read them as a statement of intent, not as evidence.
//
// # The difference they were written for
//
// Phase 10.5 scanned a real 22,542-file dependency tree and found 53 stable
// finding differences against the pre-change engine. Every affected file was
// larger than 4,096 bytes — the old dataChunkSize — and no file at or below
// that size differed at all. A controlled shift of one real file, moving a
// matching region from offset 4,327 to 3,927 by deleting 400 bytes earlier in
// the file, flips the pre-change engine's output and not the current engine's.
//
// The obvious explanation is that the old chunked read restarted matching at
// each 4KB boundary, so a buffer edge could manufacture or truncate a match.
// That explanation is **inferred from the correlation and has not been
// proved**: two attempts to reduce it to a synthetic fixture — 50 cases
// sweeping a secret across the seam, and 11 reproducing the exact shape of the
// one file examined closely — showed zero divergence between engines. Some
// property of the real content is not captured here. See baseline.md.
//
// # Why the reference corpus could not catch it
//
// Every corpus fixture except the deliberately-adversarial ones is smaller
// than 4KB, so no fixture ever contained a chunk boundary. The adversarial
// fixtures do, but they are single-line by construction and are asserted on
// for time rather than content. The missing shape was "a multi-line file over
// 4KB with a match near byte 4096" — the commonest shape in real source code,
// and the reason a whole class of differences went unnoticed until the engine
// met a real repository.
//
// If the minimal fixture is ever found, it belongs here, and at that point
// these tests become a real guard rather than an aspiration.

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
// passes on the pre-change engine too — see the file comment — so it does not
// demonstrate the difference found in Phase 10.5; it only fixes the property
// going forward.
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
