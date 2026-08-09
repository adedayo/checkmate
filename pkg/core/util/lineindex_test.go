package util

import (
	"math/rand"
	"strings"
	"testing"
)

// TestLineIndexDifferential is the licence to delete LineKeeper.
//
// LineIndex is a behavioural rewrite of LineKeeper: binary search instead of a
// linear scan, int32 offsets instead of int, no lock. Position data feeds
// directly into the finding ID (rule + repo + path + line + column +
// checksum), so any disagreement between the two — even on an edge case like
// an offset landing exactly on a newline, or past the end of the file —
// silently changes finding identity and breaks cross-scan tracking.
//
// Rather than guess at the edge cases, this compares the two implementations
// at every offset of many randomly shaped inputs.
func TestLineIndexDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260806))

	for _, content := range differentialInputs(rng) {
		content := content

		t.Run(describeInput(content), func(t *testing.T) {
			eols := newlineOffsets(content)

			var keeper LineKeeper
			keeper.EOLLocations = append(keeper.EOLLocations, eols...)

			index := NewLineIndex(0)
			index.IndexString(0, content)

			if index.Len() != len(eols) {
				t.Fatalf("index recorded %d newlines, want %d", index.Len(), len(eols))
			}

			// Probe every offset in the file, plus a few past the end: findings
			// can report an offset at the very end of a match, which may sit on
			// or beyond the final byte.
			for pos := int64(0); pos <= int64(len(content))+2; pos++ {
				want := keeper.GetPositionFromCharacterIndex(pos)
				got := index.GetPositionFromCharacterIndex(pos)

				if got != want {
					t.Fatalf("offset %d: LineIndex gave {line %d, char %d}, LineKeeper gave {line %d, char %d}\ninput: %q",
						pos, got.Line, got.Character, want.Line, want.Character, content)
				}
			}
		})
	}
}

// TestLineIndexAppendEOLsMatchesLineKeeper exercises the chunk-relative entry
// point against LineKeeper's, feeding both the same chunked input the old
// multiplexer would have produced.
func TestLineIndexAppendEOLsMatchesLineKeeper(t *testing.T) {
	content := "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n"

	// Split on newline boundaries, as the chunked reader does. AppendEOLs
	// depends on that invariant, so the test must honour it.
	var chunks []string
	lines := strings.SplitAfter(content, "\n")
	for i := 0; i < len(lines); i += 2 {
		end := i + 2
		if end > len(lines) {
			end = len(lines)
		}
		if chunk := strings.Join(lines[i:end], ""); chunk != "" {
			chunks = append(chunks, chunk)
		}
	}

	var keeper LineKeeper
	index := NewLineIndex(0)

	for _, chunk := range chunks {
		relative := newlineOffsets(chunk)
		keeper.appendEOLs(append([]int(nil), relative...))
		index.AppendEOLs(relative)
	}

	for pos := int64(0); pos <= int64(len(content))+2; pos++ {
		want := keeper.GetPositionFromCharacterIndex(pos)
		got := index.GetPositionFromCharacterIndex(pos)
		if got != want {
			t.Fatalf("offset %d: got {line %d, char %d}, want {line %d, char %d}",
				pos, got.Line, got.Character, want.Line, want.Character)
		}
	}
}

// TestLineIndexResetRetainsCapacity guards the reuse property that makes a
// per-worker index cost one allocation for the whole scan rather than one per
// file.
func TestLineIndexResetRetainsCapacity(t *testing.T) {
	index := NewLineIndex(0)
	index.IndexString(0, strings.Repeat("line\n", 500))

	if index.Len() != 500 {
		t.Fatalf("indexed %d lines, want 500", index.Len())
	}
	capacity := cap(index.eols)

	index.Reset()
	if index.Len() != 0 {
		t.Fatalf("after Reset, Len is %d, want 0", index.Len())
	}
	if cap(index.eols) != capacity {
		t.Fatalf("Reset dropped capacity: %d -> %d", capacity, cap(index.eols))
	}

	// A reset index must behave exactly like a fresh one, not like one still
	// holding the previous file's lines.
	index.IndexString(0, "a\nb")
	if got := index.GetPositionFromCharacterIndex(2); got.Line != 1 || got.Character != 0 {
		t.Fatalf("after reuse, got {line %d, char %d}, want {line 1, char 0}", got.Line, got.Character)
	}
}

// TestLineIndexIndexBytesIsChunkBoundaryAgnostic checks the property that
// AppendEOLs lacks: indexing in arbitrary pieces must give the same result as
// indexing the whole input at once. This is what allows the Phase 3 reader to
// stop cutting chunks on newline boundaries.
func TestLineIndexIndexBytesIsChunkBoundaryAgnostic(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	content := randomContent(rng, 4000)

	whole := NewLineIndex(0)
	whole.IndexString(0, content)

	pieces := NewLineIndex(0)
	for offset := 0; offset < len(content); {
		size := 1 + rng.Intn(97) // deliberately unrelated to line lengths
		if offset+size > len(content) {
			size = len(content) - offset
		}
		pieces.IndexString(int64(offset), content[offset:offset+size])
		offset += size
	}

	if whole.Len() != pieces.Len() {
		t.Fatalf("piecewise indexing found %d newlines, whole-file found %d", pieces.Len(), whole.Len())
	}
	for pos := int64(0); pos <= int64(len(content)); pos++ {
		if got, want := pieces.GetPositionFromCharacterIndex(pos), whole.GetPositionFromCharacterIndex(pos); got != want {
			t.Fatalf("offset %d: piecewise {line %d, char %d} != whole {line %d, char %d}",
				pos, got.Line, got.Character, want.Line, want.Character)
		}
	}
}

func BenchmarkLineIndexLookup(b *testing.B) {
	index := NewLineIndex(0)
	index.IndexString(0, strings.Repeat("some source line of code\n", 20000))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index.GetPositionFromCharacterIndex(int64(i % 480000))
	}
}

func BenchmarkLineKeeperLookup(b *testing.B) {
	var keeper LineKeeper
	keeper.EOLLocations = newlineOffsets(strings.Repeat("some source line of code\n", 20000))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keeper.GetPositionFromCharacterIndex(int64(i % 480000))
	}
}

// differentialInputs covers the shapes that distinguish the two
// implementations: empty input, no newlines at all, leading and trailing
// newlines, consecutive newlines (empty lines), a single enormous line, and a
// spread of random content.
func differentialInputs(rng *rand.Rand) []string {
	inputs := []string{
		"",
		"\n",
		"\n\n\n",
		"no newlines at all",
		"\nleading newline",
		"trailing newline\n",
		"a\nb\nc",
		"a\nb\nc\n",
		"\n\nempty\n\nlines\n\n",
		strings.Repeat("x", 500),        // one long unterminated line
		strings.Repeat("x", 500) + "\n", // one long terminated line
		"short\n" + strings.Repeat("y", 400) + "\nshort\n",
	}

	for i := 0; i < 12; i++ {
		inputs = append(inputs, randomContent(rng, 1+rng.Intn(300)))
	}
	return inputs
}

func randomContent(rng *rand.Rand, size int) string {
	var b strings.Builder
	b.Grow(size)
	for i := 0; i < size; i++ {
		// Newline-heavy on purpose, to generate plenty of empty and short lines.
		if rng.Intn(6) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(byte('a' + rng.Intn(26)))
		}
	}
	return b.String()
}

func newlineOffsets(s string) []int {
	var offsets []int
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func describeInput(s string) string {
	switch {
	case s == "":
		return "empty"
	case !strings.Contains(s, "\n"):
		return "no-newlines"
	default:
		return "len" + itoa(len(s)) + "-lines" + itoa(strings.Count(s, "\n"))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
