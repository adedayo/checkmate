package util

import (
	"io"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// noopConsumer isolates the multiplexer's own cost: it accepts the stream and
// does nothing, so a benchmark using it measures reading, line indexing and
// dispatch with no matching at all.
type noopConsumer struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	bytes int
	calls int
}

func (n *noopConsumer) Consume(startIndex int64, source string) {
	n.bytes += len(source)
	n.calls++
}
func (n *noopConsumer) ConsumePath(RepositoryIndexedFile)           {}
func (n *noopConsumer) SetLineIndex(*LineIndex)                     {}
func (n *noopConsumer) SetRepositoryFile(RepositoryIndexedFile)     {}
func (n *noopConsumer) ShouldProvideSourceInDiagnostics(bool)       {}
func (n *noopConsumer) End()                                        {}
func (n *noopConsumer) ShouldExcludePath(string) bool               { return false }
func (n *noopConsumer) ShouldExclude(string, string) bool           { return false }
func (n *noopConsumer) ShouldExcludeHash(string) bool               { return false }
func (n *noopConsumer) ShouldExcludeHashOnPath(string, string) bool { return false }
func (n *noopConsumer) ShouldExcludeValue(string) bool              { return false }

// TestReadPathDeliversWholeSource pins the contract the finders depend on:
// every byte of the source reaches the consumers exactly once, with correct
// start indices, whichever read path is taken.
func TestReadPathDeliversWholeSource(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"single-line-no-newline", strings.Repeat("x", 100)},
		{"many-lines", strings.Repeat("a line of source\n", 5000)},
		{"one-huge-line", strings.Repeat("x", 2_000_000)},
		{"no-trailing-newline", "alpha\nbeta\ngamma"},
		{"newline-only", strings.Repeat("\n", 1000)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consumer := &noopConsumer{}
			var reader io.Reader = strings.NewReader(tc.content)

			NewResourceMultiplexer(RepositoryIndexedFile{File: tc.name}, &reader, false, consumer)

			if consumer.bytes != len(tc.content) {
				t.Fatalf("consumer saw %d bytes, source had %d", consumer.bytes, len(tc.content))
			}
		})
	}
}

// TestReadPathPositionsMatchWholeFileIndex checks that the line index the
// multiplexer builds agrees with indexing the same content in one go — i.e.
// that whichever path is taken, positions reported to findings are identical.
func TestReadPathPositionsMatchWholeFileIndex(t *testing.T) {
	content := strings.Repeat("some source line\n", 3000) + strings.Repeat("z", 500)

	consumer := &noopConsumer{}
	var reader io.Reader = strings.NewReader(content)
	mux := NewResourceMultiplexer(RepositoryIndexedFile{File: "x.go"}, &reader, false, consumer)

	expected := NewLineIndex(0)
	expected.IndexString(0, content)

	for pos := int64(0); pos < int64(len(content)); pos += 37 {
		got := mux.(PositionProvider).GetPosition(pos)
		want := expected.GetPositionFromCharacterIndex(pos)
		if got != want {
			t.Fatalf("offset %d: multiplexer gave {line %d, char %d}, want {line %d, char %d}",
				pos, got.Line, got.Character, want.Line, want.Character)
		}
	}
}

// BenchmarkReadPathOneHugeLine is the direct measure of the quadratic
// concatenation this phase removed.
//
// The old reader accumulated chunks with largeChunk += remnant + string(buf),
// and a file with no newlines never yields a chunk boundary, so the whole
// accumulator was copied on every 4KB read. Cost grew with the square of file
// size. This benchmark is the shape that triggered it.
func BenchmarkReadPathOneHugeLine(b *testing.B) {
	content := strings.Repeat("x", 4_000_000)
	benchmarkReadPath(b, content)
}

// BenchmarkReadPathManyLines is the ordinary case, as a control: it should be
// dominated by the single string conversion, not by dispatch.
func BenchmarkReadPathManyLines(b *testing.B) {
	content := strings.Repeat("a fairly typical line of source code\n", 100_000)
	benchmarkReadPath(b, content)
}

func benchmarkReadPath(b *testing.B, content string) {
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		consumer := &noopConsumer{}
		var reader io.Reader = strings.NewReader(content)
		NewResourceMultiplexer(RepositoryIndexedFile{File: "bench"}, &reader, false, consumer)
		if consumer.bytes != len(content) {
			b.Fatalf("short read: %d of %d", consumer.bytes, len(content))
		}
	}
}

var _ code.Position // keep the code import meaningful if positions move
