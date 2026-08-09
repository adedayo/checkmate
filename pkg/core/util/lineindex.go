package util

import (
	"sort"

	"github.com/adedayo/checkmate/pkg/core/code"
)

// LineIndex maps a character offset in a file onto a code.Position.
//
// It replaces LineKeeper, which had three costs that matter at scale:
//
//  1. GetPositionFromCharacterIndex scanned the end-of-line slice linearly for
//     every lookup. Every finding costs a scan proportional to the file's line
//     count, so a file with many findings is quadratic in its own size.
//  2. Every lookup and every append took a mutex, even though a file is
//     indexed by exactly one goroutine and then queried by that same
//     goroutine. The lock only existed because the old multiplexer fanned
//     chunks out across goroutines; that fan-out is gone.
//  3. Offsets were stored as int, i.e. 8 bytes each on 64-bit. Line offsets
//     are bounded by MaxIndexableFileSize, so int32 halves the index's memory
//     for no loss.
//
// A LineIndex is reusable: Reset returns it to the empty state while keeping
// its backing array, so a per-worker index costs one allocation for the
// lifetime of the scan rather than one per file.
//
// A LineIndex is not safe for concurrent use. Parallelism belongs at the file
// level, with one index per worker.
type LineIndex struct {
	// eols holds the absolute offset of each '\n' in the file, ascending.
	eols []int32
}

// MaxIndexableFileSize is the largest file a LineIndex can describe, imposed
// by the int32 offsets. Two gigabytes is far above the engine's scanning
// thresholds; offsets beyond it are clamped rather than silently wrapping into
// negative positions.
const MaxIndexableFileSize = int64(1<<31 - 1)

// NewLineIndex returns an index with room for capacity lines.
func NewLineIndex(capacity int) *LineIndex {
	return &LineIndex{eols: make([]int32, 0, capacity)}
}

// Reset empties the index while retaining its capacity for reuse.
func (li *LineIndex) Reset() {
	li.eols = li.eols[:0]
}

// Len returns the number of recorded end-of-line positions.
func (li *LineIndex) Len() int {
	return len(li.eols)
}

// IndexBytes appends the offsets of every '\n' in data, where data begins at
// absolute offset baseOffset in the file.
//
// This is the preferred way to build the index: it is a single pass over the
// bytes with no intermediate slice of match locations, and it does not care
// where chunk boundaries fall.
func (li *LineIndex) IndexBytes(baseOffset int64, data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			li.appendOffset(baseOffset + int64(i))
		}
	}
}

// IndexString is IndexBytes for a string, avoiding the []byte conversion.
func (li *LineIndex) IndexString(baseOffset int64, data string) {
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			li.appendOffset(baseOffset + int64(i))
		}
	}
}

// AppendEOLs records end-of-line offsets expressed relative to the start of
// the current chunk.
//
// This reproduces LineKeeper.appendEOLs, including its assumption that chunks
// are split on end-of-line boundaries so the next chunk starts one byte past
// the previous chunk's final newline. It exists so callers that already have
// match locations can be ported without changing behaviour; new code should
// prefer IndexBytes, which carries an explicit base offset and therefore does
// not depend on how chunks were cut.
func (li *LineIndex) AppendEOLs(eols []int) {
	if len(eols) == 0 {
		return
	}

	sorted := make([]int, len(eols))
	copy(sorted, eols)
	sort.Ints(sorted)

	var base int64
	if n := len(li.eols); n > 0 {
		base = int64(li.eols[n-1]) + 1
	}

	for _, e := range sorted {
		li.appendOffset(base + int64(e))
	}
}

func (li *LineIndex) appendOffset(offset int64) {
	if offset > MaxIndexableFileSize {
		offset = MaxIndexableFileSize
	}
	li.eols = append(li.eols, int32(offset))
}

// GetPositionFromCharacterIndex returns the zero-based line and character
// position of the given absolute character offset.
//
// Behaviour is identical to LineKeeper.GetPositionFromCharacterIndex, but by
// binary search rather than a linear scan. TestLineIndexDifferential asserts
// the two agree over random inputs and offsets.
func (li *LineIndex) GetPositionFromCharacterIndex(pos int64) code.Position {
	n := len(li.eols)
	if n == 0 {
		return code.Position{Line: 0, Character: pos}
	}

	// i is the first line whose terminating newline is at or after pos, which
	// is the line pos falls on. If pos is past the final newline, i == n and
	// pos is on the unterminated trailing line, numbered n.
	i := sort.Search(n, func(k int) bool { return int64(li.eols[k]) >= pos })

	if i == 0 {
		// On the first line: the offset is the character position directly.
		return code.Position{Line: 0, Character: pos}
	}

	// Otherwise the line starts one byte after the preceding newline.
	return code.Position{
		Line:      int64(i),
		Character: pos - int64(li.eols[i-1]) - 1,
	}
}
