package secrets

import (
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

const (
	inlineIgnoreMarker         = "checkmate:ignore"
	inlineIgnoreNextLineSuffix = "-next-line"
)

// inlineIgnoreTracker is a zero-allocation-on-miss ResourceConsumer that
// records 0-based line numbers suppressed by inline `checkmate:ignore` or
// `checkmate:ignore-next-line` directives (case-insensitive).
type inlineIgnoreTracker struct {
	lineIndex    *util.LineIndex
	ignoredLines map[int64]struct{}
}

func (t *inlineIgnoreTracker) Reset() {
	if len(t.ignoredLines) > 0 {
		clear(t.ignoredLines)
	}
	t.lineIndex = nil
}

func (t *inlineIgnoreTracker) SetLineIndex(li *util.LineIndex) {
	t.lineIndex = li
}

func (t *inlineIgnoreTracker) SetRepositoryFile(util.RepositoryIndexedFile) {}
func (t *inlineIgnoreTracker) ConsumePath(util.RepositoryIndexedFile)       {}
func (t *inlineIgnoreTracker) End()                                         {}
func (t *inlineIgnoreTracker) ShouldProvideSourceInDiagnostics(bool)        {}

func (t *inlineIgnoreTracker) Consume(startIndex int64, source string) {
	if !containsASCIIFold(source, inlineIgnoreMarker) {
		return
	}
	if t.lineIndex == nil {
		return
	}

	mLen := len(inlineIgnoreMarker)
	nextLen := len(inlineIgnoreNextLineSuffix)
	for i := 0; i <= len(source)-mLen; i++ {
		if !hasPrefixASCIIFold(source[i:], inlineIgnoreMarker) {
			continue
		}
		line := t.lineIndex.GetPositionFromCharacterIndex(startIndex + int64(i)).Line
		targetLine := line
		if len(source)-(i+mLen) >= nextLen && hasPrefixASCIIFold(source[i+mLen:], inlineIgnoreNextLineSuffix) {
			targetLine = line + 1
		}
		if t.ignoredLines == nil {
			t.ignoredLines = make(map[int64]struct{}, 4)
		}
		t.ignoredLines[targetLine] = struct{}{}
		i += mLen - 1
	}
}

func (t *inlineIgnoreTracker) Filter(diags []*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	if len(t.ignoredLines) == 0 || len(diags) == 0 {
		return diags
	}
	out := diags[:0]
	for _, d := range diags {
		if d == nil {
			continue
		}
		if _, ignored := t.ignoredLines[d.Range.Start.Line]; ignored {
			continue
		}
		out = append(out, d)
	}
	return out
}

func hasPrefixASCIIFold(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for i := 0; i < len(lowerPrefix); i++ {
		if toLowerASCII(s[i]) != lowerPrefix[i] {
			return false
		}
	}
	return true
}
