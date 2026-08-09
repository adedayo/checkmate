package diagnostics

import (
	"sort"
	"strings"
)

// SubsumeOverlapping filters a list of SecurityDiagnostics so that when multiple
// findings overlap at the same file location, the finding with higher confidence
// and/or more complete range subsumes (replaces) the less confident or partial findings.
func SubsumeOverlapping(diags []*SecurityDiagnostic) []*SecurityDiagnostic {
	if len(diags) <= 1 {
		return diags
	}

	// Group diagnostics by file location
	grouped := make(map[string][]*SecurityDiagnostic)
	for _, d := range diags {
		if d == nil {
			continue
		}
		loc := ""
		if d.Location != nil {
			loc = *d.Location
		}
		grouped[loc] = append(grouped[loc], d)
	}

	var result []*SecurityDiagnostic

	for _, group := range grouped {
		if len(group) == 1 {
			result = append(result, group[0])
			continue
		}

		// Impose a deterministic, content-derived order before resolving
		// overlaps.
		//
		// The resolution below is positional: when neither finding dominates
		// the other it keeps whichever appears first, and the `break` on
		// subsumption makes the outcome depend on iteration order throughout.
		// Upstream order is not stable — it derives from map iteration in the
		// aggregator and from the order rules happen to fire — so identical
		// input could credit the same secret to different rules on different
		// runs, changing the derived finding ID and breaking cross-scan
		// finding identity.
		//
		// Sorting by content makes the outcome a pure function of the finding
		// set rather than of its arrival order. This is a prerequisite for
		// parallel scanning, where arrival order is nondeterministic by
		// construction.
		SortDiagnosticsDeterministically(group)

		// Keep track of which items in group are subsumed
		subsumed := make([]bool, len(group))

		for i := 0; i < len(group); i++ {
			if subsumed[i] {
				continue
			}
			for j := 0; j < len(group); j++ {
				if i == j || subsumed[j] {
					continue
				}

				d1 := group[i]
				d2 := group[j]

				if DiagnosticsOverlap(d1, d2) {
					if Dominates(d1, d2) {
						subsumed[j] = true
					} else if Dominates(d2, d1) {
						subsumed[i] = true
						break
					} else {
						// Tie breaker: keep the earlier index i, subsume j
						if i < j {
							subsumed[j] = true
						} else {
							subsumed[i] = true
							break
						}
					}
				}
			}
		}

		for i, d := range group {
			if !subsumed[i] {
				result = append(result, d)
			}
		}
	}

	return result
}

// SortDiagnosticsDeterministically imposes a stable total order on a set of
// diagnostics, derived purely from their content.
//
// The ordering is deliberately "strongest first": earlier raw range, then
// wider span, then higher confidence. That preserves the existing intent of
// the subsumption pass — which prefers to keep the earlier, more complete,
// more confident finding — while removing its dependence on arrival order.
// The trailing comparisons on provider ID, headline and source exist purely
// to guarantee the order is total, so no two distinct findings can tie.
func SortDiagnosticsDeterministically(diags []*SecurityDiagnostic) {
	sort.SliceStable(diags, func(i, j int) bool {
		return diagnosticLess(diags[i], diags[j])
	})
}

// SortDiagnosticsCanonically imposes a stable total order on a set of
// diagnostics drawn from *more than one file*.
//
// SortDiagnosticsDeterministically is a within-file order: it opens on
// RawRange.StartIndex, which is a per-file offset and therefore says nothing
// useful when two findings come from different files. That was adequate while
// findings arrived in walk order, because the file grouping was already
// implied by arrival. Once files are scanned in parallel the grouping is gone,
// so a location-first key is needed before anything is persisted or compared.
//
// Location is compared first, then the existing within-file order is applied
// unchanged — so a file's findings are ordered exactly as they always were,
// and only the arrangement *between* files is newly pinned.
func SortDiagnosticsCanonically(diags []*SecurityDiagnostic) {
	sort.SliceStable(diags, func(i, j int) bool {
		a, b := diags[i], diags[j]

		if la, lb := derefString(a.Location), derefString(b.Location); la != lb {
			return la < lb
		}
		if a.RepositoryIndex != b.RepositoryIndex {
			return a.RepositoryIndex < b.RepositoryIndex
		}
		return diagnosticLess(a, b)
	})
}

// diagnosticLess is the within-file comparison shared by both sorts above.
func diagnosticLess(a, b *SecurityDiagnostic) bool {
	{
		if a.RawRange.StartIndex != b.RawRange.StartIndex {
			return a.RawRange.StartIndex < b.RawRange.StartIndex
		}

		// Wider span first.
		spanA, spanB := getDiagnosticSpan(a), getDiagnosticSpan(b)
		if spanA != spanB {
			return spanA > spanB
		}

		// Higher confidence first.
		confA := a.Justification.Headline.Confidence
		confB := b.Justification.Headline.Confidence
		if confA != confB {
			return confA > confB
		}

		if a.Range.Start.Line != b.Range.Start.Line {
			return a.Range.Start.Line < b.Range.Start.Line
		}
		if a.Range.Start.Character != b.Range.Start.Character {
			return a.Range.Start.Character < b.Range.Start.Character
		}

		if pa, pb := derefString(a.ProviderID), derefString(b.ProviderID); pa != pb {
			return pa < pb
		}
		if a.Justification.Headline.Description != b.Justification.Headline.Description {
			return a.Justification.Headline.Description < b.Justification.Headline.Description
		}
		return derefString(a.Source) < derefString(b.Source)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DiagnosticsOverlap returns true if d1 and d2 overlap in range or source text
func DiagnosticsOverlap(d1, d2 *SecurityDiagnostic) bool {
	if d1 == nil || d2 == nil {
		return false
	}

	// 1. Check raw character index range overlap if both have RawRange set
	if d1.RawRange.EndIndex > 0 && d2.RawRange.EndIndex > 0 {
		maxStart := maxInt64(d1.RawRange.StartIndex, d2.RawRange.StartIndex)
		minEnd := minInt64(d1.RawRange.EndIndex, d2.RawRange.EndIndex)
		if maxStart <= minEnd {
			return true
		}
	}

	// 2. Check code.Range overlap (Line and Character)
	r1 := d1.Range
	r2 := d2.Range
	if r1.Start.Line >= 0 && r2.Start.Line >= 0 {
		// Line ranges overlap?
		maxLineStart := maxInt64(r1.Start.Line, r2.Start.Line)
		minLineEnd := minInt64(r1.End.Line, r2.End.Line)

		if maxLineStart <= minLineEnd {
			// On the same line start/end, check character overlap
			if r1.Start.Line == r2.Start.Line && r1.End.Line == r2.End.Line {
				maxCharStart := maxInt64(r1.Start.Character, r2.Start.Character)
				minCharEnd := minInt64(r1.End.Character, r2.End.Character)
				if maxCharStart <= minCharEnd {
					return true
				}
			} else {
				return true
			}
		}
	}

	// 3. Check source string containment if ranges are unavailable
	if d1.Source != nil && d2.Source != nil && *d1.Source != "" && *d2.Source != "" {
		s1 := strings.TrimSpace(*d1.Source)
		s2 := strings.TrimSpace(*d2.Source)
		if strings.Contains(s1, s2) || strings.Contains(s2, s1) {
			return true
		}
	}

	return false
}

// Dominates returns true if d1 strictly dominates d2 (higher confidence or more complete span)
func Dominates(d1, d2 *SecurityDiagnostic) bool {
	conf1 := d1.Justification.Headline.Confidence
	conf2 := d2.Justification.Headline.Confidence

	// Rule 1: Higher confidence strictly dominates
	if conf1 > conf2 {
		return true
	}
	if conf1 < conf2 {
		return false
	}

	// Rule 2: Equal confidence -> larger span/completeness dominates
	span1 := getDiagnosticSpan(d1)
	span2 := getDiagnosticSpan(d2)

	return span1 > span2
}

func getDiagnosticSpan(d *SecurityDiagnostic) int64 {
	if d.RawRange.EndIndex > d.RawRange.StartIndex {
		return d.RawRange.EndIndex - d.RawRange.StartIndex
	}

	if d.Range.End.Line > d.Range.Start.Line {
		return (d.Range.End.Line - d.Range.Start.Line + 1) * 100
	}

	if d.Range.End.Character > d.Range.Start.Character {
		return d.Range.End.Character - d.Range.Start.Character
	}

	if d.Source != nil {
		return int64(len(*d.Source))
	}

	return 0
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
