package code

//Position in a text document is a zero-based line and zero-based character offset. A position is between two characters like an ‘insert’ cursor in a editor.
type Position struct {

	//Line position in a document (zero-based).
	Line int `json:"line"`

	//Character offset on a line in a document (zero-based). Assuming that the line is
	//represented as a string, the `character` value represents the gap between the
	//`character` and `character + 1`.
	//If the character value is greater than the line length it defaults back to the
	//line length.
	Character int `json:"character"`
}

//LessOrEqual returns whether `thisPosition` is chronologically "before" `thatPosition`
func (thisPos Position) LessOrEqual(thatPos Position) bool {
	return thisPos.Line <= thatPos.Line && thisPos.Character <= thatPos.Character
}

//Range in a text document expressed as (zero-based) start and end positions. A range is comparable to a selection in an editor. Therefore the end position is exclusive. If you want to specify a range that contains a line including the line ending character(s) then use an end position denoting the start of the next line.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

//Contains checks whether `thisRange` completely overlaps `thatRange` i.e. `thatRange` = `thisRange` intersect `thatRange`
func (thisRange Range) Contains(thatRange Range) bool {
	return thatRange == thisRange.Intersect(thatRange)
}

//Intersect calculates the overlap between `thisRange` and `thatRange` and returns the overlapping range, otherwise it returns a range with -1 in all position coordinates
func (thisRange Range) Intersect(thatRange Range) Range {
	null := Position{
		Line:      -1,
		Character: -1,
	}
	intersect := Range{
		Start: null,
		End:   null,
	}

	if intersection := intersectRanges(thisRange, thatRange); intersection != intersect {
		return intersection
	}

	return intersect
}

func intersectRanges(a, b Range) Range {
	null := Position{
		Line:      -1,
		Character: -1,
	}
	intersect := Range{
		Start: null,
		End:   null,
	}
	if a.Start.LessOrEqual(b.Start) && b.Start.LessOrEqual(a.End) {
		intersect.Start = b.Start
		if b.End.LessOrEqual(a.End) {
			intersect.End = b.End
		} else {
			intersect.End = a.End
		}
	} else if b.Start.LessOrEqual(a.Start) && a.Start.LessOrEqual(b.End) {
		intersect.Start = a.Start
		if a.End.LessOrEqual(b.End) {
			intersect.End = a.End
		} else {
			intersect.End = b.End
		}
	}
	return intersect
}
