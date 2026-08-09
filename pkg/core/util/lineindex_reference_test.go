package util

import (
	"sort"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/code"
)

// LineKeeper is the previous production implementation of line/position
// mapping, retained solely as a test oracle for LineIndex.
//
// It was replaced because every lookup was a linear scan under a mutex, but it
// was also the definition of correct positioning for every finding CheckMate
// has ever reported. Keeping it here means TestLineIndexDifferential compares
// the new implementation against the real old code rather than against a
// paraphrase of it, so the equivalence claim cannot rot.
//
// It is not used in production and must not be reintroduced there.
// LineKeeper keeps track of line numberson a textual source file and can map character location to the relevant `code.Position`
type LineKeeper struct {
	EOLLocations []int // end-of-line locations
	lock         sync.Mutex
}

func (lk *LineKeeper) appendEOLs(eols []int) {
	sorted := sort.IntSlice(eols)
	lk.lock.Lock()
	//if this is not the first set of EOLs, "continue" from where we stopped last time, by adding the location to
	//these set of eol's position. Note this works because we chunk data on EOL boundaries
	if len(lk.EOLLocations) > 0 {
		last := lk.EOLLocations[len(lk.EOLLocations)-1]
		for i := range sorted {
			sorted[i] += last + 1
		}
	}
	lk.EOLLocations = append(lk.EOLLocations, sorted...)
	lk.lock.Unlock()
}

// GetPositionFromCharacterIndex returns the `code.Position` given the index of the character in the file
func (lk *LineKeeper) GetPositionFromCharacterIndex(pos int64) code.Position {
	//lk.EOLLocations are sorted
	lk.lock.Lock()
	defer lk.lock.Unlock()
	if len(lk.EOLLocations) > 0 {
		end := int64(len(lk.EOLLocations) - 1)
		if pos > int64(lk.EOLLocations[end]) {
			return code.Position{
				Line:      end + 1,
				Character: pos - int64(lk.EOLLocations[end]) - 1,
			}
		}
		for i, eol := range lk.EOLLocations {
			if int64(eol) >= pos {
				if i > 0 {
					return code.Position{
						Line:      int64(i),
						Character: pos - int64(lk.EOLLocations[i-1]) - 1,
					}
				}
				break
			}
		}
	}
	return code.Position{
		Line:      0,
		Character: pos,
	}
}
