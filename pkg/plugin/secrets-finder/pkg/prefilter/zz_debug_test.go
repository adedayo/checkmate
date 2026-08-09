package prefilter

import (
	"regexp/syntax"
	"testing"
)

func TestDebugGH(t *testing.T) {
	p := `(?i:(gh[pousr]_[A-Za-z0-9_]{36,255}))`
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	s := re.Simplify()
	t.Logf("op=%v\n%s", s.Op, s)
	for i, sub := range s.Sub {
		e, ok := exactSet(sub)
		t.Logf("sub[%d] op=%v exact=%v %q", i, sub.Op, ok, e)
	}
	seeds, ok := extractSeeds(p)
	t.Logf("seeds=%q ok=%v", seeds, ok)
}
