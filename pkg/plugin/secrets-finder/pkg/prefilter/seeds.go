package prefilter

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// minSeedLength is the shortest literal we are willing to use as a seed.
//
// Short seeds are legal but worthless: a two-character seed such as "id"
// occurs in almost every source file, so the rule is admitted almost always
// and we have paid for the automaton without skipping anything. Four bytes is
// enough to cover the shortest real-world token prefixes ("AKIA", "ghp_")
// while rejecting noise.
//
// Rules whose only provable seed is shorter than this become residual. That is
// a throughput trade, never a correctness one.
const minSeedLength = 4

// maxSeedAlternatives caps how many alternative seeds a single rule may
// contribute.
//
// Seed sets are built by cross-multiplying character classes, so they can grow
// explosively: "abc" followed by three [a-z] classes is already 17,576
// strings. A rule admitted by that many different strings is not meaningfully
// filtered anyway, so past this point we stop expanding and keep a shorter,
// smaller set instead.
const maxSeedAlternatives = 32

// extractSeeds returns a set of literals with the property that any string
// matched by pattern contains at least one member of the set, or ok=false if
// no such set could be established.
//
// The returned seeds are ASCII-lowercased, because the automaton matches
// case-insensitively (see Matcher). Folding is what allows a (?i) rule to be
// filtered at all, and it can only widen the set of inputs that admit a rule,
// so it cannot break soundness.
func extractSeeds(pattern string) (seeds []string, ok bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// If we cannot parse it we cannot reason about it. In practice this
		// does not happen, because every pattern reaching us has already been
		// accepted by regexp.Compile, but a rule we cannot analyse must be
		// residual rather than guessed at.
		return nil, false
	}

	set, ok := required(re.Simplify())
	if !ok {
		return nil, false
	}
	return set, usable(set)
}

// usable reports whether a seed set is worth putting in the automaton.
//
// The set means "at least one of these occurs", so it is only as good as its
// weakest member: one unusably short seed means we could not detect the case
// where that member is the one present, and would wrongly skip the rule.
func usable(set []string) bool {
	if len(set) == 0 || len(set) > maxSeedAlternatives {
		return false
	}
	for _, s := range set {
		if len(s) < minSeedLength {
			return false
		}
	}
	return true
}

// required computes a set of literals of which at least one must appear in any
// string matched by re.
//
// The recursion is conservative by default. Every operator that can match
// without consuming its subexpression -- star, question mark, zero-minimum
// repeat -- yields no requirement, and any construct not explicitly understood
// does the same.
func required(re *syntax.Regexp) (seeds []string, ok bool) {
	// A node whose complete language we know is trivially its own requirement.
	if exact, ok := exactSet(re); ok {
		return exact, true
	}

	switch re.Op {
	case syntax.OpLiteral:
		// Reached only when exactSet gave up, which for a literal means the
		// fold orbits multiplied past the budget. A seed does not have to be
		// the whole literal, though -- any substring of it is equally
		// mandatory -- so fall back to the longest stretch that does not
		// expand. See literalRunSeed.
		return literalRunSeed(re)

	case syntax.OpCapture:
		// Grouping only; it consumes exactly what its subexpression does.
		return required(re.Sub[0])

	case syntax.OpPlus:
		// x+ matches x at least once, so whatever x requires is required.
		return required(re.Sub[0])

	case syntax.OpRepeat:
		// x{n,m} requires x only when n >= 1. Simplify() rewrites most repeats
		// into concatenations and stars, but an unsimplified one may survive.
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false

	case syntax.OpConcat:
		return requiredFromConcat(re)

	case syntax.OpAlternate:
		// Exactly one branch is matched, but we do not know which, so a
		// literal is only required overall if *every* branch requires
		// something. The result is the union across branches.
		//
		// This is the case that makes a naive extractor unsound: taking the
		// requirement of one branch and applying it to the alternation as a
		// whole would skip the rule on input matching a different branch.
		union := make(map[string]struct{})
		for _, sub := range re.Sub {
			s, ok := required(sub)
			if !ok {
				return nil, false
			}
			for _, lit := range s {
				union[lit] = struct{}{}
			}
			if len(union) > maxSeedAlternatives {
				return nil, false
			}
		}
		if len(union) == 0 {
			return nil, false
		}
		return sortedKeys(union), true

	default:
		// Everything else requires no specific literal:
		//
		//   OpStar, OpQuest         - can match empty
		//   OpAnyChar, OpAnyCharNotNL, wide OpCharClass
		//                           - constrain the character, not its identity
		//   OpEmptyMatch, OpBeginLine, OpEndLine, OpBeginText, OpEndText,
		//   OpWordBoundary, OpNoWordBoundary
		//                           - consume nothing
		//   OpNoMatch               - matches nothing; nothing to filter
		//
		// Listing them is unnecessary because the default is already the safe
		// answer, and failing closed means a future Go release adding an
		// operator cannot make this unsound.
		return nil, false
	}
}

// requiredFromConcat finds the strongest requirement in a concatenation.
//
// Every element of a concatenation is matched, so any element's requirement is
// the whole concatenation's requirement. Crucially, so is any *run* of
// adjacent elements, glued together.
//
// That gluing is not an optimisation, it is essential. Go's parser factors
// common alternation prefixes, so `(ghp_|gho_|ghu_)` never reaches us as an
// alternation of three literals -- it arrives as the concatenation
// `gh` `[opu]` `_`. Considering elements individually would yield only the
// two-character "gh", below minSeedLength, and the rule would fall into the
// residual set. Multiplying the run back out recovers {gho_, ghp_, ghu_}.
func requiredFromConcat(re *syntax.Regexp) (seeds []string, ok bool) {
	// Precompute each element's exact language once; the run scan below
	// revisits elements repeatedly.
	exacts := make([][]string, len(re.Sub))
	for i, sub := range re.Sub {
		if e, ok := exactSet(sub); ok {
			exacts[i] = e
		}
	}

	var best []string
	consider := func(s []string) {
		if usable(s) && (best == nil || stronger(s, best)) {
			best = s
		}
	}

	for i, sub := range re.Sub {
		if exacts[i] == nil {
			// Not exactly known, but it may still carry a requirement of its
			// own -- a `(?:token_)+` or a nested alternation, say.
			if s, ok := required(sub); ok {
				consider(s)
			}
			continue
		}

		// Grow the run from i for as long as the cross product stays within
		// budget. Every prefix of the run is a valid requirement, so we
		// consider each: a long run may blow the cap while a shorter one
		// yields a perfectly good seed set.
		cur := exacts[i]
		consider(cur)
		for j := i + 1; j < len(re.Sub) && exacts[j] != nil; j++ {
			next, ok := cross(cur, exacts[j])
			if !ok {
				break
			}
			cur = next
			consider(cur)
		}
	}

	return best, best != nil
}

// exactSet returns the complete set of strings re matches, if that set is
// small and fully known.
//
// "Fully known" is the strong condition here: callers rely on re matching
// nothing outside the returned set, so anything open-ended must return false.
func exactSet(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return literalSeeds(re)

	case syntax.OpCharClass:
		return charClassSet(re)

	case syntax.OpCapture:
		return exactSet(re.Sub[0])

	case syntax.OpConcat:
		cur := []string{""}
		for _, sub := range re.Sub {
			e, ok := exactSet(sub)
			if !ok {
				return nil, false
			}
			cur, ok = cross(cur, e)
			if !ok {
				return nil, false
			}
		}
		return cur, true

	case syntax.OpAlternate:
		union := make(map[string]struct{})
		for _, sub := range re.Sub {
			e, ok := exactSet(sub)
			if !ok {
				return nil, false
			}
			for _, s := range e {
				union[s] = struct{}{}
			}
			if len(union) > maxSeedAlternatives {
				return nil, false
			}
		}
		return sortedKeys(union), true

	default:
		return nil, false
	}
}

// literalRunSeed returns the longest stretch of a literal that encodes to a
// single byte string, as a one-member seed set.
//
// This exists because fold orbits multiply. `(?i)aws_secret_access_key`
// contains five instances of 's' and one 'k', each with a two-member orbit, so
// expanding the whole literal yields 64 alternatives and blows the budget --
// costing us a filter on one of the most valuable rules in the set.
//
// A seed only has to be *contained* in every match, not equal to it, so any
// substring of a mandatory literal is itself mandatory. Taking the longest run
// of non-expanding runes gives "ecret_acce" for the rule above: one seed, ten
// bytes, a far better filter than 64 alternatives would have been.
func literalRunSeed(re *syntax.Regexp) ([]string, bool) {
	fold := re.Flags&syntax.FoldCase != 0

	var best, cur string
	flush := func() {
		if len(cur) > len(best) {
			best = cur
		}
		cur = ""
	}

	for _, r := range re.Rune {
		rs, ok := runeSeeds(r, fold)
		if !ok || len(rs) != 1 {
			// Either unusable, or it expands -- end the run here.
			flush()
			continue
		}
		cur += rs[0]
	}
	flush()

	if best == "" {
		return nil, false
	}
	return []string{best}, true
}

// charClassSet enumerates a character class as a set of encoded runes.
//
// Members are the UTF-8 encoding of each rune, with ASCII letters folded to
// lowercase. Non-ASCII members are kept as their multi-byte encoding rather
// than rejected: the automaton is byte-oriented, so a multi-byte seed works
// exactly as well as a single-byte one, and dropping such members would be
// unsound (see runeSeeds).
func charClassSet(re *syntax.Regexp) ([]string, bool) {
	// Bail out on huge ranges rather than enumerating them. A negated class
	// such as [^a] spans the whole rune range and would otherwise be walked
	// one code point at a time.
	total := 0
	for i := 0; i+1 < len(re.Rune); i += 2 {
		total += int(re.Rune[i+1]-re.Rune[i]) + 1
		if total > 256 {
			return nil, false
		}
	}

	seen := make(map[string]struct{}, total)
	for i := 0; i+1 < len(re.Rune); i += 2 {
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			if !utf8.ValidRune(r) {
				return nil, false
			}
			seen[encodeRune(r)] = struct{}{}
		}
	}
	// The fold collapses [A-Za-z] from 52 members to 26, so the budget check
	// belongs after folding, not before.
	if len(seen) == 0 || len(seen) > maxSeedAlternatives {
		return nil, false
	}
	return sortedKeys(seen), true
}

// cross concatenates two seed sets pairwise, refusing to exceed the budget.
func cross(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxSeedAlternatives {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	sort.Strings(out)
	return out, true
}

// literalSeeds renders an OpLiteral as the set of byte strings that can match
// it, accounting for case folding.
func literalSeeds(re *syntax.Regexp) ([]string, bool) {
	fold := re.Flags&syntax.FoldCase != 0

	cur := []string{""}
	for _, r := range re.Rune {
		rs, ok := runeSeeds(r, fold)
		if !ok {
			return nil, false
		}
		cur, ok = cross(cur, rs)
		if !ok {
			return nil, false
		}
	}
	if len(cur) == 0 || cur[0] == "" {
		return nil, false
	}
	return cur, true
}

// runeSeeds returns every byte string that could appear in the input where
// this rune is expected.
//
// The subtle case is folded literals. Go's regexp folds using full Unicode
// simple case folding, whose orbits are not confined to ASCII: 'k' folds to
// the Kelvin sign U+212A, and 's' to the long s U+017F. So a rule containing
// (?i)key genuinely matches "\u212Aey", and a seed of "key" alone would miss
// it. Because the automaton only folds ASCII, that would be a false negative
// -- exactly the failure this package must not have.
//
// Emitting the whole fold orbit keeps it sound. The orbits are tiny (two
// members for k and s, one for every other ASCII letter), so the cost is a
// small widening of the seed set rather than losing the rule to the residual
// set, which is what rejecting folded literals outright would have cost.
func runeSeeds(r rune, fold bool) ([]string, bool) {
	if !utf8.ValidRune(r) {
		return nil, false
	}
	if !fold {
		return []string{encodeRune(r)}, true
	}

	seen := map[string]struct{}{encodeRune(r): {}}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if !utf8.ValidRune(f) {
			return nil, false
		}
		seen[encodeRune(f)] = struct{}{}
		if len(seen) > maxSeedAlternatives {
			return nil, false
		}
	}
	return sortedKeys(seen), true
}

// encodeRune renders a rune as the bytes the automaton will see, folding
// ASCII letters to lowercase to match the automaton's own folding.
func encodeRune(r rune) string {
	if r < utf8.RuneSelf {
		return string([]byte{foldASCII(byte(r))})
	}
	return string(r)
}

// foldASCII lowercases an ASCII letter and leaves every other byte alone.
func foldASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b | 0x20
	}
	return b
}

// stronger reports whether seed set a filters better than b.
//
// A set is only as good as its weakest member, since any one of them admits
// the rule. So we rank by the shortest seed first, then prefer fewer
// alternatives, and finally fall back to lexicographic order so that the
// choice is deterministic -- two equally good candidates must not be resolved
// by map or slice ordering, or the automaton would differ between builds.
func stronger(a, b []string) bool {
	if am, bm := minLength(a), minLength(b); am != bm {
		return am > bm
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return strings.Join(a, "\x00") < strings.Join(b, "\x00")
}

func minLength(s []string) int {
	m := -1
	for _, x := range s {
		if m < 0 || len(x) < m {
			m = len(x)
		}
	}
	return m
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
