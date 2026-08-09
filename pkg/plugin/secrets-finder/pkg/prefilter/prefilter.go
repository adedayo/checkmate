// Package prefilter narrows the set of regular expressions that must be
// evaluated against a file.
//
// The scan engine holds several hundred vendor rules. Evaluating every one of
// them against every file is the dominant cost of a scan, and on ordinary
// source files essentially all of that work is wasted: a rule for a GitHub
// token cannot match text that does not contain "ghp_".
//
// The prefilter makes a single Aho-Corasick pass over the file and returns the
// rules whose mandatory literal occurs in it. Everything else is skipped.
//
// # Soundness
//
// The entire value of this package rests on one property:
//
//	If rule R can match input D, then R is in Candidates(D).
//
// The converse is deliberately not guaranteed. Returning a rule that turns out
// not to match costs one wasted regex evaluation and nothing else, so the
// filter is free to over-admit. Under-admitting would silently lose findings,
// which is why every decision in seeds.go is biased towards admitting.
//
// A rule is only filtered when we can *prove* from its syntax tree that a
// particular literal must appear in any string it matches. Rules for which no
// such proof is available go into the residual set and are always run.
// FuzzPrefilterSoundness checks the property directly against real rules.
package prefilter

import (
	"regexp"
	"sort"
)

// Matcher maps file content to the set of rules worth evaluating against it.
//
// A Matcher is built once and is immutable thereafter, so a single instance is
// safe to share across every scan worker without synchronisation. The only
// mutable state involved in a lookup is the caller's Set.
type Matcher struct {
	// trans is a dense goto table, numNodes x 256, flattened.
	//
	// Fail transitions are resolved at build time into a complete automaton so
	// that matching is exactly one indexed load per input byte, with no fail
	// chain to walk. At a few thousand nodes this costs a few megabytes once,
	// which is a good trade against per-byte work repeated over every file in
	// a repository.
	trans []int32

	// out[state] lists the rules whose seed ends at state, already including
	// those reachable through fail links.
	out [][]int32

	ruleIDs  []string
	indexOf  map[string]int
	residual []string

	// residualBits is a prebuilt bitset of the always-run rules, copied into
	// the caller's Set at the start of each lookup. Rebuilding it per file
	// would be O(residual) work on the hot path for a constant answer.
	residualBits []uint64

	seeds map[string][]string
}

// Build constructs a Matcher over the supplied rules.
//
// Rules whose mandatory literal cannot be established are recorded as
// residual and are returned by every lookup.
func Build(rules map[string]*regexp.Regexp) *Matcher {
	// Sort the rule IDs before doing anything else. Rule indices, node
	// numbering and the seed-to-rule lists all derive from this order, so
	// iterating the map directly would produce a structurally different
	// automaton on each run. That is the same class of defect as the six
	// determinism bugs found in phase 0.
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	m := &Matcher{
		ruleIDs: ids,
		indexOf: make(map[string]int, len(ids)),
		seeds:   make(map[string][]string, len(ids)),
	}
	for i, id := range ids {
		m.indexOf[id] = i
	}

	b := newTrieBuilder()
	for i, id := range ids {
		seeds, ok := extractSeeds(rules[id].String())
		if !ok {
			m.residual = append(m.residual, id)
			continue
		}
		m.seeds[id] = seeds
		for _, s := range seeds {
			b.add(s, int32(i))
		}
	}

	m.residualBits = make([]uint64, wordsFor(len(ids)))
	for _, id := range m.residual {
		i := m.indexOf[id]
		m.residualBits[i>>6] |= 1 << uint(i&63)
	}

	m.trans, m.out = b.compile()
	return m
}

// Candidates fills dst with every rule that could match data.
//
// dst is reset first, so it may be reused across files; reuse is the point,
// since allocating a bitset per file would reintroduce the per-file allocation
// cost that phase 2 removed.
func (m *Matcher) Candidates(data []byte, dst *Set) {
	copy(dst.bits, m.residualBits)

	state := int32(0)
	for _, c := range data {
		// Fold to lowercase on the fly. The seeds were lowercased at build
		// time, so this makes the automaton case-insensitive without a
		// second copy of the input and without a second set of seeds.
		state = m.trans[int(state)<<8|int(foldASCII(c))]
		for _, rule := range m.out[state] {
			dst.bits[rule>>6] |= 1 << uint(rule&63)
		}
	}
}

// CandidateIDs is a convenience wrapper returning rule IDs. It allocates, and
// exists for tests and diagnostics rather than the scan path.
func (m *Matcher) CandidateIDs(data []byte) []string {
	set := m.NewSet()
	m.Candidates(data, set)
	out := make([]string, 0, 16)
	for i, id := range m.ruleIDs {
		if set.Has(i) {
			out = append(out, id)
		}
	}
	return out
}

// NewSet returns a reusable result set sized for this Matcher.
func (m *Matcher) NewSet() *Set { return &Set{bits: make([]uint64, wordsFor(len(m.ruleIDs)))} }

// NumRules returns the total number of rules known to the Matcher.
func (m *Matcher) NumRules() int { return len(m.ruleIDs) }

// RuleIDs returns the rule IDs in index order.
func (m *Matcher) RuleIDs() []string { return m.ruleIDs }

// IndexOf returns the bit position of a rule, and whether it is known.
func (m *Matcher) IndexOf(id string) (int, bool) {
	i, ok := m.indexOf[id]
	return i, ok
}

// Residual returns the rules that are always evaluated because no mandatory
// literal could be proved for them.
func (m *Matcher) Residual() []string { return m.residual }

// SeedsFor returns the seeds proved for a rule, or nil if it is residual.
func (m *Matcher) SeedsFor(id string) []string { return m.seeds[id] }

// Set is a bitset of rule indices.
type Set struct{ bits []uint64 }

// Has reports whether the rule at index i is a candidate.
func (s *Set) Has(i int) bool { return s.bits[i>>6]&(1<<uint(i&63)) != 0 }

// Count returns the number of candidate rules.
func (s *Set) Count() int {
	n := 0
	for _, w := range s.bits {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}

func wordsFor(n int) int { return (n + 63) / 64 }

// trieBuilder accumulates seeds into a trie, then resolves it into a complete
// automaton.
type trieBuilder struct {
	next []map[byte]int32
	out  [][]int32
}

func newTrieBuilder() *trieBuilder {
	return &trieBuilder{
		next: []map[byte]int32{{}},
		out:  [][]int32{nil},
	}
}

func (b *trieBuilder) add(seed string, rule int32) {
	state := int32(0)
	for i := 0; i < len(seed); i++ {
		c := seed[i]
		nxt, ok := b.next[state][c]
		if !ok {
			nxt = int32(len(b.next))
			b.next = append(b.next, map[byte]int32{})
			b.out = append(b.out, nil)
			b.next[state][c] = nxt
		}
		state = nxt
	}
	b.out[state] = append(b.out[state], rule)
}

// compile performs the standard Aho-Corasick BFS, resolving fail links into a
// dense transition table and propagating outputs along them.
func (b *trieBuilder) compile() ([]int32, [][]int32) {
	n := len(b.next)
	trans := make([]int32, n*256)
	fail := make([]int32, n)

	queue := make([]int32, 0, n)

	// Depth 1: a miss returns to the root rather than to a parent.
	for c := 0; c < 256; c++ {
		if s, ok := b.next[0][byte(c)]; ok {
			trans[c] = s
			fail[s] = 0
			queue = append(queue, s)
		}
	}

	for i := 0; i < len(queue); i++ {
		state := queue[i]

		// Outputs are inherited from the fail state, so a seed that is a
		// suffix of another is still reported. Missing this is the classic
		// Aho-Corasick bug, and here it would mean silently dropping a rule.
		if o := b.out[fail[state]]; len(o) > 0 {
			b.out[state] = dedupe(append(append([]int32{}, b.out[state]...), o...))
		}

		for c := 0; c < 256; c++ {
			base := int(state) << 8
			if nxt, ok := b.next[state][byte(c)]; ok {
				trans[base|c] = nxt
				fail[nxt] = trans[int(fail[state])<<8|c]
				queue = append(queue, nxt)
			} else {
				// No edge: follow the already-resolved fail transition. The
				// fail state is always shallower and therefore already
				// complete, which is what makes one BFS pass sufficient.
				trans[base|c] = trans[int(fail[state])<<8|c]
			}
		}
	}

	return trans, b.out
}

func dedupe(in []int32) []int32 {
	sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
