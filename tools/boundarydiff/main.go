// Command boundarydiff finds the smallest input on which two engine revisions
// disagree, and is the oracle for openspec change 004.
//
// It exists because the divergence it investigates is not reproducible by
// inspection. Two manual probes failed to reproduce it by sweeping a
// well-formed secret across the 4,096-byte seam, so the search is automated
// and the reduction is driven by an oracle rather than by intuition.
//
// Two properties matter more than speed here.
//
// First, the oracle runs each engine several times and refuses to answer if
// either disagrees with itself. The pre-change engine is *not* stable against
// itself on some inputs (defects D3/D4 in the 003 record: YAMLSecretAssignment
// vs JSONSecretAssignment on identical bytes). Delta debugging against a flaky
// oracle minimises toward the flakiness, and produces a confident, meaningless
// answer.
//
// Second, reduction is offset-preserving. The divergence requires the file to
// exceed 4,096 bytes so that a second chunk exists at all, so ordinary ddmin
// would "minimise" by shrinking the file below that threshold and reporting
// that the divergence disappeared. That is a false result: the mechanism did
// not go away, its precondition did. So deleting a line here replaces it with
// spaces of exactly the same length instead of removing its bytes. Every byte
// offset and every newline position is invariant across the entire search,
// which holds chunk geometry fixed and isolates the one variable of interest:
// which line *contents* the divergence actually needs.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type oracle struct {
	baselineBin string
	currentBin  string
	probePath   string
	runs        int
	calls       int
}

// verdict is deliberately three-valued. Collapsing "unstable" into "does not
// diverge" is how a flaky oracle silently steers a search.
type verdict int

const (
	same verdict = iota
	diverges
	unstable
)

func (v verdict) String() string {
	switch v {
	case same:
		return "same"
	case diverges:
		return "diverges"
	default:
		return "unstable"
	}
}

// dump runs one engine repeatedly and returns its finding set, or ok=false if
// the engine contradicted itself across runs.
func (o *oracle) dump(bin string) (string, bool) {
	var first string
	for i := 0; i < o.runs; i++ {
		out, err := exec.Command(bin, o.probePath).Output()
		if err != nil {
			// A crash is a real signal, not a reason to stop: record it as a
			// distinct finding set so it can diverge like any other.
			out = []byte("ENGINE-ERROR: " + err.Error())
		}
		got := canonical(string(out))
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			return "", false
		}
	}
	return first, true
}

// canonical strips output that is not a finding. The pre-change tree prints a
// stray "TESTING COMPILATION ..." debug line to stdout; left in, it would
// register as a permanent difference and the search would never converge.
func canonical(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "" || !strings.Contains(l, "\t") {
			continue
		}
		keep = append(keep, l)
	}
	sort.Strings(keep)
	return strings.Join(keep, "\n")
}

func (o *oracle) test(content []byte) verdict {
	o.calls++
	if err := os.WriteFile(o.probePath, content, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write probe: %v\n", err)
		os.Exit(1)
	}
	base, ok := o.dump(o.baselineBin)
	if !ok {
		return unstable
	}
	cur, ok := o.dump(o.currentBin)
	if !ok {
		return unstable
	}
	if base == cur {
		return same
	}
	return diverges
}

// blank replaces a line's content with spaces, preserving its length exactly.
func blank(line []byte) []byte {
	return bytes.Repeat([]byte{' '}, len(line))
}

// render rebuilds the candidate: lines in keep stay as they are, all others
// become equal-length whitespace.
func render(lines [][]byte, keep map[int]bool) []byte {
	var buf bytes.Buffer
	for i, l := range lines {
		if keep[i] {
			buf.Write(l)
		} else {
			buf.Write(blank(l))
		}
		if i < len(lines)-1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// ddmin reduces the set of content-bearing lines, in the classic
// delta-debugging shape: try to drop increasingly fine partitions, and keep
// any drop that preserves divergence.
func ddmin(o *oracle, lines [][]byte, keep map[int]bool) map[int]bool {
	n := 2
	for {
		idx := sortedKeys(keep)
		if len(idx) < 2 {
			return keep
		}
		if n > len(idx) {
			n = len(idx)
		}
		progress := false
		size := (len(idx) + n - 1) / n

		for start := 0; start < len(idx); start += size {
			end := start + size
			if end > len(idx) {
				end = len(idx)
			}
			cand := map[int]bool{}
			for k := range keep {
				cand[k] = true
			}
			for _, i := range idx[start:end] {
				delete(cand, i)
			}
			if len(cand) == 0 {
				continue
			}
			if o.test(render(lines, cand)) == diverges {
				keep = cand
				progress = true
				n = max(n-1, 2)
				break
			}
		}
		if !progress {
			if n >= len(idx) {
				return keep
			}
			n = min(n*2, len(idx))
		}
	}
}

func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func main() {
	var (
		file     = flag.String("file", "", "input to reduce")
		baseline = flag.String("baseline", "", "baseline dumpfindings binary")
		current  = flag.String("current", "", "current dumpfindings binary")
		runs     = flag.Int("runs", 3, "engine runs per side; >1 detects self-instability")
		out      = flag.String("out", "", "write the reduced input here")
		probe    = flag.String("probe", "", "fixed probe path (kept constant so findings compare)")
		minimise = flag.Bool("minimise", false, "reduce, rather than just report the diff")
	)
	flag.Parse()

	if *file == "" || *baseline == "" || *current == "" {
		fmt.Fprintln(os.Stderr, "usage: boundarydiff -file F -baseline BIN -current BIN [-minimise]")
		os.Exit(2)
	}

	src, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *file, err)
		os.Exit(1)
	}

	probePath := *probe
	if probePath == "" {
		probePath = filepath.Join(os.TempDir(), "boundarydiff-probe"+filepath.Ext(*file))
	}

	o := &oracle{baselineBin: *baseline, currentBin: *current, probePath: probePath, runs: *runs}

	// Verify the oracle before trusting it to drive a search: it must say
	// "diverges" on the input we believe diverges, and "same" on an input we
	// believe does not. An oracle that answers "diverges" to everything
	// reduces to noise and looks just as convincing.
	fmt.Fprintf(os.Stderr, "== oracle self-check ==\n")
	if v := o.test(src); v != diverges {
		fmt.Fprintf(os.Stderr, "known-positive answered %q, not \"diverges\" -- oracle unusable\n", v)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "known-positive: diverges  OK")

	if v := o.test([]byte("const a = 1;\n")); v != same {
		fmt.Fprintf(os.Stderr, "known-negative answered %q, not \"same\" -- oracle unusable\n", v)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "known-negative (sub-4KB): same  OK")

	if !*minimise {
		return
	}

	lines := bytes.Split(src, []byte("\n"))
	keep := map[int]bool{}
	for i := range lines {
		keep[i] = true
	}

	fmt.Fprintf(os.Stderr, "== minimising over %d lines ==\n", len(lines))
	keep = ddmin(o, lines, keep)
	reduced := render(lines, keep)

	// The invariant that makes the result meaningful. If this ever fires, the
	// reduction changed chunk geometry and the answer is not trustworthy.
	if len(reduced) != len(src) {
		fmt.Fprintf(os.Stderr, "BUG: reduction changed length %d -> %d\n", len(src), len(reduced))
		os.Exit(1)
	}

	idx := sortedKeys(keep)
	fmt.Fprintf(os.Stderr, "\n== result ==\n")
	fmt.Fprintf(os.Stderr, "oracle calls:            %d\n", o.calls)
	fmt.Fprintf(os.Stderr, "size:                    %d bytes (unchanged, by construction)\n", len(reduced))
	fmt.Fprintf(os.Stderr, "content-bearing lines:   %d of %d\n", len(idx), len(lines))
	for _, i := range idx {
		fmt.Fprintf(os.Stderr, "  line %d: %s\n", i+1, strings.TrimRight(string(lines[i]), " "))
	}

	if *out != "" {
		if err := os.WriteFile(*out, reduced, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\nwrote %s\n", *out)
	}
}
