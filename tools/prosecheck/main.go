// Command prosecheck finds em dashes in text a user will read.
//
// The rule is a house style decision, not a correctness one: em dashes read as
// affected in a security tool's output, they are awkward to type on most
// keyboards so they drift into inconsistency, and they render unpredictably in
// terminals, in Windows console code pages, and in the plain-text half of an
// email report. A hyphen is unambiguous everywhere.
//
// The difficulty is not finding the character. It is finding it *only* where a
// user will see it. This repository's comments and specifications are written
// in deliberate prose and use em dashes throughout; rewriting those would be a
// large diff that changes nothing a user encounters, and would train everyone
// to ignore the check. So prosecheck reads structure rather than lines:
//
//	.go, .ts   string literals only, never comments
//	.html      text and attributes, never <!-- --> comments
//	.md        everything, but only in files a user is meant to read
//
// A check that flagged a word in a code comment would be noise, and a check
// that is noise is one that gets skipped.
//
// Usage:
//
//	prosecheck              report, exit 1 if anything is found
//	prosecheck --fix        rewrite what it finds, report what it changed
//	prosecheck --quiet      only speak when something is wrong
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	var (
		fix   = flag.Bool("fix", false, "rewrite occurrences instead of only reporting them")
		quiet = flag.Bool("quiet", false, "print nothing unless something is found")
		root  = flag.String("root", ".", "directory to scan")
	)
	flag.Parse()

	hits, err := scanTree(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prosecheck: %v\n", err)
		os.Exit(2)
	}

	if len(hits) == 0 {
		if !*quiet {
			fmt.Println("✔ No em dashes in user-visible text.")
		}
		return
	}

	if *fix {
		changed, err := applyFixes(*root, hits)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prosecheck: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("✔ Rewrote %d occurrence(s) in %d file(s).\n", len(hits), changed)
		fmt.Println("  Review the diff: em dashes joining clauses become ' - ', but a")
		fmt.Println("  sentence that needed one often reads better re-punctuated.")
		return
	}

	report(hits)
	os.Exit(1)
}

func report(hits []hit) {
	byFile := map[string][]hit{}
	for _, h := range hits {
		byFile[h.Path] = append(byFile[h.Path], h)
	}

	paths := make([]string, 0, len(byFile))
	for p := range byFile {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	fmt.Printf("✘ %d em dash(es) in user-visible text, in %d file(s):\n\n", len(hits), len(paths))
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
		for _, h := range byFile[p] {
			fmt.Printf("      %d: %s\n", h.Line, h.Context)
		}
	}
	fmt.Println()
	fmt.Println("  These are strings a user reads, not comments. Fix with:")
	fmt.Printf("      go run %s --fix\n", invocation())
	fmt.Println()
}

// invocation reports how to run this tool in the repository it finds itself in.
// It lives under cmd/ where that is the convention and tools/ where cmd/ is
// taken by Cobra commands, and a wrong instruction in an error message is worse
// than none.
func invocation() string {
	for _, dir := range []string{"./cmd/prosecheck", "./tools/prosecheck"} {
		if _, err := os.Stat(strings.TrimPrefix(dir, "./")); err == nil {
			return dir
		}
	}
	return "./cmd/prosecheck"
}

// applyFixes rewrites each file once, rather than per hit, so that line and
// column offsets recorded during the scan stay valid.
func applyFixes(root string, hits []hit) (int, error) {
	byFile := map[string]bool{}
	for _, h := range hits {
		byFile[h.Path] = true
	}

	for p := range byFile {
		full := filepath.Join(root, p)
		b, err := os.ReadFile(full)
		if err != nil {
			return 0, err
		}
		info, err := os.Stat(full)
		if err != nil {
			return 0, err
		}
		fixed := rewrite(string(b), kindOf(p))
		if err := os.WriteFile(full, []byte(fixed), info.Mode()); err != nil {
			return 0, err
		}
	}
	return len(byFile), nil
}

// rewrite replaces em dashes only in the regions the scanner considers
// user-visible, so that a file's comments keep the punctuation they were
// written with.
func rewrite(src string, k kind) string {
	regions := scanSource(src, k)
	if len(regions) == 0 {
		return src
	}

	var b strings.Builder
	prev := 0
	for _, r := range regions {
		b.WriteString(src[prev:r.Start])
		b.WriteString(replaceDashes(src[r.Start:r.End]))
		prev = r.End
	}
	b.WriteString(src[prev:])
	return b.String()
}

// replaceDashes turns an em dash into the punctuation it was standing in for.
//
// A spaced em dash joins two clauses and becomes a spaced hyphen, which reads
// the same. An unspaced one is almost always a range or a compound and becomes
// a bare hyphen. Neither is a substitute for rewording, which is why --fix
// prints a note asking for the diff to be read.
func replaceDashes(s string) string {
	s = strings.ReplaceAll(s, " — ", " - ")
	s = strings.ReplaceAll(s, "—", "-")
	return s
}
