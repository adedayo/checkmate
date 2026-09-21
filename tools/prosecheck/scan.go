package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const emDash = '\u2014'

// kind is how a file must be read to find the parts a user sees.
type kind int

const (
	skip     kind = iota
	goSource      // string literals only
	tsSource      // string literals, including template literals
	template      // everything outside <!-- --> comments
	prose         // the whole file
)

// region is a span of source that a user will read.
type region struct{ Start, End int }

// hit is one em dash in such a span.
type hit struct {
	Path    string
	Line    int
	Context string
}

// excludedDirs are trees whose contents are not written by hand here, or are
// not read by a user of the product.
//
// openspec is the significant one. Its proposals and specifications are
// internal argument, written for a maintainer arriving in two years; they use
// em dashes deliberately and at length. Rewriting them would produce an
// enormous diff that changes nothing anyone using Trawl will ever see, which
// is the definition of churn.
var excludedDirs = map[string]bool{
	"node_modules": true,
	"dist":         true,
	"vendor":       true,
	".git":         true,
	"openspec":     true,
	"wailsjs":      true, // generated from Go bindings
	"build":        true,
	"coverage":     true,
	".angular":     true,
	".nx":          true,
	"testdata":     true,
}

// excludedFiles are documents written for contributors rather than users.
// A release runbook and a set of agent instructions are read by the people
// maintaining this, who are also the people who chose the house style.
var excludedFiles = map[string]bool{
	"RELEASING.md":            true,
	"CONTRIBUTING.md":         true,
	"CHANGELOG.md":            true,
	"copilot-instructions.md": true,
	"AGENTS.md":               true,
	"CLAUDE.md":               true,
}

func kindOf(path string) kind {
	base := filepath.Base(path)
	if excludedFiles[base] {
		return skip
	}
	// This tool's own source and fixtures necessarily contain the character it
	// looks for. Exempting it is not special pleading: a test that proves an em
	// dash in a string literal is caught has to contain one.
	//
	// Matched by directory name rather than by full path because this tool is
	// copied between repositories, and lives under cmd/ where that is the
	// convention and tools/ where cmd/ is taken by Cobra commands.
	if strings.Contains(filepath.ToSlash(path), "prosecheck/") {
		return skip
	}
	// Test fixtures are not user-visible text. A test that asserts a UI string
	// will still hold the tool honest: change the string and the assertion
	// fails, which is a better signal than this check rewriting a fixture and
	// the assertion passing against a value nobody chose.
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".spec.ts") {
		return skip
	}
	switch filepath.Ext(path) {
	case ".go":
		return goSource
	case ".ts", ".js", ".mts":
		return tsSource
	case ".html":
		return template
	case ".md":
		return prose
	}
	return skip
}

func scanTree(root string) ([]hit, error) {
	var hits []hit

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if excludedDirs[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != "." && d.Name() != ".githooks") {
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		k := kindOf(rel)
		if k == skip {
			return nil
		}

		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(b)
		if !strings.ContainsRune(src, emDash) {
			return nil
		}

		for _, r := range scanSource(src, k) {
			for _, off := range dashOffsets(src[r.Start:r.End]) {
				at := r.Start + off
				hits = append(hits, hit{
					Path:    rel,
					Line:    lineOf(src, at),
					Context: contextAt(src, at),
				})
			}
		}
		return nil
	})

	return hits, err
}

func dashOffsets(s string) []int {
	var out []int
	for i, r := range s {
		if r == emDash {
			out = append(out, i)
		}
	}
	return out
}

func lineOf(src string, at int) int {
	return strings.Count(src[:at], "\n") + 1
}

// contextAt returns the trimmed line the dash sits on, shortened around the
// dash itself so a long line still shows the offending punctuation.
func contextAt(src string, at int) string {
	start := strings.LastIndexByte(src[:at], '\n') + 1
	end := strings.IndexByte(src[at:], '\n')
	if end == -1 {
		end = len(src)
	} else {
		end += at
	}
	line := strings.TrimSpace(src[start:end])

	const max = 100
	if len(line) <= max {
		return line
	}
	rel := at - start
	lo := rel - max/2
	if lo < 0 {
		lo = 0
	}
	hi := lo + max
	if hi > len(line) {
		hi = len(line)
		lo = hi - max
	}
	for lo > 0 && !isBoundary(line[lo]) {
		lo--
	}
	return "..." + strings.TrimSpace(line[lo:hi]) + "..."
}

func isBoundary(b byte) bool { return b == ' ' || b == '\t' }

// scanSource returns the spans of src that a user will read.
func scanSource(src string, k kind) []region {
	switch k {
	case prose:
		return []region{{0, len(src)}}
	case template:
		return outsideHTMLComments(src)
	case goSource:
		return stringLiterals(src)
	case tsSource:
		return stringLiterals(src)
	}
	return nil
}

// outsideHTMLComments returns everything that is not an HTML comment.
//
// Attributes are included deliberately. A placeholder, a title and an
// aria-label are all read by someone, and the last of them is read aloud.
func outsideHTMLComments(src string) []region {
	var out []region
	prev := 0
	for i := 0; i < len(src); {
		if strings.HasPrefix(src[i:], "<!--") {
			if i > prev {
				out = append(out, region{prev, i})
			}
			end := strings.Index(src[i:], "-->")
			if end == -1 {
				return out
			}
			i += end + 3
			prev = i
			continue
		}
		i++
	}
	if prev < len(src) {
		out = append(out, region{prev, len(src)})
	}
	return out
}

// stringLiterals returns the spans inside string literals, skipping comments
// entirely.
//
// This is a scanner rather than a parser because the question is narrow: is
// this character inside quotes or not. It handles the cases that occur in this
// codebase - escapes, raw and template literals, and comments containing
// quotes, which is the case a naive quote-counter gets wrong.
//
// Go and TypeScript need no distinction here. Both delimit strings with single
// and double quotes, both honour a backslash escape inside them, and both use
// backticks for a form that runs to the next backtick regardless: Go's raw
// string and TypeScript's template literal. The two kinds stay separate in
// kindOf because they are selected by file extension, but they scan alike.
func stringLiterals(src string) []region {
	var out []region
	i := 0
	n := len(src)

	for i < n {
		c := src[i]

		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i+1 < n && (src[i] != '*' || src[i+1] != '/') {
				i++
			}
			i += 2

		case c == '"' || c == '\'':
			quote := c
			i++
			start := i
			for i < n {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == quote || src[i] == '\n' {
					break
				}
				i++
			}
			if i > start {
				out = append(out, region{start, min(i, n)})
			}
			i++

		case c == '`':
			// Raw strings in Go and template literals in TypeScript. Both run
			// to the next backtick; neither honours a backslash escape.
			i++
			start := i
			for i < n && src[i] != '`' {
				i++
			}
			if i > start {
				out = append(out, region{start, min(i, n)})
			}
			i++

		default:
			i++
		}
	}

	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
