package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The point of this tool is the distinction between text a user reads and text
// a maintainer reads. Almost every test here is about that boundary, because
// getting it wrong in either direction destroys the check: flag comments and
// it becomes noise everyone skips, miss string literals and it reports success
// on a tree full of the thing it exists to find.

func scanString(t *testing.T, src string, k kind) []string {
	t.Helper()
	var found []string
	for _, r := range scanSource(src, k) {
		seg := src[r.Start:r.End]
		for _, off := range dashOffsets(seg) {
			found = append(found, contextAt(src, r.Start+off))
		}
	}
	return found
}

func TestAGoCommentMayUseAnEmDash(t *testing.T) {
	src := "package main\n// This is deliberate prose — it stays.\nfunc f() {}\n"
	if got := scanString(t, src, goSource); len(got) != 0 {
		t.Fatalf("flagged a comment: %v", got)
	}
}

func TestAGoStringLiteralMayNot(t *testing.T) {
	src := "package main\nvar s = \"scan failed — no resolver\"\n"
	got := scanString(t, src, goSource)
	if len(got) != 1 {
		t.Fatalf("want 1 hit, got %d: %v", len(got), got)
	}
}

func TestABlockCommentIsNotMistakenForCode(t *testing.T) {
	// The naive implementation counts quotes and loses its place here, because
	// the comment contains an unbalanced apostrophe.
	src := "package main\n/* the user's report — formatted */\nvar s = \"clean\"\n"
	if got := scanString(t, src, goSource); len(got) != 0 {
		t.Fatalf("flagged inside a block comment: %v", got)
	}
}

func TestACommentContainingAQuoteDoesNotHideALaterString(t *testing.T) {
	src := "package main\n// don't stop scanning here\nvar s = \"report — failed\"\n"
	got := scanString(t, src, goSource)
	if len(got) != 1 {
		t.Fatalf("want 1 hit after a comment with an apostrophe, got %d: %v", len(got), got)
	}
}

func TestAGoRawStringIsUserVisible(t *testing.T) {
	src := "package main\nvar tmpl = `<p>Result — pending</p>`\n"
	if got := scanString(t, src, goSource); len(got) != 1 {
		t.Fatalf("want 1 hit in a raw string, got %d: %v", len(got), got)
	}
}

func TestATypeScriptTemplateLiteralIsUserVisible(t *testing.T) {
	src := "const msg = `assessed — ${n} of ${total}`;\n"
	if got := scanString(t, src, tsSource); len(got) != 1 {
		t.Fatalf("want 1 hit in a template literal, got %d: %v", len(got), got)
	}
}

func TestATypeScriptCommentMayUseAnEmDash(t *testing.T) {
	src := "// four states — none of them a claim\nconst x = 1;\n"
	if got := scanString(t, src, tsSource); len(got) != 0 {
		t.Fatalf("flagged a TS comment: %v", got)
	}
}

func TestAnEscapedQuoteDoesNotEndAString(t *testing.T) {
	src := "package main\nvar s = \"a \\\" quote — inside\"\n"
	if got := scanString(t, src, goSource); len(got) != 1 {
		t.Fatalf("want 1 hit past an escaped quote, got %d: %v", len(got), got)
	}
}

func TestHTMLTextIsUserVisible(t *testing.T) {
	src := "<p>Nothing to report — yet</p>\n"
	if got := scanString(t, src, template); len(got) != 1 {
		t.Fatalf("want 1 hit in template text, got %d: %v", len(got), got)
	}
}

func TestAnHTMLCommentIsNot(t *testing.T) {
	src := "<!-- a note to the next reader — kept -->\n<p>clean</p>\n"
	if got := scanString(t, src, template); len(got) != 0 {
		t.Fatalf("flagged an HTML comment: %v", got)
	}
}

func TestAnAriaLabelIsUserVisible(t *testing.T) {
	// Read aloud rather than read, but read by someone either way.
	src := "<button aria-label=\"Rescan — all domains\"></button>\n"
	if got := scanString(t, src, template); len(got) != 1 {
		t.Fatalf("want 1 hit in an attribute, got %d: %v", len(got), got)
	}
}

func TestMarkdownIsUserVisibleThroughout(t *testing.T) {
	src := "# Title\n\nProse — with a dash.\n"
	if got := scanString(t, src, prose); len(got) != 1 {
		t.Fatalf("want 1 hit in markdown, got %d: %v", len(got), got)
	}
}

func TestContributorDocumentsAreExempt(t *testing.T) {
	for _, name := range []string{"RELEASING.md", "CONTRIBUTING.md", "docs/copilot-instructions.md"} {
		if kindOf(name) != skip {
			t.Errorf("%s should be exempt: it is read by maintainers, who set the style", name)
		}
	}
}

func TestFixturesAreExempt(t *testing.T) {
	// A test asserting a UI string keeps that string honest by failing when it
	// changes. Rewriting the fixture instead would make the assertion pass
	// against a value nobody chose.
	for _, name := range []string{"pkg/core/ingest_test.go", "app/src/app/x.spec.ts"} {
		if kindOf(name) != skip {
			t.Errorf("%s should be exempt: it is a fixture, not user-visible text", name)
		}
	}
}

func TestTheToolExemptsItself(t *testing.T) {
	// Not special pleading: a test proving an em dash in a literal is caught
	// has to contain one.
	if kindOf("cmd/prosecheck/scan_test.go") != skip {
		t.Error("prosecheck would report its own fixtures")
	}
}

func TestSpecificationsAreExempt(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "openspec", "changes", "001-x", "proposal.md"),
		"Deliberate prose — at length.\n")
	mustWrite(t, filepath.Join(dir, "README.md"), "clean\n")

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("scanned openspec, which is internal argument: %v", hits)
	}
}

func TestGeneratedBindingsAreExempt(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "app", "wailsjs", "go", "models.ts"),
		"export const x = \"generated — do not edit\";\n")

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("flagged generated bindings, which cannot be hand-edited: %v", hits)
	}
}

func TestTheReportNamesTheLineAndTheText(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "README.md"), "one\ntwo — three\n")

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].Line != 2 {
		t.Errorf("line = %d, want 2", hits[0].Line)
	}
	if !strings.Contains(hits[0].Context, "two") {
		t.Errorf("context %q does not show the offending text", hits[0].Context)
	}
}

// ── rewriting ────────────────────────────────────────────────────────────────

func TestASpacedDashBecomesASpacedHyphen(t *testing.T) {
	src := "package main\nvar s = \"failed — no resolver\"\n"
	got := rewrite(src, goSource)
	want := "package main\nvar s = \"failed - no resolver\"\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAnUnspacedDashBecomesAHyphen(t *testing.T) {
	src := "<p>2024—2025</p>\n"
	if got := rewrite(src, template); got != "<p>2024-2025</p>\n" {
		t.Errorf("got %q", got)
	}
}

func TestRewritingLeavesCommentsAlone(t *testing.T) {
	// The whole reason --fix works region by region rather than with a global
	// replace. A comment is the author's prose and is not the tool's business.
	src := "package main\n// deliberate — prose\nvar s = \"visible — text\"\n"
	got := rewrite(src, goSource)
	if !strings.Contains(got, "// deliberate — prose") {
		t.Error("rewrote a comment")
	}
	if !strings.Contains(got, "\"visible - text\"") {
		t.Errorf("did not rewrite the string literal: %q", got)
	}
}

func TestRewritingIsIdempotent(t *testing.T) {
	src := "package main\nvar s = \"a — b — c\"\n"
	once := rewrite(src, goSource)
	if twice := rewrite(once, goSource); twice != once {
		t.Errorf("second pass changed the file again: %q then %q", once, twice)
	}
}

func TestACleanFileIsUntouched(t *testing.T) {
	src := "package main\n// nothing here\nvar s = \"clean text\"\n"
	if got := rewrite(src, goSource); got != src {
		t.Errorf("modified a clean file: %q", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
