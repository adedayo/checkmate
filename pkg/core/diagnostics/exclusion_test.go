package diagnostics

// Phase 6 — exclusion acceleration and directory pruning guards.
//
// Two changes are under test here, and they fail in opposite ways:
//
//   - The combined alternation is a pure performance change. If it is wrong it
//     changes which files are excluded, in either direction, silently.
//   - Directory pruning removes files from the scan outright. If it is wrong it
//     removes real findings, silently. Only unsoundness matters; refusing to
//     prune is always safe.

import (
	"math/rand"
	"strings"
	"testing"
)

// exclusionFixturePatterns exercise every shape the accelerators must handle,
// including two that must NOT produce a directory pruner.
func exclusionFixturePatterns() []string {
	return []string{
		`.*/(package-lock|npm-shrinkwrap|composer)[.]json`, //the shipped default
		`.*[.](html?|s?css|sass|less)`,                     //the shipped default
		`.*/node_modules/.*`,                               //prunable
		`.*/vendor/.*$`,                                    //prunable, anchored
		`.*/generated/[^/]*[.]go`,                          //not prunable: names a file shape
		`.*/build`,                                         //not prunable: says nothing about descendants
		`^/abs/only/.*`,                                    //prunable, anchored at the front
		`a|b/.*`,                                           //top-level alternation: must not leak into the combination
	}
}

func exclusionFixturePaths() []string {
	return []string{
		"", "/", "a", "a/b", "/x/package-lock.json", "/x/npm-shrinkwrap.json",
		"/x/composer.json", "/x/composer.jsonx", "/x/index.html", "/x/index.htm",
		"/x/site.scss", "/x/site.css", "/x/site.sass", "/x/site.less",
		"/x/node_modules/pkg/index.js", "/x/node_modules", "/x/vendor/lib/a.go",
		"/x/vendor", "/x/generated/api.go", "/x/generated/api.ts", "/x/build",
		"/x/build/app.js", "/abs/only/a", "/other/abs/only/a", "b/c", "a",
		"/x/HTML/notes.txt", "/x/a.HTML", "weird\npath/index.html",
		"/x/.hidden/index.html", "/deep/" + strings.Repeat("d/", 40) + "a.css",
	}
}

func fixtureProvider(t *testing.T) *defaultExclusionProvider {
	t.Helper()
	p, err := CompileExcludes(ExcludeContainer{
		ExcludeDef: &ExcludeDefinition{PathExclusionRegExs: exclusionFixturePatterns()},
	})
	if err != nil {
		t.Fatalf("compiling fixture exclusions: %v", err)
	}
	return p.(*defaultExclusionProvider)
}

// TestExclusionEquivalence asserts the combined alternation agrees with the
// per-pattern loop it replaced, on every fixture path and on random ones.
//
// The loop is kept in the provider as the fallback for a combination that
// fails to compile, so this compares against the real previous implementation
// rather than a paraphrase of it, and cannot rot.
func TestExclusionEquivalence(t *testing.T) {
	wl := fixtureProvider(t)

	if wl.pathExclusionCombined == nil {
		t.Fatal("no combined path exclusion regex was built; the comparison would be vacuous")
	}

	loop := func(p string) bool {
		for _, prx := range wl.pathExclusionRegExsCompiled {
			if prx.MatchString(p) {
				return true
			}
		}
		return false
	}

	paths := exclusionFixturePaths()
	paths = append(paths, randomPaths(4096)...)

	excluded := 0
	for _, p := range paths {
		want := loop(p)
		if got := wl.ShouldExcludePath(p); got != want {
			t.Fatalf("ShouldExcludePath(%q) = %v, per-pattern loop says %v", p, got, want)
		}
		if want {
			excluded++
		}
	}

	//A combination that matched nothing would agree with a loop that also
	//matched nothing, and prove nothing.
	if excluded == 0 {
		t.Fatal("no fixture path was excluded; the equivalence assertion is vacuous")
	}
}

// TestCombinedExclusionIsolatesAlternation pins the one way combining patterns
// can change their meaning: a pattern containing a top-level `|` would, if
// concatenated raw, bind its alternatives to the neighbouring patterns instead
// of to itself. Each member is therefore wrapped in a non-capturing group.
func TestCombinedExclusionIsolatesAlternation(t *testing.T) {
	p, err := CompileExcludes(ExcludeContainer{
		ExcludeDef: &ExcludeDefinition{PathExclusionRegExs: []string{`^x|y$`, `^z$`}},
	})
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}

	for _, c := range []struct {
		path string
		want bool
	}{
		{"x", true}, {"y", true}, {"z", true}, {"q", false}, {"xq", true}, {"qz", false},
	} {
		if got := p.ShouldExcludePath(c.path); got != c.want {
			t.Errorf("ShouldExcludePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestDirectoryPruneIsSound is the important one.
//
// Pruning asserts "every file beneath this directory is excluded". This checks
// that claim directly: for every directory the pruner accepts, a range of
// synthesised descendants must all be excluded by the ordinary per-file
// exclusion check. A single counter-example is a silently lost finding.
func TestDirectoryPruneIsSound(t *testing.T) {
	wl := fixtureProvider(t)

	if !wl.HasPrunableDirectories() {
		t.Fatal("no prunable patterns in the fixture set; the assertion would be vacuous")
	}

	descendants := []string{
		"a.go", "a.txt", "sub/a.go", "sub/deep/er/a.bin", ".npmrc",
		strings.Repeat("x/", 20) + "a", "name with spaces.txt",
	}

	dirs := append([]string{
		"/x/node_modules", "/x/vendor", "/abs/only", "/x/build", "/x/generated",
		"/a/b/node_modules", "/node_modules",
	}, randomPaths(2048)...)

	pruned := 0
	for _, dir := range dirs {
		if !wl.ShouldPruneDirectory(dir) {
			continue
		}
		pruned++
		for _, d := range descendants {
			//Concatenated, not path.Join'd: the claim being tested is about
			//the literal string the walker builds by appending entry names to
			//the directory it is descending, and Join would clean away the
			//very shapes (".." segments, doubled separators) most likely to
			//break the implication.
			file := dir + "/" + d
			if !wl.ShouldExcludePath(file) {
				t.Fatalf("pruned directory %q but its descendant %q is NOT excluded: "+
					"pruning would silently drop it from the scan", dir, file)
			}
		}
	}

	if pruned == 0 {
		t.Fatal("nothing was pruned; the soundness assertion is vacuous")
	}
}

// TestDirectoryPruneRefusesUnprovablePatterns pins the fail-closed direction.
//
// `.*/build` matches the directory /x/build but says nothing whatever about
// /x/build/app.js — a bundled API key being among the most common true
// positives there is. A pattern naming a file shape is likewise no basis for
// skipping the directory that contains it.
func TestDirectoryPruneRefusesUnprovablePatterns(t *testing.T) {
	for _, pattern := range []string{
		`.*/build`,                 //directory named, descendants not implied
		`.*/generated/[^/]*[.]go`,  //names a file shape
		`.*[.](html?|s?css)`,       //extension rule
		`/.*`,                      //empty prefix: would prune the root
		`.*/node_modules/.*[.]js$`, //tail is not `/.*`
	} {
		if _, ok := directoryPrunePattern(pattern); ok {
			t.Errorf("pattern %q produced a directory pruner; it must not, "+
				"since matching a directory does not imply matching its files", pattern)
		}
	}
}

// TestDirectoryPruneAcceptsProvablePatterns is the complementary direction:
// fail-closed is only useful if it still says yes to the shape that matters.
func TestDirectoryPruneAcceptsProvablePatterns(t *testing.T) {
	for _, pattern := range []string{
		`.*/node_modules/.*`,
		`.*/vendor/.*$`,
		`^/abs/only/.*`,
	} {
		if _, ok := directoryPrunePattern(pattern); !ok {
			t.Errorf("pattern %q produced no directory pruner, but every file beneath "+
				"a matching directory is provably excluded", pattern)
		}
	}
}

// TestEmptyExclusionsPruneNothing guards the default posture: a project with no
// path exclusions must walk everything.
func TestEmptyExclusionsPruneNothing(t *testing.T) {
	wl := MakeEmptyExcludes().(*defaultExclusionProvider)

	if wl.HasPrunableDirectories() {
		t.Error("empty exclusions reported prunable directories")
	}
	if wl.ShouldPruneDirectory("/anything") {
		t.Error("empty exclusions pruned a directory")
	}
	if wl.ShouldExcludePath("/anything") {
		t.Error("empty exclusions excluded a path")
	}
}

// TestDefaultExclusionPrunesNothing records a fact worth keeping visible: the
// shipped default policy excludes dependency-pinning JSON and stylesheets, and
// neither can prune a subtree. Pruning is therefore inert out of the box — it
// only ever helps operators who have written directory-scoped exclusions of
// their own. See Phase 5.10 for why we will not add a built-in prune list.
func TestDefaultExclusionPrunesNothing(t *testing.T) {
	p, err := CompileExcludes(ExcludeContainer{ExcludeDef: &ExcludeDefinition{
		PathExclusionRegExs: DefaultExclusion().PathExclusionRegExs,
	}})
	if err != nil {
		t.Fatalf("compiling default exclusions: %v", err)
	}

	if p.(*defaultExclusionProvider).HasPrunableDirectories() {
		t.Error("the default exclusion policy now prunes directories; " +
			"that is a reduction in what gets scanned and needs to be a deliberate decision")
	}
}

// randomPaths generates path-shaped strings, including some that will match the
// fixture patterns by chance and some that will not.
func randomPaths(n int) []string {
	rng := rand.New(rand.NewSource(20260807))
	segments := []string{
		"node_modules", "vendor", "build", "generated", "src", "pkg", "abs",
		"only", "a", "b", "x", "package-lock.json", "index.html", "site.scss",
		"main.go", "..", ".", "", "no de", "UPPER", "тест",
	}

	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		depth := rng.Intn(6)
		parts := make([]string, 0, depth+1)
		if rng.Intn(2) == 0 {
			parts = append(parts, "")
		}
		for j := 0; j <= depth; j++ {
			parts = append(parts, segments[rng.Intn(len(segments))])
		}
		out = append(out, strings.Join(parts, "/"))
	}
	return out
}

// BenchmarkShouldExcludePath keeps both arms so the combined-alternation gain
// can be reproduced. The loop arm is the previous implementation, still live
// as the fallback when the combination fails to compile.
func BenchmarkShouldExcludePath(b *testing.B) {
	p, err := CompileExcludes(ExcludeContainer{
		ExcludeDef: &ExcludeDefinition{PathExclusionRegExs: exclusionFixturePatterns()},
	})
	if err != nil {
		b.Fatalf("compiling: %v", err)
	}
	wl := p.(*defaultExclusionProvider)

	const path = "/home/user/projects/service/src/main/java/com/example/PaymentService.java"

	b.Run("combined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = wl.ShouldExcludePath(path)
		}
	})

	b.Run("loop", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			matched := false
			for _, prx := range wl.pathExclusionRegExsCompiled {
				if prx.MatchString(path) {
					matched = true
					break
				}
			}
			_ = matched
		}
	})
}
