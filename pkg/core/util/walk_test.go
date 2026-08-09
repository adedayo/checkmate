package util

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Reference implementation
// ---------------------------------------------------------------------------

// legacyFindFiles is the pre-Phase-5 FindFiles, preserved verbatim.
//
// FindFiles itself is gone, but its behaviour is still the definition of
// "the files we have always scanned", and that must not change silently. It is
// kept here as executable code rather than described in prose because a
// paraphrase would drift and this cannot.
func legacyFindFiles(paths []string) []RepositoryIndexedFile {
	for i, p := range paths {
		paths[i] = filepath.Clean(p)
	}

	out := []RepositoryIndexedFile{}
	for i, path := range paths {
		var files []string
		_ = filepath.WalkDir(path, func(p string, info os.DirEntry, err error) error {
			if err != nil {
				return filepath.SkipDir
			}
			if !info.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		for _, f := range files {
			out = append(out, RepositoryIndexedFile{RepositoryIndex: i, File: f})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// walkFixture builds a tree that exercises every branch the walker has:
// nesting, lexical ordering that differs from creation order, a prunable
// directory holding files that must not be emitted when pruning is on, an
// empty directory, and a dotfile.
func walkFixture(tb testing.TB) string {
	tb.Helper()

	root := tb.TempDir()
	files := []string{
		"zebra.go",
		"alpha.go",
		"src/main.go",
		"src/nested/deep/util.go",
		"src/nested/other.go",
		".hidden/config.yaml",
		"node_modules/pkg/index.js",
		"node_modules/pkg/sub/more.js",
		"vendor/lib/lib.go",
	}
	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			tb.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte("content of "+f+"\n"), 0o644); err != nil {
			tb.Fatalf("write %s: %v", full, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		tb.Fatalf("mkdir empty: %v", err)
	}
	return root
}

func collect(tb testing.TB, paths []string, opts WalkOptions) ([]RepositoryIndexedFile, WalkStats) {
	tb.Helper()
	return collectCtx(tb, context.Background(), paths, opts)
}

func collectCtx(tb testing.TB, ctx context.Context, paths []string, opts WalkOptions) ([]RepositoryIndexedFile, WalkStats) {
	tb.Helper()

	files, stats := WalkFiles(ctx, paths, opts)

	done := make(chan []RepositoryIndexedFile, 1)
	go func() {
		out := []RepositoryIndexedFile{}
		for f := range files {
			out = append(out, f)
		}
		done <- out
	}()

	var out []RepositoryIndexedFile
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		tb.Fatal("walk did not terminate within 60s")
	}

	//The stats channel is latest-wins and closed after the walk, so draining
	//it here yields the final update.
	var last WalkStats
	for s := range stats {
		last = s
	}
	return out, last
}

func sortedPaths(files []RepositoryIndexedFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, fmt.Sprintf("%d\x00%s", f.RepositoryIndex, f.File))
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// 5.1 — WalkFiles equivalence with the legacy walk
// ---------------------------------------------------------------------------

// TestWalkFilesMatchesLegacyWalk is the equivalence test for this phase
// (task 5.9). With the zero-value options the walker must discover exactly the
// legacy file set — not a superset, not a subset. Anything else is a change in
// what gets scanned, which no performance work is allowed to cause.
func TestWalkFilesMatchesLegacyWalk(t *testing.T) {
	rootA := walkFixture(t)
	rootB := walkFixture(t)
	paths := []string{rootA, rootB}

	want := sortedPaths(legacyFindFiles(append([]string{}, paths...)))
	got, _ := collect(t, append([]string{}, paths...), WalkOptions{})

	if !reflect.DeepEqual(want, sortedPaths(got)) {
		t.Errorf("walk diverged from the legacy walk\nwant %d files:\n%s\ngot %d files:\n%s",
			len(want), strings.Join(want, "\n"),
			len(got), strings.Join(sortedPaths(got), "\n"))
	}
}

// TestCollectFilesOrderIsDeterministic pins the ordering of the materialising
// helper.
//
// Callers index into this result and report positions from it, so if
// concurrency leaked into the returned order they would see results shuffle
// between runs — an intermittent determinism regression of exactly the kind
// Phase 0.7 was spent eliminating. Ten runs, because once would not catch it.
func TestCollectFilesOrderIsDeterministic(t *testing.T) {
	roots := []string{walkFixture(t), walkFixture(t), walkFixture(t)}

	want := legacyFindFiles(append([]string{}, roots...))

	for i := 0; i < 10; i++ {
		got := CollectFiles(context.Background(), append([]string{}, roots...), WalkOptions{})
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("run %d: CollectFiles order differs from the legacy walk\nwant %v\ngot  %v", i, want, got)
		}
	}
}

// TestWalkFilesSingleFileRoot covers a root that is a file rather than a
// directory — the CLI accepts either, and filepath.WalkDir emits the file, so
// the walker must too.
func TestWalkFilesSingleFileRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "creds.yaml")
	if err := os.WriteFile(file, []byte("token: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, stats := collect(t, []string{file}, WalkOptions{})

	if len(got) != 1 || got[0].File != file {
		t.Errorf("want the single file %q, got %v", file, got)
	}
	if stats.DiscoveredSoFar != 1 {
		t.Errorf("want DiscoveredSoFar 1, got %d", stats.DiscoveredSoFar)
	}
}

// TestWalkFilesMissingRootIsSkipped: a root that does not exist must not abort
// the other roots. Multi-repository scans routinely include a clone that
// failed, and losing every other repository's findings because of it would be
// a far worse failure than the missing one.
func TestWalkFilesMissingRootIsSkipped(t *testing.T) {
	good := walkFixture(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	got, _ := collect(t, []string{missing, good}, WalkOptions{})

	if len(got) == 0 {
		t.Fatal("the surviving root produced no files")
	}
	for _, f := range got {
		if f.RepositoryIndex != 1 {
			t.Errorf("file %q attributed to root %d, want 1", f.File, f.RepositoryIndex)
		}
	}
}

// ---------------------------------------------------------------------------
// 5.2 — Pruning before descent
// ---------------------------------------------------------------------------

func TestWalkFilesPrunesBeforeDescent(t *testing.T) {
	root := walkFixture(t)

	got, _ := collect(t, []string{root}, WalkOptions{PruneDirs: DefaultPruneDirs()})

	for _, f := range got {
		rel, _ := filepath.Rel(root, f.File)
		for _, pruned := range []string{"node_modules", "vendor"} {
			if strings.HasPrefix(filepath.ToSlash(rel), pruned+"/") {
				t.Errorf("pruned subtree was walked: %s", rel)
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("pruning removed everything")
	}
}

// TestWalkFilesPruneIsConsultedPerDirectoryNotPerFile is the test that
// distinguishes pruning from filtering.
//
// A predicate applied to files would produce an identical file set while doing
// all the work the prune exists to avoid — it would walk node_modules in full
// and discard the results. Counting the calls is the only way to tell the two
// apart, and the whole value of this task is in that difference.
func TestWalkFilesPruneIsConsultedPerDirectoryNotPerFile(t *testing.T) {
	root := walkFixture(t)

	var mu sync.Mutex
	var seen []string

	opts := WalkOptions{PruneDirs: func(path, name string) bool {
		mu.Lock()
		seen = append(seen, name)
		mu.Unlock()
		return name == "node_modules"
	}}

	got, _ := collect(t, []string{root}, opts)

	for _, name := range seen {
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".go") {
			t.Errorf("prune predicate was consulted for a file (%q); it must only see directories", name)
		}
	}
	//"sub" lives under node_modules/pkg. Seeing it means we descended into a
	//subtree we had already decided to skip.
	for _, name := range seen {
		if name == "pkg" || name == "sub" {
			t.Errorf("descended into the pruned subtree: prune was consulted for %q", name)
		}
	}
	for _, f := range got {
		if strings.Contains(filepath.ToSlash(f.File), "/node_modules/") {
			t.Errorf("pruned file emitted: %s", f.File)
		}
	}
}

// TestWalkFilesPruneReceivesFullPath: the predicate takes both path and name
// so that root-relative rules are expressible. If the path argument were not
// the full path, such a rule would silently never match.
func TestWalkFilesPruneReceivesFullPath(t *testing.T) {
	root := walkFixture(t)

	var mu sync.Mutex
	ok := false

	_, _ = collect(t, []string{root}, WalkOptions{PruneDirs: func(path, name string) bool {
		if name == "src" {
			mu.Lock()
			ok = path == filepath.Join(root, "src")
			mu.Unlock()
		}
		return false
	}})

	if !ok {
		t.Error("prune predicate did not receive the absolute directory path")
	}
}

// ---------------------------------------------------------------------------
// 5.3 / 5.8 — Cycle safety and depth
// ---------------------------------------------------------------------------

// TestWalkFilesTerminatesOnSymlinkLoop is the reason the visited guard exists.
//
// With FollowLinks the loop is unbounded in principle; only the (device,
// inode) guard stops it. The test asserts termination *and* that the looped
// directory's own content is still found — a guard that simply refused to
// follow any link would pass the first half and silently lose files.
func TestWalkFilesTerminatesOnSymlinkLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation typically requires elevation on Windows")
	}

	root := walkFixture(t)
	loop := filepath.Join(root, "loop")
	if err := os.MkdirAll(loop, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loop, "creds.yaml"), []byte("token: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(loop, "back")); err != nil {
		t.Skipf("platform does not support symlinks: %v", err)
	}

	got, stats := collect(t, []string{root}, WalkOptions{FollowLinks: true})

	if !stats.WalkComplete {
		t.Error("walk did not complete")
	}

	found := false
	for _, f := range got {
		if strings.HasSuffix(f.File, filepath.Join("loop", "creds.yaml")) {
			found = true
		}
	}
	if !found {
		t.Error("the looped directory's own content was not discovered; the guard is too aggressive")
	}

	//Every emitted path must be distinct. A cycle that terminated by depth cap
	//alone would still emit the same file many times over, multiplying
	//findings.
	seen := map[string]struct{}{}
	for _, f := range got {
		if _, dup := seen[f.File]; dup {
			t.Errorf("duplicate emission: %s", f.File)
		}
		seen[f.File] = struct{}{}
	}
}

// TestWalkFilesDoesNotFollowLinksByDefault pins the historic behaviour: a
// symlinked directory is emitted as an ordinary entry, exactly as
// filepath.WalkDir does. Changing this would change the scanned file set.
func TestWalkFilesDoesNotFollowLinksByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation typically requires elevation on Windows")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secret.yaml"), []byte("token: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("platform does not support symlinks: %v", err)
	}

	want := sortedPaths(legacyFindFiles([]string{root}))
	got, _ := collect(t, []string{root}, WalkOptions{})

	if !reflect.DeepEqual(want, sortedPaths(got)) {
		t.Errorf("default link handling diverged from filepath.WalkDir\nwant %v\ngot  %v", want, sortedPaths(got))
	}
}

// TestWalkFilesDeepNesting checks that legitimate deep trees are walked in
// full, so the depth backstop cannot be mistaken for a working cycle guard by
// quietly truncating real repositories.
func TestWalkFilesDeepNesting(t *testing.T) {
	root := t.TempDir()

	const depth = 80
	dir := root
	for i := 0; i < depth; i++ {
		dir = filepath.Join(dir, fmt.Sprintf("d%d", i))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("platform rejected a %d-deep path: %v", depth, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deep.yaml"), []byte("token: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, _ := collect(t, []string{root}, WalkOptions{})

	if len(got) != 1 {
		t.Fatalf("want 1 file at depth %d, got %d", depth, len(got))
	}
}

// ---------------------------------------------------------------------------
// 5.4 — Multiple roots
// ---------------------------------------------------------------------------

// TestWalkFilesPreservesRepositoryIndex.
//
// RepositoryIndex is how a finding is attributed back to a repository and how
// its path is transposed for reporting. Concurrent roots make mis-attribution
// possible for the first time, and the failure is quiet: findings appear under
// the wrong repository rather than not at all.
func TestWalkFilesPreservesRepositoryIndex(t *testing.T) {
	roots := []string{walkFixture(t), walkFixture(t), walkFixture(t)}

	got, _ := collect(t, append([]string{}, roots...), WalkOptions{})

	if len(got) == 0 {
		t.Fatal("no files discovered")
	}
	counts := map[int]int{}
	for _, f := range got {
		if f.RepositoryIndex < 0 || f.RepositoryIndex >= len(roots) {
			t.Fatalf("index %d out of range for %q", f.RepositoryIndex, f.File)
		}
		if !strings.HasPrefix(f.File, roots[f.RepositoryIndex]) {
			t.Errorf("file %q attributed to root %d (%q)", f.File, f.RepositoryIndex, roots[f.RepositoryIndex])
		}
		counts[f.RepositoryIndex]++
	}
	for i := range roots {
		if counts[i] == 0 {
			t.Errorf("root %d produced no files", i)
		}
	}
}

// TestWalkFilesIdenticalRootsAreNotDeduplicated.
//
// The visited guard is deliberately per root. Two roots may be the same tree —
// a local path that is also a configured repository — and each must be scanned
// under its own index, because each reports to a different project. A global
// guard would silently drop the second one.
func TestWalkFilesIdenticalRootsAreNotDeduplicated(t *testing.T) {
	root := walkFixture(t)

	got, _ := collect(t, []string{root, root}, WalkOptions{})

	counts := map[int]int{}
	for _, f := range got {
		counts[f.RepositoryIndex]++
	}
	if counts[0] == 0 || counts[0] != counts[1] {
		t.Errorf("identical roots produced %d and %d files; want equal and non-zero", counts[0], counts[1])
	}
}

// ---------------------------------------------------------------------------
// 5.5 — Stats
// ---------------------------------------------------------------------------

func TestWalkStatsFinalCountIsExact(t *testing.T) {
	root := walkFixture(t)

	got, stats := collect(t, []string{root}, WalkOptions{})

	if !stats.WalkComplete {
		t.Error("final stats did not report WalkComplete")
	}
	if stats.DiscoveredSoFar != int64(len(got)) {
		t.Errorf("final DiscoveredSoFar %d, want %d", stats.DiscoveredSoFar, len(got))
	}
}

// TestWalkStatsIgnoredDoesNotBlock is the property that makes the stats
// channel safe to ignore.
//
// A conventional buffered progress channel deadlocks the producer once it
// fills, so every caller would be obliged to drain it. Here the send is
// latest-wins and non-blocking, and this test — with enough files to overrun
// any fixed buffer — is what proves it.
func TestWalkStatsIgnoredDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5_000; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%04d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, _ := WalkFiles(context.Background(), []string{root}, WalkOptions{})

	done := make(chan int, 1)
	go func() {
		n := 0
		for range files {
			n++
		}
		done <- n
	}()

	select {
	case n := <-done:
		if n != 5_000 {
			t.Errorf("want 5000 files, got %d", n)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("walk blocked with the stats channel undrained")
	}
}

// TestWalkStatsLatestWins checks the single-slot channel keeps the newest
// update rather than the oldest. A stale-wins buffer would make progress
// appear to freeze near zero on a long walk.
func TestWalkStatsLatestWins(t *testing.T) {
	stats := make(chan WalkStats, 1)

	publishWalkStats(stats, WalkStats{DiscoveredSoFar: 1})
	publishWalkStats(stats, WalkStats{DiscoveredSoFar: 2})
	publishWalkStats(stats, WalkStats{DiscoveredSoFar: 3, WalkComplete: true})

	got := <-stats
	if got.DiscoveredSoFar != 3 || !got.WalkComplete {
		t.Errorf("want the latest update {3 true}, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// 5.6 — PruneDirs option and environment variable
// ---------------------------------------------------------------------------

func TestDefaultPruneDirsCoversTheDocumentedSet(t *testing.T) {
	prune := DefaultPruneDirs()
	if prune == nil {
		t.Fatal("default pruning is disabled")
	}
	for _, name := range defaultPruneDirNames {
		if !prune("/some/path/"+name, name) {
			t.Errorf("%q is documented as pruned but is not", name)
		}
	}
	for _, name := range []string{"src", "pkg", "lib", "app", "internal"} {
		if prune("/some/path/"+name, name) {
			t.Errorf("%q must not be pruned", name)
		}
	}
}

// TestPruneDirsEnvironmentOverride.
//
// pruneDirNames is resolved once per process, so this exercises the resolution
// directly rather than through the cached accessor — a t.Setenv here would be
// silently ignored if another test had already triggered the OnceValue, and
// the test would pass without testing anything.
func TestPruneDirsEnvironmentOverride(t *testing.T) {
	cases := []struct {
		name     string
		env      string
		set      bool
		want     []string
		disabled bool
	}{
		{name: "default", set: false, want: defaultPruneDirNames},
		{name: "replaces the default set", env: "foo,bar", set: true, want: []string{"foo", "bar"}},
		{name: "tolerates spacing", env: " foo , bar ,", set: true, want: []string{"foo", "bar"}},
		{name: "empty disables pruning", env: "", set: true, disabled: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("CHECKMATE_PRUNE_DIRS", tc.env)
			} else {
				// t.Setenv first so the original value is restored on cleanup,
				// then unset so resolvePruneDirNames sees genuinely-absent
				// rather than empty-string.
				t.Setenv("CHECKMATE_PRUNE_DIRS", "")
				if err := os.Unsetenv("CHECKMATE_PRUNE_DIRS"); err != nil {
					t.Fatalf("unsetenv: %v", err)
				}
			}

			set := resolvePruneDirNames()

			if tc.disabled {
				if len(set) != 0 {
					t.Fatalf("want pruning disabled, got %v", set)
				}
				return
			}
			for _, want := range tc.want {
				if _, ok := set[want]; !ok {
					t.Errorf("missing %q from %v", want, set)
				}
			}
			if len(set) != len(tc.want) {
				t.Errorf("want %d entries, got %d: %v", len(tc.want), len(set), set)
			}
		})
	}
}

// TestPruningDisabledWalksEverything: with CHECKMATE_PRUNE_DIRS="" the escape
// hatch must actually restore the full walk, otherwise it is no escape at all.
func TestPruningDisabledWalksEverything(t *testing.T) {
	t.Setenv("CHECKMATE_PRUNE_DIRS", "")
	if len(resolvePruneDirNames()) != 0 {
		t.Fatal("empty CHECKMATE_PRUNE_DIRS did not disable pruning")
	}

	root := walkFixture(t)
	want := sortedPaths(legacyFindFiles([]string{root}))

	//DefaultPruneDirs returns nil when disabled, which is what the walker
	//treats as "no pruning".
	got, _ := collect(t, []string{root}, WalkOptions{PruneDirs: nil})

	if !reflect.DeepEqual(want, sortedPaths(got)) {
		t.Error("disabling pruning did not restore the full file set")
	}
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

// TestWalkFilesCancellation: cancellation must stop the walk and close the
// channels. Without this, an abandoned scan leaves walker goroutines running
// against the filesystem for as long as the tree takes to traverse.
func TestWalkFilesCancellation(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20_000; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%05d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	files, stats := WalkFiles(ctx, []string{root}, WalkOptions{})

	//Take a few, then abandon.
	for i := 0; i < 10; i++ {
		<-files
	}
	cancel()

	drained := make(chan struct{})
	go func() {
		for range files {
		}
		for range stats {
		}
		close(drained)
	}()

	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatal("walk did not stop after cancellation")
	}
}

// ---------------------------------------------------------------------------
// Cycle guard unit
// ---------------------------------------------------------------------------

// TestFileKeyDistinguishesHardLinkedDirectories checks the guard's two
// required properties directly: the same directory reached by two paths yields
// one key, and two different directories yield two.
//
// If the first failed, symlink loops would not terminate; if the second
// failed, unrelated directories would be silently skipped.
func TestFileKeyIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file identity is reported unavailable on this platform by design")
	}

	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "link-to-a")
	if err := os.Symlink(a, link); err != nil {
		t.Skipf("platform does not support symlinks: %v", err)
	}

	key := func(p string) fileKey {
		info, err := os.Stat(p) //Stat, not Lstat: we want the target's identity
		if err != nil {
			t.Fatal(err)
		}
		k, ok := fileKeyFor(info)
		if !ok {
			t.Skip("file identity unavailable on this platform")
		}
		return k
	}

	if key(a) != key(link) {
		t.Error("the same directory reached via a symlink produced a different key; loops would not terminate")
	}
	if key(a) == key(b) {
		t.Error("distinct directories produced the same key; real directories would be skipped")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func benchTree(tb testing.TB, dirs, filesPerDir int) string {
	tb.Helper()
	root := tb.TempDir()
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, fmt.Sprintf("d%03d", d), "node_modules", "pkg")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			tb.Fatal(err)
		}
		src := filepath.Join(root, fmt.Sprintf("d%03d", d), "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			tb.Fatal(err)
		}
		for f := 0; f < filesPerDir; f++ {
			name := fmt.Sprintf("f%03d.go", f)
			if err := os.WriteFile(filepath.Join(src, name), []byte("package x\n"), 0o644); err != nil {
				tb.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte("module.exports={}\n"), 0o644); err != nil {
				tb.Fatal(err)
			}
		}
	}
	return root
}

func BenchmarkWalkFiles(b *testing.B) {
	root := benchTree(b, 50, 20)

	b.Run("unpruned", func(b *testing.B) {
		for b.Loop() {
			files, _ := WalkFiles(context.Background(), []string{root}, WalkOptions{})
			for range files {
			}
		}
	})

	b.Run("pruned", func(b *testing.B) {
		prune := func(_ string, name string) bool { return name == "node_modules" }
		for b.Loop() {
			files, _ := WalkFiles(context.Background(), []string{root}, WalkOptions{PruneDirs: prune})
			for range files {
			}
		}
	})

	b.Run("legacy", func(b *testing.B) {
		for b.Loop() {
			var n int
			_ = filepath.WalkDir(root, func(_ string, e fs.DirEntry, err error) error {
				if err != nil {
					return filepath.SkipDir
				}
				if !e.IsDir() {
					n++
				}
				return nil
			})
		}
	})
}
