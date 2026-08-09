package secrets

// Phase 9 tests: repository acquisition is concurrent and pipelined, and the
// RepositoryIndex a finding carries does not depend on which clone finished
// first.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// TestResolveCloneConcurrencyPrecedence pins option > environment > default.
//
// As with the worker count, an unusable environment value must fall through to
// the default rather than reach the semaphore: a literal zero there is a
// buffered channel of size zero, which serialises every clone — the exact
// behaviour this phase exists to remove, and silently.
func TestResolveCloneConcurrencyPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		option  int
		env     string
		hasEnv  bool
		expects int
	}{
		{name: "default", expects: defaultCloneConcurrency},
		{name: "option wins", option: 9, env: "3", hasEnv: true, expects: 9},
		{name: "environment", env: "16", hasEnv: true, expects: 16},
		{name: "whitespace tolerated", env: " 7 ", hasEnv: true, expects: 7},
		{name: "zero ignored", env: "0", hasEnv: true, expects: defaultCloneConcurrency},
		{name: "negative ignored", env: "-2", hasEnv: true, expects: defaultCloneConcurrency},
		{name: "garbage ignored", env: "lots", hasEnv: true, expects: defaultCloneConcurrency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hasEnv {
				t.Setenv("CHECKMATE_CLONE_CONCURRENCY", tc.env)
			}
			got := resolveCloneConcurrency(SecretSearchOptions{CloneConcurrency: tc.option})
			if got != tc.expects {
				t.Errorf("concurrency = %d, want %d", got, tc.expects)
			}
		})
	}
}

// TestTransposeIsIndependentOfAcquisitionOrder is the guard on the correctness
// half of this phase.
//
// Filling the registry in reverse is a stand-in for the second repository
// cloning before the first, which is entirely ordinary — clone time is network
// weather. If indices were handed out on completion the findings below would
// be attributed to each other's repositories, and nothing in the scan output
// would reveal it: both results look perfectly plausible.
func TestTransposeIsIndependentOfAcquisitionOrder(t *testing.T) {
	transposeAll := func(fill func(*rootRegistry)) []string {
		registry := newRootRegistry(2)
		fill(registry)
		out := []string{}
		for _, f := range []util.RepositoryIndexedFile{
			{RepositoryIndex: 0, File: "/tmp/a/src/app.go"},
			{RepositoryIndex: 1, File: "/tmp/b/src/app.go"},
		} {
			location, branch, _ := registry.transpose(f)
			out = append(out, location+"@"+branch)
		}
		return out
	}

	main, dev := "main", "dev"
	first := func(r *rootRegistry) {
		r.set(0, repoCloneAndDetail{CloneDetail: gitutils.CloneDetail{
			Location: "/tmp/a", Repository: "https://git.example/a.git", Branch: &main}})
	}
	second := func(r *rootRegistry) {
		r.set(1, repoCloneAndDetail{CloneDetail: gitutils.CloneDetail{
			Location: "/tmp/b", Repository: "https://git.example/b.git", Branch: &dev}})
	}

	inOrder := transposeAll(func(r *rootRegistry) { first(r); second(r) })
	reversed := transposeAll(func(r *rootRegistry) { second(r); first(r) })

	if len(inOrder) != 2 {
		t.Fatalf("unexpected result count %d", len(inOrder))
	}
	if inOrder[0] != "https://git.example/a.git/src/app.go@main" {
		t.Errorf("transposed to %q", inOrder[0])
	}
	if inOrder[1] != "https://git.example/b.git/src/app.go@dev" {
		t.Errorf("transposed to %q", inOrder[1])
	}
	for i := range inOrder {
		if inOrder[i] != reversed[i] {
			t.Errorf("acquisition order changed the result: %q vs %q", inOrder[i], reversed[i])
		}
	}
}

// TestTransposeOfUnknownIndexPassesThrough. A repository whose clone failed
// leaves an empty slot. Its files are never scanned, but a defensive lookup
// must return the path unchanged rather than panic or blank it out.
func TestTransposeOfUnknownIndexPassesThrough(t *testing.T) {
	registry := newRootRegistry(1)
	for _, index := range []int{0, 5, -1} {
		location, branch, detail := registry.transpose(
			util.RepositoryIndexedFile{RepositoryIndex: index, File: "/x/y.go"})
		if location != "/x/y.go" || branch != "" || detail != nil {
			t.Errorf("index %d: got (%q, %q, %v)", index, location, branch, detail)
		}
	}
}

// TestAcquirePathsPreservesArgumentOrder.
//
// The indices must come from the caller's argument order. Previously they came
// from the position of each path in a *filtered* list of local paths, with
// cloned repositories appended in map-iteration order — while the walk roots
// were built from a second, independently randomised iteration of the same
// map. When those two disagreed, findings were transposed against the wrong
// repository.
func TestAcquirePathsPreservesArgumentOrder(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	//A git URL between the two local paths. The context is already cancelled,
	//so the clone fails immediately and nothing touches the network — what is
	//under test is that its failure does not shift the index of the local path
	//that follows it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	paths := []string{a, "https://127.0.0.1:1/unreachable.git", b}
	registry, roots := acquirePaths(ctx, paths, SecretSearchOptions{})

	got := map[int]string{}
	for root := range roots {
		got[root.Index] = root.Path
	}

	if got[0] != a {
		t.Errorf("root 0 = %q, want %q", got[0], a)
	}
	if got[2] != b {
		t.Errorf("root 2 = %q, want %q; a failed clone displaced a local path", got[2], b)
	}
	if _, present := got[1]; present {
		t.Errorf("unreachable repository published a root: %q", got[1])
	}

	//Local roots are the user's own directories and must never appear in the
	//delete-after-scan list.
	if locations := registry.cloneLocations(); len(locations) != 0 {
		t.Errorf("local paths listed as deletable checkouts: %v", locations)
	}
}

// TestAcquirePathsDeduplicatesRepositories preserves the long-standing
// behaviour that the same URL listed twice is cloned once.
func TestAcquirePathsDeduplicatesRepositories(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	local := t.TempDir()
	url := "https://127.0.0.1:1/same.git"
	_, roots := acquirePaths(ctx, []string{url, local, url}, SecretSearchOptions{})

	count := 0
	for range roots {
		count++
	}
	if count != 1 {
		t.Errorf("published %d roots, want 1 (the local path only)", count)
	}
}

// TestLocalRootsAreScannableBeforeCloningFinishes is the pipelining guarantee.
//
// Acquisition used to return only when the last repository had been cloned, so
// a scan of one local directory alongside one slow repository read nothing at
// all until the network was done. Here the local root must be readable off the
// channel while the (never-completing) clone is still outstanding.
func TestLocalRootsAreScannableBeforeCloningFinishes(t *testing.T) {
	local := t.TempDir()

	//A context that is never cancelled and an unroutable address: the clone
	//will still be in flight when the assertion runs, which is the point.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, roots := acquirePaths(ctx, []string{local, "https://192.0.2.1:9418/slow.git"},
		SecretSearchOptions{})

	select {
	case root := <-roots:
		if root.Path != local || root.Index != 0 {
			t.Fatalf("first root = %+v, want index 0 at %q", root, local)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local root was withheld until cloning completed")
	}
}

// TestWalkRootsScansRootsAsTheyArrive covers the walker half of the pipeline:
// files must come out of a root that has been published without waiting for
// the root channel to close.
func TestWalkRootsScansRootsAsTheyArrive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "first.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots := make(chan util.IndexedRoot)
	files, _ := util.WalkRoots(context.Background(), roots, util.WalkOptions{})

	//Published, but the channel is deliberately left open — as it is while
	//other repositories are still cloning.
	roots <- util.IndexedRoot{Index: 3, Path: dir}

	select {
	case f := <-files:
		if f.RepositoryIndex != 3 {
			t.Errorf("RepositoryIndex = %d, want the index supplied with the root", f.RepositoryIndex)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no files emitted while the root channel was still open")
	}

	close(roots)
	for range files {
	}
}

// TestWalkRootsSurvivesCancellationMidFlight.
//
// The walk closes its output channel when it is done, and on cancellation it
// returns from the middle of the dispatch loop with walkers still running —
// walkers that send on that channel. Closing underneath them turns a cancelled
// scan into a panic, and only sometimes, which is the worst version of it.
func TestWalkRootsSurvivesCancellationMidFlight(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 200; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%03d.txt", i)),
			[]byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	roots := make(chan util.IndexedRoot, 64)
	for i := 0; i < 64; i++ {
		roots <- util.IndexedRoot{Index: i, Path: dir}
	}
	close(roots)

	files, stats := util.WalkRoots(ctx, roots, util.WalkOptions{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := 0
		for range files {
			n++
			if n == 5 {
				cancel()
			}
		}
		for range stats {
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("walk did not terminate after cancellation")
	}
}
