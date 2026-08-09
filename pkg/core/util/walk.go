package util

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// maxWalkDepth bounds directory recursion.
//
// It is a backstop, not the primary cycle defence — that is the
// (device, inode) guard below. It exists because the guard is only as strong
// as the platform's file identity support: where identity is unavailable the
// depth cap is all that stands between a symlink loop and an unbounded walk.
// 512 is far beyond any real repository (the deepest fixture in the reference
// corpus is 80) and well inside every platform's path-length limit, so it can
// only ever fire on pathological input.
const maxWalkDepth = 512

// walkStatsInterval is how many discovered files pass between progress
// updates. Stats are latest-wins on a single-slot channel, so this only
// controls how often we attempt a send, not how much memory is retained.
const walkStatsInterval = 512

// WalkStats reports walk progress.
//
// The walk streams, so the total file count is not known until it finishes.
// DiscoveredSoFar is therefore a running count that becomes exact exactly when
// WalkComplete is true. Callers driving a progress bar should treat it as a
// moving denominator rather than a fixed one.
type WalkStats struct {
	//DiscoveredSoFar is the number of files emitted so far across all roots.
	DiscoveredSoFar int64
	//WalkComplete is true only on the final update, at which point
	//DiscoveredSoFar is the exact total.
	WalkComplete bool
}

// WalkOptions configures WalkFiles.
//
// The zero value discovers exactly the set of files the engine has always
// scanned: no pruning, no symlink following. Pruning is opt-in because it
// trades coverage for speed — see defaultPruneDirNames.
type WalkOptions struct {
	//PruneDirs is consulted BEFORE descending into a directory. Returning true
	//skips the entire subtree, so the cost of an excluded tree is one call and
	//not one call per contained file.
	//
	//It receives the full path and the base name; name alone covers the common
	//"never enter node_modules" case, while path allows root-relative rules.
	//
	//Pruning removes files from the scan outright. It is not a performance-only
	//knob: a pruned subtree is one that will not be searched for secrets.
	PruneDirs func(path string, name string) bool

	//FollowLinks makes the walker descend into symlinked directories. When
	//false (the default, and the historic behaviour) a symlink to a directory
	//is emitted as an ordinary file entry, exactly as filepath.WalkDir does.
	FollowLinks bool

	//Concurrency bounds how many roots are walked at once. Defaults to
	//GOMAXPROCS. Per-root parallelism matters for multi-repository scans: a
	//slow network mount should not hold up a local checkout.
	Concurrency int
}

// defaultPruneDirNames are the directories DefaultPruneDirs skips.
//
// # This set is opt-in, and deliberately not the default
//
// The obvious argument for pruning these by default is that they are
// machine-generated and already excluded. The second half of that is simply
// untrue here: DefaultExclusion() excludes dependency-pinning JSON and
// web/stylesheet extensions, and nothing else. None of the directories below
// is excluded today, so all of them are scanned today.
//
// Pruning them by default would therefore stop finding real secrets, silently:
// an .npmrc auth token under node_modules, credentials in vendored config, an
// API key baked into dist/bundle.js — which is one of the most common genuine
// findings there is — or a remote URL of the form
// https://user:token@host in .git/config.
//
// So this is a speed/coverage trade the operator makes explicitly, via
// WalkOptions.PruneDirs or CHECKMATE_PRUNE_DIRS, and never one we make for
// them. It is worth roughly 2× on a dependency-heavy tree.
//
// (Note that pruning .git affects *filesystem* scanning only; git history
// scanning is a separate concern driven by the git service layer. But .git
// also holds config, which is a legitimate place to find a credential, so it
// is not a free prune either.)
var defaultPruneDirNames = []string{
	".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
	"__pycache__", "target", "build", "dist", ".gradle", ".terraform",
	".next", ".nuxt", ".cache", ".idea", ".vscode",
}

// pruneDirNames resolves the effective prune set once per process.
//
// The resolution itself lives in resolvePruneDirNames so it can be tested
// directly. Caching it behind OnceValue would otherwise make the environment
// variable untestable — whichever test ran first would fix the value for the
// whole process, and later assertions would pass without exercising anything.
var pruneDirNames = sync.OnceValue(resolvePruneDirNames)

// resolvePruneDirNames reads CHECKMATE_PRUNE_DIRS.
//
// When set, its comma-separated entries *replace* the default set rather than
// adding to it, so an operator can express "prune only these". Setting it to
// the empty string disables pruning altogether, which is the escape hatch for
// anyone who genuinely needs to scan inside vendored code.
func resolvePruneDirNames() map[string]struct{} {
	names := defaultPruneDirNames
	if v, ok := os.LookupEnv("CHECKMATE_PRUNE_DIRS"); ok {
		names = nil
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// PruneDirNames returns the effective prune set, honouring
// CHECKMATE_PRUNE_DIRS. Exposed for diagnostics and tests.
func PruneDirNames() []string {
	set := pruneDirNames()
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// DefaultPruneDirs returns the opt-in pruning predicate over
// defaultPruneDirNames, honouring CHECKMATE_PRUNE_DIRS, or nil when pruning
// has been disabled by setting that variable empty.
//
// Read defaultPruneDirNames before using this: it removes files from the scan,
// and some of what it removes contains real secrets.
//
// Returning nil rather than a predicate that always says false keeps the
// disabled case free: WalkFiles skips the call entirely.
func DefaultPruneDirs() func(path string, name string) bool {
	set := pruneDirNames()
	if len(set) == 0 {
		return nil
	}
	return func(_ string, name string) bool {
		_, pruned := set[name]
		return pruned
	}
}

// WalkFiles streams the files under each of paths, tagging every file with the
// index of the root it was found under.
//
// It replaces the removed FindFiles' materialise-everything-then-return model.
// On a large estate that slice was hundreds of megabytes that had to be
// complete before the first byte was scanned; here the first file is available
// immediately and memory is bounded by the channel.
//
// The returned channels are both closed when the walk finishes. Callers must
// drain the files channel — abandoning it leaks the walker goroutines until
// ctx is cancelled. The stats channel is single-slot and latest-wins, so it is
// safe to ignore, and safe to read only at the end: the final update is
// retained in the buffer after close.
//
// Per-root file ordering is lexical and depth first, matching filepath.WalkDir.
// Order *between* roots is not defined, because roots are walked concurrently.
func WalkFiles(ctx context.Context, paths []string, opts WalkOptions) (<-chan RepositoryIndexedFile, <-chan WalkStats) {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.GOMAXPROCS(0)
	}
	if concurrency > len(paths) {
		concurrency = len(paths)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	//The whole root set is known, so it is delivered on a buffered channel
	//that never blocks and is closed immediately. WalkRoots then behaves
	//exactly as this function always did.
	roots := make(chan IndexedRoot, len(paths))
	for i, p := range paths {
		roots <- IndexedRoot{Index: i, Path: p}
	}
	close(roots)

	return walkRoots(ctx, roots, opts, concurrency)
}

// IndexedRoot is one scan root together with the RepositoryIndex every file
// discovered beneath it will carry.
//
// The index is supplied by the caller rather than derived from arrival order
// because the callers that need a streaming walk are precisely the ones whose
// roots arrive out of order: repositories are pipelined into the scan as each
// clone completes, and a fast local checkout must not take the index of a slow
// remote one. Findings are mapped back to their repository through this index,
// so an index that depended on clone timing would attribute findings to the
// wrong repository from one run to the next.
type IndexedRoot struct {
	Index int
	Path  string
}

// WalkRoots is WalkFiles over a stream of roots, for callers that can begin
// scanning one root before the next is available.
//
// The walk finishes when roots is closed and every root has been walked, so a
// caller that never closes the channel will hang until ctx is cancelled.
// Concurrency defaults to GOMAXPROCS; unlike WalkFiles it cannot be clamped to
// the number of roots, since that number is not known in advance.
func WalkRoots(ctx context.Context, roots <-chan IndexedRoot, opts WalkOptions) (<-chan RepositoryIndexedFile, <-chan WalkStats) {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.GOMAXPROCS(0)
	}
	return walkRoots(ctx, roots, opts, concurrency)
}

func walkRoots(ctx context.Context, roots <-chan IndexedRoot, opts WalkOptions, concurrency int) (<-chan RepositoryIndexedFile, <-chan WalkStats) {
	files := make(chan RepositoryIndexedFile, 1024)
	//single slot: progress is latest-wins, so an update we could not deliver
	//is one a newer update supersedes. This is what makes stats non-blocking
	//and therefore safe to ignore.
	stats := make(chan WalkStats, 1)

	if concurrency < 1 {
		concurrency = 1
	}

	go func() {
		var discovered atomic.Int64
		var wg sync.WaitGroup

		defer func() {
			//Wait before closing: on cancellation we return from the middle of
			//the loop with walkers still in flight, and those walkers send on
			//`files`. Closing underneath them would turn a cancelled scan into
			//a panic on a closed channel — and only sometimes, which is worse.
			wg.Wait()
			close(files)
			publishWalkStats(stats, WalkStats{
				DiscoveredSoFar: discovered.Load(),
				WalkComplete:    true,
			})
			close(stats)
		}()

		sem := make(chan struct{}, concurrency)

		for root := range roots {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(index int, root string) {
				defer wg.Done()
				defer func() { <-sem }()

				w := &walker{
					ctx:        ctx,
					opts:       opts,
					index:      index,
					out:        files,
					stats:      stats,
					discovered: &discovered,
					//The visited set is per root, not global. Two roots may
					//legitimately be the same tree (a local path also listed
					//as a repository, say), and each must keep its own
					//RepositoryIndex — deduplicating across roots would drop
					//one repository's findings entirely.
					visited: make(map[fileKey]struct{}),
				}
				w.walkRoot(filepath.Clean(root))
			}(root.Index, root.Path)
		}
	}()

	return files, stats
}

type walker struct {
	ctx        context.Context
	opts       WalkOptions
	index      int
	out        chan<- RepositoryIndexedFile
	stats      chan WalkStats
	discovered *atomic.Int64
	visited    map[fileKey]struct{}
}

func (w *walker) walkRoot(root string) {
	info, err := os.Lstat(root)
	if err != nil {
		//Matches the historic behaviour: an unreadable root contributes
		//nothing and does not abort the scan of the other roots.
		return
	}

	if info.Mode()&os.ModeSymlink != 0 {
		//A root given as a symlink is what the user asked us to scan, so
		//resolve it even when FollowLinks is off. This differs from a symlink
		//*encountered during* the walk, which we do not follow by default.
		if resolved, err := os.Stat(root); err == nil {
			info = resolved
		}
	}

	if !info.IsDir() {
		w.emit(root)
		return
	}

	w.markVisited(info)
	w.walkDir(root, 0)
}

// walkDir mirrors filepath.WalkDir's traversal exactly — os.ReadDir returns
// entries sorted by name, and directories are descended into as they are
// encountered — so the emitted order per root is unchanged from FindFiles.
func (w *walker) walkDir(dir string, depth int) {
	if depth >= maxWalkDepth {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		//Equivalent to the SkipDir the old getFiles returned on error: the
		//unreadable directory is skipped, its siblings are not.
		return
	}

	for _, entry := range entries {
		if w.ctx.Err() != nil {
			return
		}

		path := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			w.descend(path, entry.Name(), depth)
			continue
		}

		if entry.Type()&os.ModeSymlink != 0 && w.opts.FollowLinks {
			target, err := os.Stat(path)
			if err != nil {
				//A dangling symlink. Emitting it would make the scanner open a
				//file that is not there; WalkDir would have reported it as a
				//non-directory entry, which is what emit does, so keep that.
				w.emit(path)
				continue
			}
			if target.IsDir() {
				w.descendResolved(path, entry.Name(), target, depth)
				continue
			}
		}

		w.emit(path)
	}
}

func (w *walker) descend(path, name string, depth int) {
	if w.pruned(path, name) {
		return
	}

	//A ReadDir entry reporting IsDir is a real directory, never a symlink —
	//the type comes from the directory entry itself, not from resolution. So
	//when we are not following links there is no route back to an ancestor and
	//no cycle to guard against, and the identity Stat would be a syscall per
	//directory spent on an impossibility. Measured at ~25% of total walk time.
	//
	//The guard is applied on exactly the path where a cycle can arise: a
	//followed symlink. See descendResolved.
	if !w.opts.FollowLinks {
		w.walkDir(path, depth+1)
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}
	w.descendResolved(path, name, info, depth)
}

func (w *walker) descendResolved(path, name string, info os.FileInfo, depth int) {
	if w.pruned(path, name) {
		return
	}
	if w.seen(info) {
		//Either a symlink loop or a subtree reachable by two routes. Both mean
		//re-walking would produce duplicate findings at best and never
		//terminate at worst.
		return
	}
	w.markVisited(info)
	w.walkDir(path, depth+1)
}

func (w *walker) pruned(path, name string) bool {
	return w.opts.PruneDirs != nil && w.opts.PruneDirs(path, name)
}

func (w *walker) seen(info fs.FileInfo) bool {
	key, ok := fileKeyFor(info)
	if !ok {
		return false
	}
	_, visited := w.visited[key]
	return visited
}

func (w *walker) markVisited(info fs.FileInfo) {
	if key, ok := fileKeyFor(info); ok {
		w.visited[key] = struct{}{}
	}
}

func (w *walker) emit(path string) {
	select {
	case <-w.ctx.Done():
	case w.out <- RepositoryIndexedFile{RepositoryIndex: w.index, File: path}:
		if n := w.discovered.Add(1); n%walkStatsInterval == 0 {
			publishWalkStats(w.stats, WalkStats{DiscoveredSoFar: n})
		}
	}
}

// publishWalkStats performs a latest-wins send: it clears any undelivered
// update before posting the new one, so the walker never blocks on a caller
// that is not reading progress, and a caller that reads late sees the most
// recent value rather than a stale one.
func publishWalkStats(stats chan WalkStats, s WalkStats) {
	for {
		select {
		case stats <- s:
			return
		default:
		}

		//Drain the stale value. The receive is itself non-blocking because
		//another producer may have drained it first.
		select {
		case <-stats:
		default:
			return
		}
	}
}

// CollectFiles drains WalkFiles into a slice, ordered by root and then
// lexically within each root.
//
// This is the shape the removed FindFiles had, and it exists only for the
// callers that genuinely need the whole list — the SDK returns one. Prefer
// WalkFiles: materialising the list reintroduces exactly the memory cost the
// streaming walker was built to remove.
func CollectFiles(ctx context.Context, paths []string, opts WalkOptions) []RepositoryIndexedFile {
	files, _ := WalkFiles(ctx, paths, opts)

	out := []RepositoryIndexedFile{}
	for f := range files {
		out = append(out, f)
	}

	//Roots are walked concurrently, so entries arrive interleaved. A stable
	//sort on the root index gives a deterministic order: within one root the
	//arrival order is already lexical, and stability preserves it.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RepositoryIndex < out[j].RepositoryIndex
	})

	return out
}
