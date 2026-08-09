# Design: 003-scan-engine-performance

## Architecture Overview

The engine moves from a three-phase batch model
(**discover all → loop → accumulate all**) to a **bounded, back-pressured
streaming pipeline**. Every stage communicates over a channel with a bounded
capacity, so a fast producer can never inflate memory: back-pressure propagates
naturally from the slowest stage.

```
paths
  │
  ▼
┌──────────────────────────────────────────┐
│ Stage 1: Walker                          │   goroutine(s)
│  • prunes directories before descending  │
│  • symlink/hardlink cycle guard          │
│  • emits RepositoryIndexedFile as found  │
└───────────────┬──────────────────────────┘
                │ chan RepositoryIndexedFile   cap = 4 × workers
                ▼
┌──────────────────────────────────────────┐
│ Stage 2: Gate (cheap rejection)          │   goroutine(s)
│  ext → test-file → exclusion → size      │
│  → binary sniff                          │
└───────────────┬──────────────────────────┘
                │ chan scanUnit                cap = 4 × workers
                ▼
┌──────────────────────────────────────────┐
│ Stage 3: Worker pool (N = GOMAXPROCS)    │
│  ┌────────────────────────────────────┐  │
│  │ ScanContext (one per worker)       │  │
│  │  • finder set built ONCE           │  │
│  │  • Reset(rif) per file             │  │
│  │  • pooled read buffer              │  │
│  │  • pooled LineIndex                │  │
│  └────────────────────────────────────┘  │
│  Prefilter (Aho–Corasick) → regex        │
└───────────────┬──────────────────────────┘
                │ chan *SecurityDiagnostic     cap = 1024
                ▼
┌──────────────────────────────────────────┐
│ Stage 4: Sink                            │
│  • streaming NDJSON writer               │
│  • coalesced progress ticker (250ms)     │
└──────────────────────────────────────────┘
```

Memory is **O(workers × maxInMemoryFileSize)** plus fixed channel buffers —
independent of the number of files or findings.

---

## Stage 1 — Streaming Walker

Replaces `util.FindFiles` / `util.getFiles`.

```go
// pkg/core/util/walk.go
type WalkOptions struct {
    PruneDirs   func(path string, name string) bool // consulted BEFORE descent
    FollowLinks bool
    Concurrency int
}

func WalkFiles(ctx context.Context, paths []string, opts WalkOptions) (<-chan RepositoryIndexedFile, <-chan WalkStats)
```

**Directory pruning before descent.** `filepath.WalkDir` already gives us
`fs.SkipDir`; today it is never used. The walker consults the compiled exclusion
provider and a default prune set at directory granularity and returns
`fs.SkipDir`, so excluded subtrees are never entered at all. Default prune set
(overridable, and *purely an optimisation of paths that the existing exclusion
logic would reject per file anyway* — see "Behaviour preservation" below):

`.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `.venv`, `venv`,
`__pycache__`, `target`, `build`, `dist`, `.gradle`, `.terraform`,
`.next`, `.nuxt`, `.cache`, `.idea`, `.vscode`

> **Important:** `.git` is pruned for *filesystem content* scanning only. Git
> history scanning remains a separate concern driven by the git service layer
> and is unaffected.

**Cycle safety.** A `map[fileKey]struct{}` of `(device, inode)` for visited
directories (`syscall.Stat_t` on Unix, `FileIndex`/`VolumeSerialNumber` on
Windows) prevents symlink loops and repeated subtree traversal. This restores
the de-duplication that was commented out in `FindFiles`.

**Per-root parallelism.** Multi-repository scans walk each root concurrently
(bounded by `opts.Concurrency`), so a slow NFS mount does not block a fast local
one. `RepositoryIndex` is carried per root exactly as today.

**Progress semantics.** Because the total is not known up front, `WalkStats`
streams a `DiscoveredSoFar` count and a `WalkComplete` flag. `diagnostics.Progress.Total`
carries the running discovered count and becomes exact once the walk completes.
This is a strict improvement: today `Total` is only known after a long silence.

---

## Stage 2 — Gate

All cheap rejections move ahead of any file open, ordered by ascending cost.
Today these checks live inside `ConsumePath` and are duplicated across the two
path consumers (`confidentialFilesFinder` and `pathBasedSourceSecretFinder`),
so `testFile.MatchString` and `ShouldExcludePath` each run twice per file.

Order:

1. **Extension classification** — map lookup against `common.TextFileExtensions`
   / `recognisedFiles` / `common.IsConfidentialFile`.
2. **Test-file check** — `strings.Contains(strings.ToLower(path), "test")`,
   replacing `regexp.MustCompile("(?i:.*test.*)")`. These are **exactly
   equivalent**: the pattern is an unanchored case-insensitive substring match
   with leading/trailing `.*`. Covered by a differential test over a large path
   corpus.
3. **Exclusion match** — memoised per directory (see below).
4. **Size check** — from the `fs.DirEntry` info already available from the walk,
   avoiding an extra `Stat` syscall.
5. **Binary sniff** — read the first 512 bytes once, reject on NUL byte or
   non-`text/*` `http.DetectContentType`. Today this only applies to
   extensionless files (S7); extending it is gated behind an option defaulting
   to **current behaviour**, with widening proposed only if the golden corpus
   shows no finding loss.

The 512-byte prefix read is **retained in the buffer** and reused by the scanner
rather than re-read.

**Exclusion memoisation (S8).** `defaultExclusionProvider` currently walks a
linear list of regexes per path. We add:
- a per-directory LRU cache keyed by parent directory for directory-level
  verdicts, and
- a single pre-combined alternation regex per rule group, so one `MatchString`
  replaces N.

Semantics are unchanged: combined alternation matches iff any member matched.

---

## Stage 3 — Worker Pool and `ScanContext`

### Removing the global finder cache

The `vendorFinders` package-level slice is deleted. `rif` is removed from the
`secretFinder` struct and threaded as an explicit per-file parameter through
`Consume`/`ConsumePath`. This simultaneously:

- fixes the stale `RepositoryIndex` defect (finders currently report the *first*
  scanned file's repository index),
- makes finders free of cross-file state, and
- makes them safely reusable within a worker.

### `ScanContext`

```go
// pkg/plugin/secrets-finder/pkg/scancontext.go
type ScanContext struct {
    providers map[string]MatchProvider // one per file-type class, built once
    buf       []byte                   // reused whole-file read buffer
    lines     LineIndex                // reused, truncated per file
    prefilter *prefilter.Matcher       // shared, immutable, safe to share
    sink      func(*diagnostics.SecurityDiagnostic)
}

func NewScanContext(opts SecretSearchOptions, pf *prefilter.Matcher) *ScanContext
func (c *ScanContext) ScanFile(rif util.RepositoryIndexedFile, ext string) error
```

Each worker owns exactly one `ScanContext`, constructed once at pool start. All
`MatchProvider` variants (`java`, `cpp`, `xml`, `yaml`, `ruby`, `eruby`, `conf`,
`default`) are built **once per worker** and selected by `ext` per file. Per-file
allocation drops from ~240 objects to approximately zero in steady state.

`sync.Pool` backs the read buffer for the large-file path so that transient
spikes are returned to the runtime.

### Pool sizing

`Workers` defaults to `runtime.GOMAXPROCS(0)`, configurable via
`SecretSearchOptions.Workers` and the `CHECKMATE_SCAN_WORKERS` environment
variable. Because scanning is a mix of syscall-bound I/O and CPU-bound regex
work, the default is deliberately `GOMAXPROCS` rather than a larger I/O-oriented
multiple; the benchmark harness will validate and may adjust.

---

## Prefilter (Aho–Corasick)

The single largest CPU win. Built once at package init.

```go
// pkg/plugin/secrets-finder/pkg/prefilter/prefilter.go
type Matcher struct { /* Aho–Corasick automaton over literal seeds */ }

// Returns the set of rule IDs whose required literal seed occurs in data.
func (m *Matcher) CandidateRules(data []byte) ruleSet
```

**Seed extraction.** At init, each rule's pattern is analysed for a mandatory
literal substring. Two sources:

1. `regexp/syntax` — parse the pattern, simplify, and walk the AST for a
   required literal (a `OpLiteral` on every alternation branch, outside any
   `OpStar`/`OpQuest`). This is the same technique Go's own `regexp` uses for
   its one-pass literal prefix optimisation, generalised to alternations.
2. A curated seed table for high-value rules where automatic extraction is
   conservative (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `glpat-`, `xoxb-`,
   `xoxp-`, `sk_live_`, `sk_test_`, `whsec_`, `pypi-`, `AKIA`, `-----BEGIN`, …).

**Soundness rule.** A rule is admitted to the prefilter **only if** its seed is
provably mandatory — i.e. the regex cannot match any input that does not contain
the seed. Rules where this cannot be established (notably the generic
entropy/assignment/long-string finders) go into an **always-run residual set**.
Because prefiltering only ever *skips regexes that could not have matched*, the
finding set is unchanged by construction.

**Verification.** A dedicated fuzz test (`FuzzPrefilterSoundness`) generates
random inputs, runs every rule with and without the prefilter, and asserts
identical match sets. This is in addition to the golden-corpus test.

**Expected effect.** With 222 Gitleaks rules, the overwhelming majority carry
strong literal seeds. On typical source files the automaton makes a single pass
and returns an empty candidate set, so 200+ regex passes collapse to the small
residual set.

---

## File Reading: whole-file default, allocation-free chunking for the rest

`util.readChunks` is replaced.

### Small/medium files (default `< 4MB`)

Read fully into the worker's reusable buffer via `io.ReadFull` sized from the
already-known `DirEntry` size, then match in a single pass. This eliminates
chunk boundaries entirely, which additionally removes a class of missed matches
at chunk edges — but **only for files that today already fit within the
newline-aligned chunking**, so no new findings appear. (Any divergence surfaces
in the golden corpus and would be treated as a bug to reconcile, not a silent
behaviour change.)

The `4MB` threshold is exactly the value `readChunks`' own comment intended
before the `4096` constant diverged from it.

### Large files (`>= 4MB`)

A rewritten chunker with:
- a fixed reusable `[]byte` buffer — **no string concatenation, no `O(n²)`**,
- a bounded **overlap window** (`maxMatchWindow`, default 64KB) carried between
  chunks so matches spanning a boundary are still found, and
- newline alignment preserved where a newline exists within the window; when it
  does not (minified/single-line content) the chunker simply cuts at the buffer
  boundary and relies on the overlap, instead of growing a string unboundedly.

The existing 10MB `cutOffSize` skip for unrecognised extensions is retained
verbatim.

### No goroutine per chunk

`defaultResourceMultiplexer.start()`'s `go` + `WaitGroup` per consumer per chunk
is removed. Consumers are invoked **synchronously** on the worker goroutine.
Parallelism now lives at the file level, where the work units are large enough
to amortise scheduling. This removes the ~614k-goroutine pathology on a single
large file.

---

## `LineIndex` (replaces `LineKeeper`) — S1

```go
type LineIndex struct { eols []int32 } // int32 halves memory; files > 2GB are not scanned

func (l *LineIndex) Reset()
func (l *LineIndex) Build(data []byte)                     // single pass, one alloc, reused slice
func (l *LineIndex) Position(off int64) code.Position      // sort.Search — O(log n), lock-free
```

Built once per file *before* matching, so it is immutable during matching and
requires **no mutex** — removing both the lock contention and the O(lines)
linear scan per finding. `code.Position` output is bit-identical; a differential
test asserts equality against the current implementation across random inputs.

---

## Inline hashing — S2

`computeFileHash` currently re-opens and re-reads the file with `io.Copy` after
it has already been streamed for scanning. Since the whole-file path already
holds the bytes, the SHA-256 is computed from the in-memory buffer. The
large-file path feeds the hasher from each chunk via `io.MultiWriter`-style
tee. Result is identical; one full file read is eliminated per file whenever
`CalculateChecksum` is enabled.

Similarly, `xmlSecretFinder.ConsumePath`'s second `os.Open` of the same file
(S3) is replaced by an `io.SectionReader`/`bytes.Reader` over the already-read
buffer.

---

## Stage 4 — Streaming Sinks — P6

### `projects.simpleDiagnosticConsumer`

Replaced by a streaming writer:

```go
type streamingDiagnosticConsumer struct {
    f   *os.File
    w   *bufio.Writer   // 256KB
    enc *json.Encoder   // one JSON document per line (NDJSON)
    mu  sync.Mutex
    n   int64
}
```

Diagnostics are written as they arrive; nothing is retained. Memory is flat, and
a crash preserves everything written so far.

**Compatibility.** The results file gains a `.ndjson` sibling. The reader
sniffs the first byte: `[` → legacy JSON array, otherwise → NDJSON. Existing
scan result files continue to load unchanged, so no migration is required and
historical scans remain readable.

### `SearchSecretsOnPaths`

The `fileBuffers map[string][]*SecurityDiagnostic` accumulator is removed;
diagnostics stream directly to the output channel. Where per-file grouping is
genuinely required (aggregation ordering), it is scoped to a **single file** and
released immediately, matching `MakeSimpleAggregator`'s existing per-file
semantics.

---

## Progress Coalescing — S4

Per-file `progressCallback` invocations (1M calls on a 1M-file scan, each fanning
out to WebSocket broadcast and/or DB writes) are replaced by:

- atomic counters incremented by workers (`filesScanned`, `bytesScanned`,
  `findingsEmitted`), plus an atomically-stored "most recent file",
- a single `time.Ticker` (default 250ms, configurable) that snapshots the
  counters and emits one `diagnostics.Progress`,
- a guaranteed final emission at 100% on completion.

The `diagnostics.Progress` struct and callback signature are **unchanged**, so
the API, WebSocket, SSE and Wails app consumers need no modification.

---

## Cancellation — S5

`ctx.Err()` is checked in the walker loop, the gate loop and every worker loop.
On cancellation, channels are drained and closed, workers exit, and the sink is
flushed and closed cleanly so partial results remain valid. This makes the `ctx`
parameter `Scan` already accepts actually meaningful.

---

## Parallel Shallow Cloning — S6

`cloneRepositories` becomes:

- an `errgroup` with a bounded concurrency limit (default 4, configurable),
- shallow clone (`Depth: 1`) by default where the scan does not require history,
- **pipelined**: each repository is pushed onto the walker input channel as soon
  as its clone completes, rather than waiting for all clones.

`RepositoryIndex` assignment remains deterministic — indices are allocated up
front from the ordered repository list, before cloning starts, so the
`locationTransposer` mapping is byte-identical to today regardless of completion
order.

---

## Configuration Surface

All additive, all defaulted to sensible values. No existing flag changes meaning.

| Option | Env | Default | Purpose |
|---|---|---|---|
| `Workers` | `CHECKMATE_SCAN_WORKERS` | `GOMAXPROCS` | Scan worker pool size |
| `CloneConcurrency` | `CHECKMATE_CLONE_CONCURRENCY` | `4` | Parallel repo clones |
| `MaxInMemoryFileSize` | `CHECKMATE_MAX_INMEM_FILE` | `4MB` | Whole-file vs chunked |
| `ProgressInterval` | `CHECKMATE_PROGRESS_INTERVAL` | `250ms` | Progress coalescing |
| `DisablePrefilter` | `CHECKMATE_DISABLE_PREFILTER` | `false` | Escape hatch / A-B validation |
| `PruneDirs` | `CHECKMATE_PRUNE_DIRS` | built-in set | Walker pruning |

`DisablePrefilter` exists specifically so the golden-corpus test can run both
paths and assert equality, and so users can rule the prefilter out if they ever
suspect it.

---

## Behaviour Preservation Strategy

This is a performance change; **result equivalence is the acceptance gate**.

1. **Golden corpus.** A fixture tree combining the existing `pkg/.../testdata`
   samples with synthetic repositories covering every file-type branch of
   `GetFinderForFileType`, plus adversarial inputs (minified JS, single-line
   JSON, base64 blobs, symlink loops, deeply-nested trees, 10MB+ files,
   extensionless binaries).
2. **Baseline snapshot.** The current engine's findings are serialised,
   canonically sorted, and committed as the golden file.
3. **Equivalence test.** The new engine must produce a byte-identical canonical
   finding set. Run in CI on every commit of this change.
4. **Prefilter soundness fuzzing.** `FuzzPrefilterSoundness` asserts prefiltered
   and unfiltered rule matching agree on random input.
5. **`LineIndex` differential test.** Random offsets over random files must yield
   identical `code.Position` to `LineKeeper`.
6. **Race detector.** The full suite runs under `-race`, which is what catches
   regressions of the `vendorFinders` class of bug.
7. **Staged rollout.** Each task lands independently behind the equivalence test,
   so any divergence is attributable to a single change.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Prefilter wrongly skips a matching rule | Soundness proof per seed + fuzz test + `DisablePrefilter` escape hatch + residual always-run set |
| Whole-file reading inflates memory on huge files | Hard `MaxInMemoryFileSize` threshold; above it the bounded chunker is used; buffers pooled |
| Directory pruning hides files users expect scanned | Prune set is configurable; defaults are directories the per-file exclusion logic already rejects; documented and logged in verbose mode |
| Parallelism introduces nondeterministic output ordering | Findings are canonically sorted before persistence and comparison; finding IDs are already order-independent |
| Removing `rif` from finder structs is a wide refactor | Purely mechanical, compiler-enforced; the equivalence test also catches the stale-index fix changing `RepositoryIndex` values (an intended correction, explicitly re-baselined and documented) |
| NDJSON breaks existing stored scans | Format sniffing on read; legacy JSON arrays still supported indefinitely |

> **Note on the one intentional behavioural correction:** fixing the stale
> `vendorFinders` `rif` changes `RepositoryIndex` on vendor-rule findings in
> multi-repository scans from "always the first repo" to "the correct repo".
> This is a bug fix, not a regression. It is called out explicitly, the golden
> baseline is re-recorded for that case only, and it is documented in the
> change's release notes.
