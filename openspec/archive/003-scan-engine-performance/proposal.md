# OpenSpec Proposal: 003-scan-engine-performance

**Status:** Draft
**Capability:** `scan-engine`
**Type:** Performance / architecture — **no functional change**

## Goal

Re-architect the CheckMate secret-scanning engine from a single-threaded,
fully-materialising batch pipeline into a **bounded, streaming, parallel
pipeline** whose memory footprint is independent of corpus size, so that
CheckMate handles the largest realistic workloads — multi-repository scans and
whole-filesystem scans of millions of files — without stalling or exhausting
memory.

## Motivation

CheckMate is fast on small and medium repositories but degrades
catastrophically on large ones. A code review of the hot path
(`SecretScanner.Scan` → `util.FindFiles` → `PathMultiplexer.ConsumePath` →
`GetFinderForFileType` → `FindSecret` → `NewResourceMultiplexer` →
`readChunks` → per-rule `Consume`) identified six structural causes.

### P1 — The scan loop is single-threaded

`pkg/plugin/secrets-finder/pkg/secret_scanner.go` iterates the discovered file
list synchronously on one goroutine. Scan throughput is capped at one CPU core
regardless of the host. On a 32-core machine roughly 3% of available compute is
used.

### P2 — Discovery fully materialises before any scanning begins

`util.FindFiles` walks every path into a `[]RepositoryIndexedFile` slice and
only returns when the walk is complete. Consequences:

- Memory proportional to the total file count (hundreds of MB for multi-repo
  scans) held live for the entire scan.
- **No findings and no meaningful progress are emitted until the walk
  finishes** — the primary "the scanner got lost" symptom.
- `getFiles` performs no directory pruning, descending into `.git`,
  `node_modules`, `vendor`, `target`, `dist`, `.venv`, etc. Exclusions are only
  consulted afterwards, per file, inside `ConsumePath`.
- No symlink-cycle guard; the previous de-duplication map is commented out.

### P3 — ~240 finder objects are allocated per file, behind an unsafe cache

`GetFinderForFileType` constructs a fresh `defaultMatchProvider` for every file.
`makeVendorSecretsFinders` alone covers **222 Gitleaks rules** plus 9 built-in
vendor rules, plus the assignment/string/XML finders. Per file this is ~240
struct allocations, ~240 slice allocations, a fresh
`RegisterDiagnosticsConsumer` closure graph, and a new channel + goroutine in
`FindSecret`.

The existing mitigation is unsound. `vendorFinders` is a package-level slice
built lazily from **the first file ever scanned**:

```go
var vendorFinders []common.ResourceToSecurityDiagnostics
func makeVendorSecretsFinders(options SecretSearchOptions, rif util.RepositoryIndexedFile) []common.ResourceToSecurityDiagnostics {
    if len(vendorFinders) == 0 { /* built with THIS file's rif and options */ }
    return vendorFinders
}
```

These finders carry mutable per-file state (`lineKeeper`, `provideSource`,
broadcast consumer list, `rif`). The cached `rif` is therefore **stale for every
file after the first**, which is a latent correctness defect today and a
guaranteed data race under any concurrency. It must be fixed before P1.

### P4 — Quadratic chunking and goroutine storms

`util.readChunks` accumulates with string concatenation whenever a read buffer
contains no newline:

```go
largeChunk += remnant + string(buf[:len])
```

Minified JS/CSS, single-line JSON, base64 blobs, lockfiles and SQL dumps all hit
this branch on every iteration. Combined with `dataChunkSize = 4096` (the
adjacent comment claims 4Mb — a 1000× discrepancy), a 10MB single-line file
performs ~2,560 iterations each copying a string growing toward 10MB:
approximately **13GB of memcpy for one file**.

`defaultResourceMultiplexer.start()` compounds this by spawning one goroutine
**per consumer per chunk**:

```go
wg.Add(len(consumers))
for _, c := range consumers { go func(...) { ... }(c, &wg) }
```

240 consumers × 2,560 chunks ≈ **614,400 goroutine creations for a single 10MB
file**, each performing ~4KB of work. Scheduling overhead dominates real
matching.

### P5 — 222+ regexes run over every chunk with no prefilter

Every chunk is scanned independently by all rules. This is the dominant CPU cost
and is largely avoidable: most high-value rules key off distinctive literal
seeds (`ghp_`, `glpat-`, `xox`, `sk_live`, `pypi-`, `-----BEGIN`). A single
combined literal prefilter can eliminate the vast majority of regex executions.

Related avoidable regex work in the same path:

- `testFile = regexp.MustCompile("(?i:.*test.*)")` — a leading-`.*` pattern
  evaluated on **every path, once per path consumer**.
- `space.FindAllStringIndex(src[a:b], -1) == nil` — allocates a complete match
  slice to answer a boolean question.

### P6 — Results are accumulated wholly in memory

- `projects.simpleDiagnosticConsumer` appends every diagnostic of the entire
  scan to a slice and `json.Encode`s once at the end. Large scans exhaust
  memory, and any crash discards the whole scan.
- `SearchSecretsOnPaths` similarly accumulates
  `fileBuffers map[string][]*SecurityDiagnostic` for the full run.
- `common.MakeSimpleAggregator` buffers all of a file's diagnostics before
  emitting any.

### Secondary findings

| # | Issue | Location |
|---|---|---|
| S1 | `GetPositionFromCharacterIndex` linear-scans a sorted slice under a mutex for every finding — O(lines × findings) | `pkg/core/util/util.go` |
| S2 | `computeFileHash` re-opens and re-reads the whole file after it was already streamed | `pkg/plugin/secrets-finder/pkg/regex_providers.go` |
| S3 | `xmlSecretFinder.ConsumePath` opens the same file twice concurrently | `pkg/plugin/secrets-finder/pkg/regex_providers.go` |
| S4 | `progressCallback` fires once per file — 1M callbacks fan out to WebSocket/DB | `pkg/plugin/secrets-finder/pkg/secret_scanner.go` |
| S5 | `ctx` is accepted by `Scan` but never checked in the scan loop; scans cannot be cancelled | `pkg/plugin/secrets-finder/pkg/secret_scanner.go` |
| S6 | `cloneRepositories` clones sequentially and fully; scanning waits for all clones | `pkg/plugin/secrets-finder/pkg/secret_scanner.go` |
| S7 | Binary sniffing only applied to extensionless files | `pkg/plugin/secrets-finder/pkg/path_processing.go` |
| S8 | Exclusion providers evaluate a linear regex list per path with no memoisation | `pkg/core/diagnostics/exclusion.go` |
| S9 | `detectSecret` → `isVendorSecret` evaluates the **entire** vendor rule set against every candidate secret, ungated by the prefilter. Found during Phase 10 validation; 94.95% of the time on the adversarial fixtures. Attacker-controlled input, so this is a DoS surface and not only a performance defect. Phase 11. | `pkg/plugin/secrets-finder/pkg/secrets_util.go` |

## Scope

1. **Streaming, pruning, cycle-safe walker** replacing `util.FindFiles`.
2. **Bounded worker pool** with per-worker reusable finder state; removal of the
   global `vendorFinders` cache and the stale-`rif` defect.
3. **Literal prefilter (Aho–Corasick)** gating regex execution.
4. **Whole-file scanning** for files under a threshold; rewritten allocation-free
   chunker with overlap for the remainder.
5. **Streaming NDJSON sinks** replacing whole-scan in-memory accumulation.
6. **Coalesced progress reporting and genuine context cancellation.**
7. **Parallel shallow cloning** with per-repository pipelining.
8. Secondary fixes S1–S8.
9. **Benchmark and golden-corpus harness** proving both the speedup and the
   absence of behavioural change.

## Non-Goals

- No new detection rules, no rule removal, no rule tuning.
- No changes to the REST/WebSocket/SSE API surface, the SDK surface, or CLI
  flags (only additive, defaulted tuning options).
- No changes to storage schema or report formats.

## Invariant (non-negotiable)

**This change must not alter scan results.** For any given corpus and
configuration, the set of emitted findings — including finding IDs, locations,
severities, confidences, evidence, tags and exclusion decisions — must be
identical before and after. This is enforced by a golden-corpus regression test
that fails the build on any divergence.

## Success Criteria

| Dimension | Baseline | Target |
|---|---|---|
| CPU utilisation | 1 core | ≥ 80% of `GOMAXPROCS` |
| Throughput, 16-core, 1M-file corpus | 1× | **≥ 10×** |
| Peak RSS, 1M files / 500k findings | O(files + findings), multi-GB | **flat, < 512MB** |
| Time to first finding | after full walk (minutes) | **< 1s** |
| 10MB single-line file | minutes (O(n²)) | **< 1s** |
| Steady-state allocations per file | ~240 objects | **~0 (pooled)** |
| Findings emitted | baseline set | **byte-identical** |
