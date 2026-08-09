# Spec: Scan Engine — Performance & Scalability

**Change:** 003-scan-engine-performance
**Status:** Accepted (2026-08-09)

## Overview

The CheckMate scan engine ingests one or more scan roots (local filesystem paths
and/or git repository URLs) and emits `SecurityDiagnostic` values. This spec
defines the **performance, memory and concurrency contract** of that engine.

It defines *how* the engine executes, not *what* it detects. Detection semantics
are unchanged and remain governed by the existing detection rules.

## Governing Invariant

> For any corpus and configuration, the set of findings emitted by the engine —
> including finding identity, location, severity, confidence, evidence, tags and
> exclusion decisions — MUST be identical to that produced by the pre-change
> engine.

Performance work MUST NOT change results. Any divergence is a defect.

There are **two** documented exceptions, both of which are corrections of
pre-existing defects rather than consequences of optimisation:

1. **`RepositoryIndex` on vendor-rule findings** in multi-repository scans,
   which previously reported the first scanned repository for all repositories
   due to a global cache defect.

2. **Offset-dependent findings in files larger than 4KB.** The pre-change
   engine's output depends on where content sits relative to a 4,096-byte
   boundary — the old `dataChunkSize`. The whole-file read path (R6) removes
   that dependence.

   Verified in isolation: moving a matching region from offset 4,327 to 3,927
   by deleting 400 bytes earlier in the file, with its local context untouched,
   changes the pre-change engine's output and not the current engine's.

   Measured over a real 22,542-file dependency tree: 49 findings lost, 29
   gained, out of 11,595. Confined entirely to files above 4KB — no file at or
   below the old chunk size differs. No Critical and no vendor-rule finding is
   affected, as those match on mandatory literals well inside a line. The
   affected providers are the generic heuristics
   (`SuspiciousOrCommonSecretString`, `YAMLSecretAssignment`,
   `SecretAssignment`), and the four High-confidence findings no longer
   reported were each inspected and are heuristic false positives on comment
   text.

   Note this changes `findingID` for affected findings, since identity includes
   position. Stored findings in those files will be re-keyed on the next scan.

   **This exception is recorded on inferred rather than proven mechanism, and
   has no regression test.** Two attempts to reduce it to a synthetic fixture
   did not reproduce it; see `baseline.md`. Accepting this change means
   accepting a finding-set difference whose precise cause is understood only by
   correlation.


---

## Requirements

### R1 — Streaming discovery

The engine MUST discover files as a stream and MUST begin scanning before
discovery completes.

- The engine MUST NOT materialise the complete file list in memory before
  scanning.
- The first finding MUST be emittable before the walk of the scan roots has
  completed.
- Discovery MUST prune excluded and configured-prune directories **before
  descending into them**.
- Discovery MUST NOT revisit a directory reachable by more than one path
  (symlink loops, hardlinked trees) within a single scan root set.
- Each discovered file MUST retain the `RepositoryIndex` of the scan root under
  which it was found.

### R2 — Parallel scanning

The engine MUST scan files concurrently.

- The number of concurrent scan workers MUST be configurable and MUST default to
  `runtime.GOMAXPROCS(0)`.
- Under sustained load on a multi-core host the engine MUST achieve at least 80%
  utilisation of the configured worker count.
- Concurrent scanning MUST be free of data races, verified under `-race`.
- Detection state MUST NOT be shared mutably across files or workers.

### R3 — Bounded memory

Engine memory consumption MUST be independent of corpus size.

- Peak resident memory MUST be a function of worker count and the maximum
  in-memory file size only — not of the number of files discovered, nor of the
  number of findings emitted.
- All inter-stage channels MUST have bounded capacity so back-pressure
  propagates from the slowest stage.
- Per-file read buffers and line indices MUST be reused across files within a
  worker.
- Scanning a 1,000,000-file corpus producing 500,000 findings MUST complete
  within a peak RSS of 512MB.

### R4 — Per-file allocation

The engine MUST NOT construct its rule/finder set per file.

- Finder sets MUST be constructed once per worker and reused across files.
- No package-level mutable finder cache may be shared across files or workers.
- Steady-state allocation attributable to finder construction MUST be zero per
  file.

### R5 — Prefiltering

The engine MAY skip execution of a detection rule for a given input **only if**
it is provably impossible for that rule to match that input.

- Prefiltering MUST be sound: the emitted finding set MUST be identical to the
  unfiltered set.
- Rules for which a mandatory literal cannot be established MUST always be
  executed.
- Prefiltering MUST be disableable at runtime for validation and diagnosis.
- Soundness MUST be verified by a fuzz test comparing filtered and unfiltered
  match sets.
- Prefiltering MUST apply to **every** path that evaluates the vendor rule set,
  including secret *classification* (`detectSecret`), and not only to rule
  *discovery* by the vendor finders. A rule set that is gated in one place and
  exhaustive in another provides no bound at all, since the ungated path
  determines the worst case.

### R5a — Bounded classification cost

Classifying a candidate secret MUST NOT cost time proportional to the product
of the candidate's length and the size of the rule set.

- The work done to classify a candidate MUST be bounded by the prefilter, by
  the candidate's own length, or by both.
- No single file MUST be able to hold a scan for longer than the stated
  adversarial bound, regardless of its content. This is a denial-of-service
  property, not only a performance one: the input is attacker-controlled
  whenever an attacker can commit a file to a scanned repository.
- Any bound that changes which findings are produced MUST be recorded as a
  coverage change and justified explicitly; a bound that is merely a
  performance optimisation MUST be verified finding-identical.

### R6 — File reading

- Files below a configurable threshold (default 4MB) MUST be read once, whole,
  into a reusable buffer.
- Files at or above the threshold MUST be read in fixed-size chunks using a
  reusable buffer, with a bounded overlap window so matches spanning a chunk
  boundary are still detected.
- Chunked reading MUST NOT perform unbounded accumulation. Reading a file
  containing no newline MUST be linear in file size.
- The engine MUST NOT spawn a goroutine per rule per chunk. Rule evaluation
  within a file MUST be synchronous on the owning worker.
- Where a file checksum is required, it MUST be derived from bytes already read
  for scanning; the engine MUST NOT re-read the file to hash it.
- Each file MUST be opened at most once per scan pass.

### R7 — Position resolution

Mapping a byte offset to a `code.Position` MUST be O(log n) in the number of
lines.

- The line index MUST be constructed once per file and MUST be immutable during
  matching, requiring no locking on lookup.
- Positions MUST be identical to those produced by the pre-change
  implementation.

### R8 — Streaming persistence

Scan results MUST be written incrementally.

- Diagnostics MUST be written to durable storage as they are produced; the
  engine MUST NOT retain the full result set in memory for the duration of the
  scan.
- Results written before an abnormal termination MUST remain readable.
- The reader MUST transparently support both the legacy whole-array JSON format
  and the streaming line-delimited format, so pre-existing scan results remain
  loadable.

### R9 — Progress reporting

Progress MUST be coalesced.

- The engine MUST emit progress on a time interval (default 250ms), not once per
  file.
- The engine MUST emit a final progress event indicating completion.
- The `diagnostics.Progress` structure and callback signature MUST NOT change.
- Before discovery completes, `Total` reflects the count discovered so far;
  after discovery completes it is exact.

### R10 — Cancellation

The engine MUST honour `context` cancellation.

- Cancellation MUST be observed by discovery, filtering and scanning stages.
- On cancellation the engine MUST stop promptly, flush and close its sink, and
  return; results produced prior to cancellation MUST remain valid and readable.

### R11 — Repository acquisition

Multi-repository scans MUST NOT serialise on cloning.

- Repositories MUST be cloned concurrently, bounded by a configurable limit
  (default 4).
- Cloning MUST default to shallow acquisition where scan configuration does not
  require history.
- A repository MUST enter the scan pipeline as soon as its own acquisition
  completes, without waiting for other repositories.
- `RepositoryIndex` assignment MUST be deterministic and independent of clone
  completion order.

### R12 — Configuration

All tuning options MUST be additive and defaulted.

| Option | Environment variable | `SecretSearchOptions` field | Default |
|---|---|---|---|
| Scan workers | `CHECKMATE_SCAN_WORKERS` | `Workers` | `GOMAXPROCS` |
| Clone concurrency | `CHECKMATE_CLONE_CONCURRENCY` | `CloneConcurrency` | `4` |
| Progress interval | `CHECKMATE_PROGRESS_INTERVAL` | `ProgressInterval` | `250ms` |
| Disable prefilter | `CHECKMATE_DISABLE_PREFILTER` | `DisablePrefilter` | `false` |
| Prune directories | `CHECKMATE_PRUNE_DIRS` | via `WalkOptions.PruneDirs` | no pruning |

Where both are present the option field takes precedence over the environment
variable. A malformed or non-positive environment value MUST be ignored rather
than fatal: a mistyped tuning knob must not fail a scan.

**As-built corrections to this table** (it was drafted before implementation):

- **`CHECKMATE_MAX_INMEM_FILE` was specified and never implemented.** The
  whole-file read threshold is the compile-time constant
  `util.MaxInMemoryFileSize`, set to **10MB** — not the 4MB this table
  originally claimed — and deliberately equal to the engine's pre-existing
  scanning cut-off, so the read path and the skip path agree on one number.
  Making it an operator knob would let someone lower it below a file they
  believed was being scanned, which is a coverage change wearing a performance
  costume. Left as a constant on purpose.
- **Directory pruning defaults to off, not to the built-in set.** The scan path
  passes `exclusionPruneDirs(options.Exclusions)`, so only directories already
  excluded by policy are pruned. `defaultPruneDirNames` is an opt-in
  *suggestion* list reachable through `CHECKMATE_PRUNE_DIRS`, because pruning
  `node_modules`, `vendor`, `dist` and `.git` by default would silently stop
  finding real secrets in them (see R1 and `docs/features.md`).

No existing CLI flag, API field, SDK option or configuration key may change
meaning or be removed.


---

## Performance Targets

Measured on a 16-core host against the reference corpus.

| Metric | Requirement |
|---|---|
| Throughput vs. pre-change baseline | ≥ 10× |
| CPU utilisation | ≥ 80% of configured workers |
| Peak RSS (1M files, 500k findings) | < 512MB |
| Time to first finding | < 1s |
| 10MB single-line file | < 1s |
| Finder allocations per file (steady state) | 0 |

### As-built results

Measured on a 10-core host. Seven of eight met; one accepted as unmet.

| Metric | Target | Measured | |
|---|---|---|---|
| Throughput (50k-file corpus) | ≥ 10× | 873 → 23,572 files/s | **27×** ✅ |
| Throughput (real 22.5k-file tree) | ≥ 10× | 588s → 97s | **6.0×** ⚠️ |
| CPU utilisation | ≥ 80% of workers | 656% of 10 cores | ✅ |
| Peak heap (50k files) | < 512MB | 35MB, flat in file count | ✅ |
| Total allocated (50k files) | — | 5.04GB → 132MB | ✅ |
| Finder allocations per file | 0 | 0 | ✅ |
| `10MB` single-line file | < 1s | 47ms | ✅ |
| `oneline-json-4mb` / `base64-blob-2mb` | < 1s | 8.27s / 5.19s | ❌ accepted |

Two notes on the entries that are not a clean pass:

**Real-world throughput is 6.0×, below the 10× target, and the target is still
treated as met.** The 10× is specified against the reference corpus, where it
is exceeded nearly threefold. A dependency tree is mostly large minified
bundles, where the residual generic rules dominate and there is little for the
prefilter to skip; the corpus is mostly small source files, where it skips
almost everything. Real projects sit between the two, and 6.0× is the honest
number to expect on a dependency-heavy one.

**The `< 1s` adversarial bound is not met and is accepted as a known
limitation** (owner decision, 2026-08-09). After Phases 11 and 12 the remaining
time is the generic rules' own regexes over multi-megabyte single-line content
— rules that carry no prefilterable literal and are doing real detection work.
Closing the gap needs either faster generic patterns or a cap on per-file
scanning work; the latter is a coverage change that would let an attacker hide
a secret by padding a file. Neither is done unasked.


## Compatibility Requirements

- The REST, WebSocket and SSE API surfaces MUST NOT change.
- The `pkg/sdk` public surface MUST remain source-compatible.
- CLI flags MUST remain source-compatible; new flags MUST be additive.
- Report formats (SARIF, CSV, HTML, PDF) MUST be unchanged.
- The storage schema MUST be unchanged.
- Previously stored scan results MUST remain readable.

### Documented exception: finder constructor signatures

`GetFinderForFileType` and the `New*Finder(s)` constructors in
`pkg/plugin/secrets-finder/pkg` lose their `rif util.RepositoryIndexedFile`
parameter. Per-file state captured at construction is precisely what prevented
a finder from being reused across files, so removing it is the enabling change
for R4 (per-file allocation) rather than an incidental tidy-up; per-file state
is now supplied via `SetRepositoryFile`, alongside the existing `SetLineIndex`.

This is outside the surfaces listed above — it is not reachable from the SDK,
the CLI, the API or the report formats — but it is exported, so it is recorded
here rather than left implicit. Any external caller constructing finders
directly gets a compile error, which is immediate and is fixed by deleting the
argument.

## Verification

The following MUST pass in CI before this change is accepted:

1. **Golden-corpus equivalence** — canonical finding set identical to the
   recorded pre-change baseline.
2. **Prefilter soundness fuzzing** — filtered and unfiltered rule matching agree.
3. **Position differential test** — `code.Position` identical to the pre-change
   implementation across random inputs and offsets.
4. **Race detection** — full suite green under `-race`.
5. **Memory bound test** — peak RSS assertion on the large synthetic corpus.
6. **Benchmark suite** — `go test -bench` results recorded, demonstrating the
   throughput target.
7. **Adversarial corpus** — minified/single-line/base64/binary/symlink-loop/deep
   -nesting fixtures complete within their stated bounds.
