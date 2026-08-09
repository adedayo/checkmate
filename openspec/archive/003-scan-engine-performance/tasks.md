# Tasks: 003-scan-engine-performance

Tasks are ordered so that each phase lands independently and the equivalence
test passes after every phase. **Phase 0 must be completed first** — nothing
else can be validated without it.

---

## Phase 0 — Safety net (blocking prerequisite) — ✅ COMPLETE

- [x] **0.1** Build the reference corpus (`corpus_test.go`):
  - one synthetic repo per branch of `GetFinderForFileType`
    (`.java`, `.scala`, `.kt`, `.go`, `.cpp`, `.hpp`, `.xml`, `.yaml`, `.json`,
    `.rb`, `.erb`, `.conf`, extensionless, unknown extension)
  - two repository roots, so `RepositoryIndex` 0 and 1 are both exercised
  - confidential-file and test-file fixtures
  - adversarial set: 10MB minified JS, 4MB single-line JSON, 2MB base64 blob,
    binary behind a text extension, extensionless binary, >10MB file with an
    unrecognised extension (`cutOffSize`), 200-deep nesting, symlink loop
  - Corpus is materialised to `os.MkdirTemp("", "cmcorpus")`, **not**
    `testdata/` or `t.TempDir()`, because `testFile` matches any path
    containing "test" and would otherwise tag every fixture
- [x] **0.2** Canonicalisation helper (`canonical_test.go`) with a verified
  **total** ordering, so parallel scanning cannot introduce sort flakiness
- [x] **0.3** Record the baseline golden file (21 findings, 19 files, 2 roots)
- [x] **0.4** `TestScanEquivalence` + `TestCanonicalOrderIsTotal` +
  `TestCanonicaliseIsStable`, all green in CI
- [x] **0.5** `BenchmarkScanScale`, `BenchmarkFinderConstruction`,
  `TestBaselineMemoryProfile`, `TestBaselineAdversarial`,
  `TestBaselineSymlinkLoop`; numbers recorded in `baseline.md`. Slow
  measurements gated behind `CHECKMATE_PERF_BASELINE=1` so ordinary CI stays
  within its timeout
- [x] **0.6** `-race` already enabled for the full suite in `.github/workflows/ci.yml`

### 0.7 — Determinism defects (discovered by 0.3; blocking) — ✅ COMPLETE

The baseline could not be recorded because the engine produced different
results for identical input, both across processes and between consecutive
scans in one process. Six defects, all pre-existing. See `baseline.md` for
detail and impact.

- [x] **0.7.1** D1 — sort vendor rule IDs in `makeVendorSecretsFinders`
- [x] **0.7.2** D2 — sort `indexedEncodedSecretPatterns` in
  `setupSecretStringsIndicators` (it builds a regex alternation) and make it
  idempotent by assigning rather than appending to a package-level slice
- [x] **0.7.3** D3 — sort file-group keys in `simpleDiagnosticAggregator.Aggregate`
- [x] **0.7.4** D4 — add `diagnostics.SortDiagnosticsDeterministically` and
  apply it in `SubsumeOverlapping` and `removeOverlappingIssues`, making
  overlap resolution a pure function of the finding set rather than of arrival
  order. **Required for parallel scanning**, where arrival order is
  nondeterministic by construction
- [x] **0.7.5** D5 — evaluate vendor rules in sorted order in `isVendorSecret`
  and `isEncodedSecret`; share one `sortedVendorSecretIDs` order with finder
  construction. Populate it in `init` (a package-var initialiser would capture
  `vendorSecrets` while still empty and disable every vendor rule)
- [x] **0.7.6** D6 — remove the `vendorFinders` global cache entirely. Besides
  the append-aliasing corruption, it captured `rif` from the first file ever
  scanned and grew its consumer list without bound
- [x] **0.7.7** Pull task 3.5 forward: remove the goroutine-per-consumer-per
  -chunk fan-out, which fed the nondeterministic ordering
- [x] **0.7.8** Add permanent regression guards (`determinism_test.go`):
  `TestScanIsRepeatable`, `TestVendorFinderOrderIsDeterministic`,
  `TestVendorSecretEvaluationOrderIsSorted`,
  `TestSecretStringIndicatorsAreDeterministic`,
  `TestConnectorOrderIsDeterministic`, `TestUniquePreservesOrder`
- [x] **0.7.9** Remove stray `fmt.Println("TESTING COMPILATION …")` debug output
- [x] **0.7.10** Verify: byte-identical results across 10 consecutive
  independent processes with `-race`; full repository suite green

---

## Phase 1 — Remove shared mutable finder state (unblocks concurrency)

> **Partially delivered in 0.7.6** — the global cache is gone and the
> `RepositoryIndex` correction is already reflected in the baseline. Tasks 1.4
> and the separate baseline re-record are therefore no longer required.

- [x] **1.1** Delete the package-level `vendorFinders` cache
- [x] **1.2** Remove `rif` from finder *construction*; supply it as per-file
  state instead.
  *Delivered slightly differently from the plan. Threading `rif` through every
  `Consume` call would have changed the `ResourceToSecurityDiagnostics`
  interface for every implementation. Instead `rif` became a per-file field set
  by `SetRepositoryFile`, alongside the existing `SetLineIndex`, which already
  worked exactly this way. The property that matters — nothing about a specific
  file is captured at construction, so one finder serves many files — holds
  either way, and `TestScanContextIsReusableAcrossFiles` guards it.*
- [x] **1.3** All `make*Finder` constructors and `New*Finder` providers now take
  only `options`; the `rif` parameter is gone from every one
- [x] **1.4** ~~Re-record the golden baseline for the `RepositoryIndex`
  correction~~ — already included in the Phase 0 baseline
- [x] **1.5** Audit for remaining package-level mutable state in the secrets
  package (compiled regexes are immutable and may stay)

  Audit result — everything remaining is **write-once during `init`, read-only
  thereafter**, which is safe for the concurrent readers Phase 7 introduces:
  - Compiled regexes and description/provider-ID strings — immutable literals.
  - `recognisedFiles`, `common.TextFileExtensions` — literal maps, never written.
  - `vendorSecrets`, `sortedVendorSecretIDs`, `encodedSecretPatterns`,
    `connectorKeysBySpecificity` — populated in `setupVendorSecrets()` /
    `setupSecretStringsIndicators()` during `init`, read-only afterwards.
    `setupSecretStringsIndicators` was made idempotent (assign, not append) in
    Phase 0.7, so a repeat call cannot corrupt it.

  The two genuinely mutable pieces of state — the `vendorFinders` finder cache
  and the per-file `rif` — were removed in 1.1 and 1.2/1.3 respectively. No
  shared mutable state remains on the scan path.

---

## Phase 2 — `ScanContext` and per-worker finder reuse

**Status: complete.** Per-file finder construction is gone; a `ScanContext`
built once per worker serves every file. Allocations per file fell from ~970 to
~30, and total allocation for a 50k-file scan from 5.04 GB to 354 MB.

- [x] **2.1** Add `pkg/plugin/secrets-finder/pkg/scancontext.go` with
  `ScanContext`, `NewScanContext`, `FindSecretsInFile`.
  *(`Reset` proved unnecessary: the aggregator is created per file inside
  `FindSecretsInFile` and cleared on return, so there is no residue for a
  caller to reset. Making that automatic removes a way to get it wrong.
  `ScanFile` is named `FindSecretsInFile` to sit alongside `FindSecret`, which
  it replaces.)*
- [x] **2.2** Build all `MatchProvider` variants once per `ScanContext`, keyed by
  file-type class; select per file by extension.
  *`classForExtension` mirrors the `GetFinderForFileType` switch;
  `TestScanContextMatchesGetFinderForFileType` fails if the two ever diverge.*
- [x] **2.3** Move the diagnostic sink from the per-file
  `RegisterDiagnosticsConsumer` closure graph to a `ScanContext`-level sink set
  once at construction.
  *This also fixes a latent leak: registering per file against reused finders
  would have grown the consumer list without bound, retaining every previous
  file's aggregator and broadcasting each finding to a growing list of dead
  collectors.*
- [x] **2.4** Add a pooled read buffer.
  *Implemented as `chunkBufferPool` in `pkg/core/util`, where the buffer
  actually lives, rather than on `ScanContext`. Saves one 4KB allocation per
  file. The larger cost in `readChunks` — quadratic string concatenation for
  files with sparse newlines — is deliberately left to the Phase 3 rewrite.*
- [x] **2.5** Add `BenchmarkAllocsPerFile`; steady-state finder allocations are
  zero (`BenchmarkFinderConstruction`'s 460 allocs/65KB no longer appear on the
  per-file path).
- [x] **2.6** Equivalence test green — golden baseline reproduced byte-for-byte;
  full repo suite green under `-race`.

Additional guards added beyond the plan:
- `TestScanContextClassesAreDistinct` — stops the class map collapsing, which
  would make the mirror test pass vacuously.
- `TestScanContextIsReusableAcrossFiles` — two passes over the corpus through
  one context, each file compared against a fresh per-file construction.
  This is the test that would catch state leaking between files.

---

## Phase 3 — File reading rewrite

**Status: complete.** The quadratic read path is gone. Reading a 4MB
single-line file now costs 3.6ms at ~1.1 GB/s and is no slower than an
equivalent many-line file — the pathological shape is no longer pathological.

- [x] **3.1** Add `LineIndex` (`sort.Search`-based, `int32` offsets, reusable,
  lock-free) in `pkg/core/util/lineindex.go`.
  *Lookup: 1043ns → 8.6ns on a 20k-line file (**122×**), and O(log n) rather
  than O(n), so the gap widens with file size. The old linear scan made a file
  with many findings quadratic in its own size.*
- [x] **3.2** Add `TestLineIndexDifferential` against `LineKeeper` over random
  inputs and offsets. Retain `LineKeeper` until this passes, then remove it.
  *`LineKeeper` was **moved to `lineindex_reference_test.go`**, not deleted.
  Position data feeds the finding ID, so the differential compares against the
  real previous implementation rather than a paraphrase of it, and cannot rot.
  Covers empty input, no newlines, leading/trailing/consecutive newlines, one
  enormous line, and random content — at every offset, plus past end-of-file.*
- [x] **3.3** Whole-file read path for files `< MaxInMemoryFileSize`,
  single-pass matching, no chunking. `*os.File` is sized via `Stat` so the
  buffer is exact and oversized files are rejected without being read.
- [x] **3.4** Rewrite the chunked path: fixed pooled `[]byte`, bounded carry of
  the trailing partial line, **no string concatenation**.
- [x] **3.5** Goroutine-per-consumer-per-chunk fan-out removed (landed early, in
  Phase 0.7, because it was also a determinism defect).
- [x] **3.6** `dataChunkSize` comment said 4Mb while the value was 4Kb. The
  **value** was correct (a page-sized pooled buffer); the comment was the error
  and is fixed. Added `MaxInMemoryFileSize`, set to the engine's existing 10MB
  scanning cut-off.
- [x] **3.7** ~~Compute file checksums inline; remove the second full read in
  `computeFileHash`.~~ **Premise did not survive checking — no change made.**

  `computeFileHash` was expected to re-read files the engine had already read.
  Tracing all five call sites shows it is reached only when a file is (a)
  skipped as a test file, (b) skipped as oversized, or (c) already identified
  as *confidential* by `confidentialFilesFinder`. In none of those cases has
  the content been read for scanning, so there is no redundant read to remove.

  There *is* a real double read, but it is a different one: `confidentialFiles-
  Finder` and `pathBasedSourceSecretFinder` are independent path consumers and
  each opens the file separately. Fixing that needs a single per-file read
  shared between consumers, which is precisely the Phase 6 gate stage. Deferred
  there rather than bolted on here.

- [x] **3.8** Replace `xmlSecretFinder`'s second `os.Open` with a reader over
  the already-read buffer.
  *It was worse than the task implies: the finder discarded the content handed
  to `Consume` and then opened the file **twice** — three full reads of every
  XML file, two redundant. It now retains the streamed content and serves both
  readers from memory. `source` is reset at the start of `ConsumePath`, since
  the finder is reused across files and leftover content would be parsed into
  the next document.*
- [x] **3.9** Adversarial fixtures complete. The 10MB single-line fixture is
  skipped by the size cut-off (correctly, and that behaviour is preserved).
  The remaining slow fixtures — `oneline-json-4mb` (54s), `base64-blob-2mb`
  (148s) — are **not** read-bound: `BenchmarkReadPathOneHugeLine` shows reading
  4MB of single-line content takes 3.6ms. That time is regex evaluation, and is
  Phase 4's target. The suite as a whole now completes in 203s where it
  previously exceeded the 600s timeout.
  *Also fixed a fixture bug: the deep-nesting fixture used 200 levels, which
  overflowed macOS's 1024-byte `PATH_MAX` so the corpus failed to build at all.
  Capped at 80 levels — still far deeper than any real repository.*
- [x] **3.10** Equivalence test green — golden baseline byte-identical; full
  repo suite green under `-race`.

New tests: `TestLineIndexDifferential`, `TestLineIndexAppendEOLsMatchesLine-
Keeper`, `TestLineIndexResetRetainsCapacity`,
`TestLineIndexIndexBytesIsChunkBoundaryAgnostic`,
`TestReadPathDeliversWholeSource`, `TestReadPathPositionsMatchWholeFileIndex`,
plus `BenchmarkReadPathOneHugeLine` / `ManyLines` and `BenchmarkLineIndexLookup`
/ `BenchmarkLineKeeperLookup`.

---

## Phase 4 — Prefilter

**Status: complete.** Rule gating is live on the scan path.

Result: **210 of 225 vendor rules filterable (93.3%)**, **8.9× faster** per
file on ordinary source (166.5 ms → 18.8 ms), with the finding set proved
byte-identical both against the Phase 0 golden baseline and against an
unfiltered run of the same corpus.

Built and validated in isolation before being wired in, deliberately: this is
the only optimisation in the change that can *silently remove findings* if it
is wrong. Every other phase either produces the same output or fails loudly.


- [x] **4.1** `pkg/plugin/secrets-finder/pkg/prefilter/` with an Aho–Corasick
  automaton over literal seeds. Fail links are resolved into a dense
  transition table at build time, so matching is one indexed load per input
  byte with no fail chain to walk.
- [x] **4.2** Mandatory-literal extraction via `regexp/syntax` AST analysis
  (`seeds.go`). A rule is admitted only when the literal is provably mandatory;
  the recursion fails closed, so an operator we do not understand — including
  one a future Go release might add — yields no seed rather than a wrong one.

  Two findings worth recording, both discovered by testing rather than by
  reading the design:

  - **Go factors alternation prefixes.** `(ghp_|gho_|ghu_)` never arrives as an
    alternation of three literals; it arrives as the concatenation
    `gh` `[opu]` `_`. Examining concat elements individually yields only the
    two-character `gh`, so the highest-value rules in the set were all landing
    in the residual bucket. The extractor now multiplies out *runs* of adjacent
    elements, recovering `{gho_, ghp_, ghu_}`.

  - **Case folding is not ASCII-local, and the first implementation was
    unsound because of it.** Under `(?i)`, Go expands folds using full Unicode
    simple case folding: `s` gains U+017F (long s) and `k` gains U+212A (Kelvin
    sign) — visible in the parsed AST as `[OPRSUoprsuſ]`. So `(?i)key` really
    does match `"\u212Aey"`. The original code lowercased seeds with an ASCII
    fold and would have skipped the rule on exactly that input: a false
    negative, the one failure mode this package must not have. Seeds are now
    emitted for the whole fold orbit as byte strings, which the byte-oriented
    automaton handles natively.

    Orbit expansion is multiplicative, though, and
    `(?i)aws_secret_access_key` has six expanding runes — 64 alternatives,
    over budget, which would have pushed a top-value rule into the residual
    set. Since any *substring* of a mandatory literal is itself mandatory, the
    extractor falls back to the longest non-expanding run.

- [x] **4.3** ~~Curated seed table for high-value vendor/Gitleaks rules.~~
  **Dropped deliberately — not deferred.**

  The table was specified as a fallback for rules where automatic extraction is
  too conservative. After 4.2 it is very nearly moot: the run-multiplication
  and fold-orbit work recovers `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
  `glpat-`, `xoxb-`, `sk_live_`, `whsec_`, `pypi-`, `-----BEGIN` and the rest
  automatically, and *proves* them rather than asserting them.

  It is also the one thing here that cannot be made sound. Every other seed is
  derived from the syntax tree; a hand-written seed is an assertion, and
  "this regex cannot match without this literal" is undecidable in general, so
  there is no way to verify one mechanically. That would put the single
  soundness-critical component of the scan engine partly on someone having read
  a regex correctly — and a mistake fails silently, in production, on real
  secrets. The asymmetry is bad: a wrong seed loses findings, while the upside
  is a few percent of throughput.

  What remains residual could not be rescued by a curated seed anyway, because
  the patterns are genuinely generic and contain no mandatory literal:

  | Rule | Why no seed exists |
  | --- | --- |
  | Generic API Key | matches on any of `access`/`key`/`token`/… near a delimiter |
  | JSON Web Token | `ey…` is 2 chars, below `minSeedLength` |
  | Twilio API Key | `SK[0-9a-fA-F]{32}` — 2-char prefix |
  | Sourcegraph | one branch is bare 40-hex, so the alternation requires nothing |
  | AWS credentials | `A3T`/`AKIA`/`ASIA`/`ABIA`/`ACCA` alternation; the `A3T` branch is 3 chars, and one short branch poisons the set |
  | 1Password secret key | `A3-` is 3 chars |
  | Azure AD Client Secret, Connection URI, SendGrid, Facebook, Hugging Face, FlutterWave, Vault, Fly.io, Airtable | leading `\b`/class or a short-literal branch |

  Lowering `minSeedLength` to 3 would admit AWS and 1Password, but a 3-byte
  seed matches almost every file, so the rule would be admitted almost always:
  automaton cost with no skipping. Not worth it.

  These 15 rules always run. That is the designed behaviour of the residual
  set, not a gap.

- [x] **4.4** Rules without a provable seed go into the always-run residual
  set, and the counts are logged once per process in verbose mode. Logged once,
  not once per worker, and the *residual* count is the number surfaced: those
  are the rules that run against every file regardless of content, so it is
  what predicts scan cost when someone is investigating a slow scan.
- [x] **4.5** Rule execution gated on the candidate set in
  `secretStringFinder.Consume`.

  The gate reaches the matching path without changing the multiplexer's
  signature or re-reading the file: `ruleGate` is itself a `ResourceConsumer`,
  registered *first* in each class's consumer list. The multiplexer invokes
  consumers synchronously in declared order, so the candidate set for a given
  piece of content is always computed before any rule sees it.

  That ordering is load-bearing and invisible, so
  `TestPrefilterGateRunsBeforeFinders` pins it. It would break silently if the
  multiplexer ever went back to dispatching consumers concurrently, as it did
  before phase 0.7.7 — every gated rule would read an empty set and findings
  would vanish with no error.
- [x] **4.6** `FuzzPrefilterSoundness` comparing filtered vs unfiltered match
  sets. Asserts only the one direction that matters — a rule that matches must
  have been admitted — since over-admitting is free and under-admitting loses
  findings. Seeded with near-misses built from the rules themselves, because
  random bytes never match a secret regex and would explore nothing.
  Clean over ~1M executions.
- [x] **4.7** `DisablePrefilter` option + `CHECKMATE_DISABLE_PREFILTER`.
  Landed before 4.5 rather than after, so 4.8 could run the corpus both ways
  as soon as gating existed.
- [x] **4.8** `TestPrefilterEquivalence` scans the whole reference corpus with
  gating on and off and asserts the finding sets are byte-identical.

  This is deliberately stronger than the golden baseline. The baseline says the
  gated engine matches a recording; this says the gated and unfiltered engines
  agree with each other *now*, so an unsound seed cannot hide behind a baseline
  recorded after it was introduced. `TestScanEquivalence` also remains green
  and byte-identical, so gating changed nothing against the original Phase 0
  recording either.
- [x] **4.9** Throughput delta recorded.

  | Measurement | Exhaustive | Prefiltered | Change |
  | --- | ---: | ---: | ---: |
  | `BenchmarkScanFileGated` (6KB Go source) | 166.5 ms | 18.8 ms | **8.9× faster** |
  | Allocations per file | 57 | 27 | 2.1× fewer |
  | Rules evaluated on clean source | 225 | 15 | 93.3% skipped |
  | `BenchmarkPrefilterScan` (automaton pass) | — | 418 MB/s, **0 allocs** | — |

  Adversarial fixtures, which Phase 3.9 identified as regex-bound rather than
  read-bound and named as this phase's target:

  | Fixture | Phase 3 | Phase 4 | Change |
  | --- | ---: | ---: | ---: |
  | `oneline-json-4mb` | 54 s | 22.9 s | 2.4× |
  | `base64-blob-2mb` | 148 s | 83.0 s | 1.8× |

  These gain less than the 8.9× seen on ordinary source, and the reason is
  structural rather than disappointing: what remains is almost entirely the
  *residual* set — the generic base64/hex/long-string finders — and on a 2MB
  base64 blob those rules genuinely do have to run and genuinely do match
  everywhere. The prefilter removed the vendor-rule cost; the rest is the
  generic finders doing real work on pathological input. Reducing it further
  needs the entropy/length pre-checks in the Phase 6 gate stage, not more
  prefiltering.


Permanent guards added beyond the plan:
`TestPrefilterEquivalence` (gated vs unfiltered over the whole corpus),
`TestPrefilterCoversMostVendorRules` (fails below 90% filterable — a drop here
is a silent *performance* regression that correctness tests cannot catch),
`TestHighValueRulesAreFilterable` (pins GitHub/GitLab/Slack/Stripe/PyPI
specifically, since losing one of those matters more than the aggregate),
`TestGatedFindersSkipOnlyWhenSeedAbsent` (a gate that admitted everything would
pass equivalence perfectly while delivering no speed-up at all, so equivalence
alone cannot show the gate works — only that it is harmless),
`TestPrefilterGateRunsBeforeFinders`, `TestGateIsInertWhenDisabled`,
`TestDisablePrefilterViaEnvironment`, `TestBuildIsDeterministic`,
`TestOverlappingSeedsAreAllReported` (fail-link output propagation — get it
wrong and a seed that is a suffix of another is silently never reported),
plus `BenchmarkPrefilterScan` and `BenchmarkScanFileGated`.



---

## Phase 5 — Streaming walker

**Status: complete.** The walk streams, prunes before descent and is cycle
safe. `util.FindFiles` is **removed**; both callers now consume `WalkFiles`
directly, so scanning starts on the first file rather than after the last
directory has been read. The bounded worker pool that consumes the stream in
parallel arrives in Phase 7.

Pruning is **opt-in, not on by default** — see 5.10, which corrects a false
premise in the design.

| Measurement (1,000 files, 100 dirs, half under `node_modules`) | Legacy | Phase 5 |
| --- | ---: | ---: |
| Walk time, no pruning | 15.5 ms | 15.2 ms |
| Walk time, pruned | — | 7.8 ms (**2.0×**) |
| Allocations, pruned | 8,566 | 4,477 |

- [x] **5.1** `pkg/core/util/walk.go` with
  `WalkFiles(ctx, paths, opts) (<-chan RepositoryIndexedFile, <-chan WalkStats)`.

  The traversal is a hand-rolled recursion over `os.ReadDir` rather than
  `filepath.WalkDir`, because the walker needs to make three decisions
  `WalkDir` does not expose: whether to descend *before* paying for the
  subtree, whether to resolve a symlink, and whether it has been here before.
  `ReadDir` returns entries sorted by name and directories are descended into
  as they are met, which is precisely `WalkDir`'s own order — so per-root
  emission order is unchanged, and `legacyFindFiles` in the test file asserts
  it rather than the comment merely claiming it.

- [x] **5.2** Directory pruning before descent, via the `PruneDirs` predicate.

  `TestWalkFilesPruneIsConsultedPerDirectoryNotPerFile` is the test that
  matters here: a predicate applied to *files* would produce a byte-identical
  file set while doing every bit of the work pruning exists to avoid. Only
  counting the calls — and asserting we never even ask about `node_modules/pkg`
  — distinguishes a prune from a filter.

  The task also called for consulting the **exclusion provider** at directory
  granularity. That part is deferred to 6.6, on purpose: doing it here means
  calling `ShouldExcludePath` — an unmemoised linear scan of regexes — once per
  directory, before the memoisation that makes it affordable exists. The
  predicate hook is in place, so 6.6 supplies the provider-backed
  implementation rather than changing the walker.

- [x] **5.3** `(device, inode)` visited-directory guard.

  Applied on the followed-symlink path only. A `ReadDir` entry that reports
  `IsDir` is a real directory — the type comes from the directory entry, not
  from resolution — so with `FollowLinks` off there is no route back to an
  ancestor and no cycle to guard. Statting every directory anyway cost a
  syscall each and measured at ~20% of total walk time (18.3 ms → 15.2 ms when
  removed), all of it spent on an impossibility.

  `maxWalkDepth` (512) is a second-line backstop for platforms where identity
  is unavailable. On Windows the real identity needs an open handle and
  `GetFileInformationByHandle`; rather than guess from size and mtime,
  `fileKeyFor` reports identity *unavailable* and lets the depth cap do the
  work. That is the safe direction — a wrong "yes, seen it" silently skips a
  real directory and loses findings, while a wrong "no" only costs time.

- [x] **5.4** Roots walked concurrently, bounded by `Concurrency`
  (default `GOMAXPROCS`), each carrying its own `RepositoryIndex`.

  The visited set is deliberately **per root, not global**. Two roots can
  legitimately be the same tree — a local path that is also a configured
  repository — and each must be scanned under its own index because each
  reports to a different project. Global de-duplication would silently drop the
  second one. This is a considered departure from the design note about
  "restoring the de-duplication commented out in `FindFiles`"; the commented-out
  code would have merged those roots.

- [x] **5.5** `WalkStats` with a running `DiscoveredSoFar` and a `WalkComplete`
  flag.

  The channel is **single-slot and latest-wins**: `publishWalkStats` drains a
  stale update before posting a new one, so the walker never blocks on a caller
  that is not reading progress. A conventional buffered channel would deadlock
  the walk once it filled, obliging every caller to drain it forever;
  `TestWalkStatsIgnoredDoesNotBlock` walks 5,000 files with stats ignored
  entirely. The final update survives in the buffer after close, so a caller
  reading only at the end still gets the exact total.

- [x] **5.6** `PruneDirs` option + `CHECKMATE_PRUNE_DIRS`. The variable
  *replaces* the default set (so "prune only these" is expressible) and an
  empty value disables pruning outright.

  Resolution is split into `resolvePruneDirNames` behind the `OnceValue` cache
  specifically so it can be tested: with the cache alone, whichever test ran
  first would fix the value for the process and every later assertion would
  pass without exercising anything.

- [x] **5.7** `util.FindFiles` **removed**, and both callers
  (`SecretScanner.Scan`, `SearchSecretsOnPaths`) moved onto `WalkFiles`.

  `Scan` now streams: the first file is scanned while the walk is still
  running, instead of after the last directory has been read. `Total` becomes
  the running discovered count, clamped so it can never fall below `Position`
  (consumers divide the two and would otherwise render past 100%), plus a final
  exact event so progress cannot come to rest on a stale total. In practice the
  walker runs far ahead of the scanner, so the total is exact for all but the
  first moments. Phase 9 replaces this properly with a ticker.

  `SearchSecretsOnPaths` still accumulates a slice, because its signature
  promises the caller the full file list on `pathsOut`. It consumes the stream
  as it arrives, so it gets the latency win now; Phase 8 addresses the
  accumulation itself. `util.CollectFiles` is available for callers that
  genuinely need the whole list.

### 5.10 — The default prune set is *not* the default (correction to the design)

The design justifies the built-in prune set as

> *purely an optimisation of paths that the existing exclusion logic would
> reject per file anyway*

**That premise is false.** `diagnostics.DefaultExclusion()` excludes exactly
two things — dependency-pinning JSON (`package-lock`, `npm-shrinkwrap`,
`composer`) and web/stylesheet extensions. Nothing excludes `node_modules`,
`vendor`, `dist`, `build`, `target`, `.idea` or `.git`. Those trees are scanned
today, so pruning them is not an optimisation of a rejection that already
happens; it is a **reduction in what gets searched for secrets**, and the
findings it would remove are real ones:

- an `.npmrc` auth token under `node_modules/`
- credentials in vendored configuration under `vendor/`
- an API key baked into `dist/bundle.js` — among the most common true positives
  in practice
- `https://user:token@host` in a remote URL in `.git/config`

Pruning is therefore **opt-in**: `WalkOptions{}` prunes nothing, and the whole
engine walks with it. `DefaultPruneDirs()` and `CHECKMATE_PRUNE_DIRS` expose
the set for operators who want the ~2× walk speed-up and accept the trade,
which is a decision that belongs to whoever owns the risk, not to us.

The `PruneDirs` hook is what 6.6 will drive from the memoised exclusion
provider — pruning subtrees the operator has *actually* excluded, which is the
version of this idea that is genuinely free.

- [x] **5.8** `TestWalkFilesTerminatesOnSymlinkLoop` and
  `TestWalkFilesDeepNesting`.

  The loop test asserts more than termination: the looped directory's *own*
  content must still be discovered (a guard that refused to follow any link
  would pass a termination-only test while quietly losing files), and every
  emitted path must be unique (terminating by depth cap alone would still emit
  the same file dozens of times, multiplying findings).

- [x] **5.9** Equivalence test green — `TestWalkFilesMatchesLegacyWalk` proves
  the file set matches the legacy walk directly, and `TestScanEquivalence` /
  `TestPrefilterEquivalence` remain byte-identical against the Phase 0 golden
  baseline. Full repository suite green under `-race`.

Guards added beyond the plan:
`TestWalkFilesSingleFileRoot` (the CLI accepts a file as a root),
`TestWalkFilesMissingRootIsSkipped` (a failed clone must not cost every other
repository its findings), `TestWalkFilesDoesNotFollowLinksByDefault` (pins the
historic treatment of a symlinked directory as an ordinary entry),
`TestWalkFilesPreservesRepositoryIndex` (mis-attribution under concurrency is
silent — findings appear under the wrong repository rather than not at all),
`TestWalkFilesIdenticalRootsAreNotDeduplicated`, `TestWalkFilesPruneReceivesFullPath`,
`TestWalkStatsLatestWins`, `TestWalkFilesCancellation`, `TestFileKeyIdentity`
(both directions: same directory via a symlink yields one key, distinct
directories yield two), `TestCollectFilesOrderIsDeterministic` (ten runs — a
concurrency leak into the returned order would be intermittent), plus
`BenchmarkWalkFiles` with a legacy arm so the comparison cannot rot.

---

## Phase 6 — Gate stage

**Status: complete.** The per-file cheap checks are computed once and shared by
every path consumer instead of being recomputed by each. The two hot regexes on
that path are gone, and directory pruning is now driven by the operator's own
exclusions — but only where the prune can be *proved* sound.

| Measurement | Before | After | Change |
| --- | ---: | ---: | ---: |
| Test-file check (`BenchmarkIsTestPath`) | 1138 ns | 77.0 ns | **14.8×** |
| Whitespace check (`BenchmarkContainsWhitespace`) | 559.7 ns | 37.4 ns | **15.0×** |
| `ShouldExcludePath`, 8 patterns | 7427 ns | 7007 ns | 1.06× |
| Exclusion evaluations per file | 2 | 1 | 2× fewer |

- [x] **6.1** Per-file cheap checks extracted into a single shared gate
  (`gate.go`). `pathGate` computes extension, test-file, exclusion and
  confidential-file verdicts once; `gatedPathMultiplexer` hands the same value
  to every consumer.

  The gate is deliberately a *value carrying answers*, not a component that
  decides what to do with them. The two consumers report skipped files
  differently — different provider IDs, different payloads, different tags —
  and folding that into the gate would have changed the diagnostics the engine
  emits while looking like pure deduplication.

  Consumers keep their own `ConsumePath`, which builds a gate of its own, so
  they still work with the plain multiplexer and in isolation in tests. Sharing
  is an optimisation the multiplexer applies, not a requirement consumers
  depend on.

  `TestGateIsEvaluatedOncePerFile` is the test that matters: doing the work
  twice produces exactly the right answer, so no equivalence test can see this
  regression. Only counting the calls distinguishes a shared gate from a
  duplicated one.

- [x] **6.2** `testFile` regex replaced by `isTestPath`, 14.8× faster and
  allocation-free.

  **Not** `strings.Contains(strings.ToLower(path), "test")`, which is what the
  design specified and what the task called "exactly equivalent". It is not.
  Go's `(?i)` applies full Unicode simple case folding, so `(?i:s)` also
  matches U+017F (long s) and `(?i:.*test.*)` genuinely matches `teſt` — while
  `strings.ToLower` leaves U+017F alone. The obvious rewrite silently stops
  tagging such a path as a test file. This is the same trap the prefilter's
  seed extraction hit in Phase 4.2, and it is a false negative either way.

  `isTestPath` therefore does an allocation-free ASCII fold scan (which also
  removes the lowercased copy of every path, itself a per-file allocation) and
  falls back to the original regex when the path contains a non-ASCII byte and
  has not already matched. `TestIsTestPathMatchesRegex` differentials the two
  over ~8,000 generated paths; `TestIsTestPathHandlesUnicodeFold` pins the trap
  on its own so a future "simplification" fails with a message naming the
  reason.

- [x] **6.3** `space.FindAllStringIndex(...) == nil` and
  `space.FindStringSubmatchIndex(...)` replaced by `containsWhitespace`,
  15× faster.

  The `FindAllStringIndex` shape was the worse of the two: it built a slice of
  *every* match in the string purely to compare the result against nil. Go's
  `\s` is the Perl class `[\t\n\f\r ]` — ASCII only and, notably, **not**
  including `\v` — so an implementation written from the intuition "is this
  byte whitespace" (`unicode.IsSpace`, say) would differ on exactly one byte
  that no realistic sample would ever contain.
  `TestWhitespaceCheckMatchesRegex` compares against the regex over all 256
  single bytes and 20,000 random strings.

- [x] **6.4** ~~Take file size from the walk's `DirEntry` info; drop the
  redundant `Stat`.~~ **Premise did not survive checking — no change made.**

  The saving assumes `os.ReadDir` returns size information already paid for.
  It does not: on Unix the kernel's directory read yields name and type only,
  and `dirEntry.Info()` performs an `lstat` per entry on demand. Adopting it
  would add one syscall for *every* discovered file — including the majority
  that are excluded, pruned or of an ignored extension and never opened — to
  remove an `fstat` on an already-open handle paid only for files actually
  scanned. That is strictly more syscalls, on the larger set.

- [x] **6.5** The 512-byte sniff is no longer discarded — and fixing that
  turned out to be a **correctness fix, not an optimisation**.

  The sniff reads the first 512 bytes from the open handle to decide whether an
  extensionless file is text, and that same handle was then passed straight to
  the scanner. So every extensionless *text* file was scanned from byte 512
  onwards: its first 512 bytes were never searched for secrets at all, and
  every finding after them was reported 512 characters early — wrong line
  number, and since position feeds the finding ID, wrong finding identity too.
  Extensionless files are exactly where credentials live (`.npmrc`-style
  configuration, `credentials`, `authorized_keys`), so this was silently losing
  high-value findings.

  The handle is rewound rather than the sniffed bytes being spliced back with
  `io.MultiReader`: a rewind is one `lseek` against a handle whose first page
  is certainly still in the page cache, whereas a `MultiReader` hides the file
  size from `readAll` and pushes every extensionless file off the whole-file
  read path onto the chunked one — a far worse trade than the 512 bytes it
  saves.

  `TestExtensionlessFileIsScannedFromByteZero` fails against the previous
  behaviour, verified by reverting the seek.

  The golden baseline is **unchanged**: the Phase 0 corpus's extensionless
  fixtures happen to carry no secret within their first 512 bytes. That is luck,
  not coverage, so the new test supplies the fixture that was missing.

- [x] **6.6** Exclusion acceleration and provider-driven pruning.

  - `ShouldExcludePath` now evaluates a single pre-combined alternation instead
    of walking the compiled pattern list. Each member is wrapped in a
    non-capturing group, without which a pattern containing a top-level `|`
    would bind its alternatives to its neighbours and change meaning —
    `TestCombinedExclusionIsolatesAlternation` pins that. The loop remains as
    the fallback if the combination fails to compile, which is also what
    `TestExclusionEquivalence` differentials against.

    The gain is modest (1.06×), and the honest reason is that the cost is not
    the number of patterns but the leading `.*` in each of them. Combining is
    still worth keeping — it makes the cost independent of how large a policy a
    project accumulates — but the headline win in this phase is 6.1's halving
    of the number of evaluations, not this.

  - **The per-directory LRU was dropped deliberately, not deferred.** A
    directory-keyed memo only helps if the verdict is a function of the
    directory alone, and it is not: exclusion patterns match complete file
    paths, and the shipped defaults match on *file name and extension*
    (`package-lock.json`, `*.css`). Caching a directory's verdict and applying
    it to its files would be wrong, and caching per full path is a cache with
    no hits, since the walk visits each path exactly once.

  - Directory pruning is supplied from the provider via the new optional
    `diagnostics.DirectoryPruner` interface — optional, so no existing
    `ExclusionProvider` implementation breaks and a provider that cannot prove
    a verdict degrades to walking everything.

    **Soundness is the whole of the design here.** "This directory is excluded"
    does not imply "every file under it is excluded": a pattern matching
    `/x/build` says nothing about `/x/build/app.js`, and a bundled API key is
    among the most common true positives there is. Pruning on that basis would
    silently delete findings — the exact failure Phase 5.10 refused to accept by
    default.

    So a pruner is derived only from patterns of the form `X/.*`, where the
    implication can be *proved*: if `(?:X)$` matches directory `D`, then for any
    descendant `D/rest` the pattern `X/.*` matches, so every file beneath `D` is
    excluded and `D` can be skipped unopened. The `$` anchor is what makes the
    argument work. Everything else fails closed.
    `TestDirectoryPruneIsSound` checks the claim directly rather than trusting
    it — for every directory the pruner accepts, a set of synthesised
    descendants must all be excluded by the ordinary per-file check.

    `TestDefaultExclusionPrunesNothing` records that the shipped default policy
    prunes nothing at all. Pruning is inert out of the box and helps only
    operators who have written directory-scoped exclusions themselves, which is
    the correct default given 5.10.

- [x] **6.7** `TestExclusionEquivalence` over the fixture patterns plus ~4,000
  generated paths, with a vacuity guard so a combination matching nothing
  cannot pass by agreeing with a loop that also matches nothing.
- [x] **6.8** Equivalence green — `TestScanEquivalence` and
  `TestPrefilterEquivalence` byte-identical against the Phase 0 golden
  baseline; full repository suite green under `-race`.

Guards added beyond the plan:
`TestGatedConsumersMatchUngatedConsumers` (gated vs plain multiplexer over the
whole corpus with `ReportIgnored` on, so the skip-reporting branches are
compared too — stronger than the baseline, which compares the engine against a
recording that could itself have been re-recorded after a mistake),
`TestFileExtensionMatchesFilepathExt`, `TestDirectoryPruneRefusesUnprovable-
Patterns` and `TestDirectoryPruneAcceptsProvablePatterns` (both directions:
fail-closed is only useful if it still says yes to the shape that matters),
`TestEmptyExclusionsPruneNothing`, plus paired benchmarks
(`BenchmarkTestFileRegex`/`BenchmarkIsTestPath`,
`BenchmarkWhitespaceRegex`/`BenchmarkContainsWhitespace`,
`BenchmarkShouldExcludePath/{combined,loop}`) that keep both arms so the
comparison cannot rot.

---

## Phase 7 — Worker pool wiring

- [x] **7.1** `SecretScanner.Scan`'s sequential loop replaced by the bounded
  pipeline: walker → worker pool → sink.

  The gate is **not** a separate stage, and deliberately so. The design drew it
  as its own goroutine layer between walker and workers, but after Phase 6.1 the
  gate is four map lookups, one allocation-free substring scan and one combined
  regex — tens of nanoseconds. Handing that across a channel costs more in
  scheduling than the work itself, and a stage that cheap simply becomes a
  queue with overhead. It runs inside the worker, where it already lives
  (`gatedPathMultiplexer`), and the ordering guarantee that Phase 6 depends on
  is preserved unchanged.

  The substantive decision is that **each worker owns its consumers**. The
  obvious parallelisation — keep one consumer set, call `ConsumePath` from N
  goroutines — is wrong and silently so: `pathBasedSourceSecretFinder` holds a
  `ScanContext`, which holds two pieces of per-file mutable state (the
  aggregator collecting the current file's findings, and the `ruleGate`'s
  candidate set). Two goroutines inside it would interleave one file's findings
  into another file's aggregate and evaluate rules against the wrong candidate
  set. Neither crashes; both corrupt results. So `newScanWorker` builds a
  private consumer set per worker and each worker is single-threaded within
  itself — exactly the arrangement `ScanContext`'s doc comment anticipated in
  Phase 3. What is shared is only what is immutable: the compiled exclusion
  provider, the prefilter automaton, the vendor rule tables.

  Worker contexts are built **on receipt of the first file**, not at pool
  start. A `ScanContext` is eight provider sets and the dominant fixed cost of
  the pool; a three-file scan has no use for sixteen of them.

- [x] **7.2** Channel sizing — **the 1024 findings channel was not adopted.**

  Results are batched per file rather than streamed per finding (the callers
  need the grouping: `SearchSecretsOnPaths` subsumes overlapping findings within
  a file, `Scan` reports progress per file). A buffered result therefore holds
  one file's entire finding set, each carrying its source text when
  `ShowSource` is on — so 1024 of them is a memory commitment of a completely
  different order to 1024 individual findings, and precisely the kind of
  unbounded accumulation this change exists to remove. The results channel is
  sized `4 × workers`, which is enough to keep every worker off the sink's
  critical path while a slow consumer (a WebSocket broadcast, a database write)
  is served.

- [x] **7.3** `Workers` option + `CHECKMATE_SCAN_WORKERS`, defaulting to
  `GOMAXPROCS`. Precedence is option → environment → `GOMAXPROCS`.

  An unparseable or non-positive environment value is **ignored, not obeyed**.
  `CHECKMATE_SCAN_WORKERS=0` reaching the pool as a literal zero would create no
  workers at all, and a scan with no workers does not fail — it reports zero
  findings, which is indistinguishable from a clean codebase.
  `TestResolveWorkersNeverReturnsZero` states that invariant directly.

- [x] **7.4** `ctx.Err()` checked in the worker loop, and every send selects on
  `ctx.Done()`. Abandoning the files channel mid-flight is safe because
  `WalkFiles` already selects on the same context when emitting, so the walker
  unblocks and exits rather than leaking on a channel nobody is reading.

- [x] **7.5** `SearchSecretsOnPaths` moved onto the same pipeline, which
  removed the `fileBuffers` map and its mutex as a side effect (Phase 8.4,
  arrived at early).

  The transposition callback used to be registered as the finders' diagnostic
  consumer, so it ran on whichever goroutine was broadcasting and had to stash
  its output in a mutex-guarded map keyed by location, to be picked up again
  when the file finished. The pool returns findings already grouped by file, so
  the map, the mutex, and a latent leak all go together: a diagnostic whose
  location did not match its file's — possible, since the key was the
  *transposed* location — was never flushed and stayed in that map until the
  process exited.

- [x] **7.6** Canonical sorting before persistence.

  `SortDiagnosticsDeterministically` could not be reused: it opens on
  `RawRange.StartIndex`, a **per-file** offset that says nothing when two
  findings come from different files. It was correct while findings arrived in
  walk order, because file grouping was implied by arrival. Applied to a
  parallel multi-file result set it interleaves files by coincidence of offset
  — stable, meaningless, and looks right in a spot check.

  `diagnostics.SortDiagnosticsCanonically` sorts on location first, then
  repository index, then delegates to the existing within-file comparator
  (extracted as `diagnosticLess`, unchanged). Applied at the two persistence
  points: `projects.simpleDiagnosticConsumer.close` and the SQLite scan runner
  before the summary is computed. `SearchSecretsOnPaths` also sorts the
  returned file list, which callers treat as scan coverage.

- [x] **7.7** `TestScanCancellation` — cancels at file 25 of a 5,000-file
  corpus, asserts the pool returns, that far fewer than the whole corpus was
  scanned, and that every partial finding delivered is complete (location,
  provider ID and headline all populated). Aborting a scan is routine — a
  closed tab, a CI timeout, an evicted container — and the partial results are
  still reported, so a half-populated diagnostic would be worse than none.
  `TestScanCancellationBeforeStart` covers an already-cancelled context.

- [x] **7.8** Equivalence green — `TestScanEquivalence` byte-identical against
  the Phase 0 golden baseline; full repository suite green under `-race`.

Guards added beyond the plan:
`TestScanResultsIndependentOfWorkerCount` (the phase's core claim, pinned
across pool sizes 1, 2, 3, 8 and 64 rather than left to whatever `GOMAXPROCS`
CI happens to have), `TestScannedFileSetIndependentOfWorkerCount`,
`TestPipelineDeliversResultsSerially` (asserts the sink callback is never
entered concurrently — checked with an in-flight counter rather than left to
`-race`, so it fails deterministically instead of when the scheduler
cooperates; the WebSocket broadcaster, SSE broker, results writer and SDK
channel are all unguarded single-producer consumers),
`TestPipelineGroupsFindingsByFile` (a shared or uncleared collector would
attribute one file's secrets to another — no count changes, so equivalence
could still pass, and only the one field a user acts on is wrong),
`TestSortDiagnosticsCanonicallyOrdersAcrossFiles` and
`TestSortDiagnosticsCanonicallyIsOrderIndependent`.

Measured on the 10,000-file scale corpus (Apple M4, 10 cores):
**6,347 files/s → 25,039 files/s, 3.95×**. Peak allocation rose from 25MB to
32MB, which is the ten worker contexts and is bounded by pool size rather than
corpus size.

One behavioural note: progress is now reported as each file **completes**
rather than as it is picked up. With one file in flight the two were the same
event; with N they are not, and "started" would let `Position` run ahead of the
work actually done.

---

## Phase 8 — Streaming sinks

- [x] **8.1** `projects.simpleDiagnosticConsumer` replaced by
  `streamingDiagnosticConsumer`: NDJSON over a 256KB `bufio.Writer`, one
  document per line.

  Two defects went with it, and the second is the more serious. The slice held
  every finding of the entire scan and grew with the number of findings —
  the one quantity a security scanner has no control over. And the file was
  only *created* at close, so a crash, an eviction or a cancelled scan lost
  every finding it had already made. The file is now opened when the scan
  starts.

  `json.Encoder.Encode` already terminates each value with a newline, so NDJSON
  costs nothing to produce.

  The writer takes a mutex despite the engine delivering from a single sink
  goroutine (Phase 7): this is registered as a `SecurityDiagnosticsConsumer`,
  and that interface promises implementors nothing about threading — the git
  history scanner broadcasts on its own goroutine. A mutex is a few nanoseconds
  against a JSON encode.

- [x] **8.1a** **The sort/stream tension in the plan, resolved.**

  Phase 7.6 sorts findings canonically *before* persistence so identical scans
  produce identical output. Streaming is in direct opposition: you cannot sort
  what you have not finished receiving, and buffering in order to sort would
  reinstate precisely the accumulation 8.1 removes. The plan does not
  acknowledge that these two tasks conflict.

  Resolved by moving the sort to the **read** side. The file is written in
  arrival order; `GetScanResults` sorts canonically before returning. Every
  consumer-visible guarantee survives, because no caller reads the file
  directly. What is given up is diffing two results files with `diff`, which
  was never a supported operation. `TestScanResultsAreSortedOnRead` is what
  would catch the sort being dropped rather than moved — and nothing else
  would, since the file itself still looks perfectly well-formed.

- [x] **8.2** Format sniffing on the first non-whitespace byte (`[` → legacy
  array, `{` → NDJSON).

  Retained despite compatibility being out of scope for this change, because it
  is two lines and the failure it prevents is the dangerous kind: without it a
  stored scan decodes as an **empty set**, which renders as "no secrets found"
  — indistinguishable from a clean codebase, and giving exactly the wrong
  assurance.

- [x] **8.3** `TestLegacyScanResultsReadable` — written against an inline
  fixture rather than a committed one. A committed golden file would be
  justified if the legacy format were still being produced and could drift;
  it is not, and it cannot.

- [x] **8.4** ~~Remove the `fileBuffers` whole-scan accumulator in
  `SearchSecretsOnPaths`.~~ **Done in 7.5** — the pool returns findings already
  grouped by file, so the map and its mutex had nothing left to do.

- [x] **8.5** `TestScanResultsSurviveAbortedScan` truncates a written file
  mid-line and asserts every complete finding before the truncation is
  recovered.

  A killed scan leaves a half-written final line. That is the *ordinary* state
  of an abort, not corruption, and the reader treats it as such: failing the
  read would discard thousands of valid findings to punish the one the process
  died halfway through — turning a partial result into no result at exactly the
  moment a user most wants to see what was found. `TestEmptyScanResultsReadable`
  covers the zero-length file left by a clean scan and by one killed before its
  first flush.

- [x] **8.6** **The fixed 512MB budget on a 1M-file corpus was not adopted.**
  `TestScanSinkMemoryIsFlatInFindingCount` asserts the property instead.

  A fixed threshold measured on one machine is a poor guard: it passes on a
  developer laptop with headroom, flakes under CI memory pressure, and is then
  deleted — leaving no guard at all. The defect is not "uses more than 512MB",
  it is "grows with the number of findings". The test scales the finding count
  tenfold and requires the retained heap not to follow, which runs in 0.13s
  instead of requiring a 1M-file corpus to be materialised.

  **Verified by reintroducing the accumulator**, not merely by observing a
  green run: the retained heap went from 3.8MB at 10k findings to 38.5MB at
  100k — exactly linear — and the test failed with that message.

Remaining accumulation, identified but out of scope: `GetScanResults` still
materialises the full finding set, and `summariseScanResults` reads it back
whole immediately after every scan. That is now the peak, and reducing it means
changing the `ScanSummariser` signature to consume a stream — an API change
affecting the HTTP layer, so it does not belong in a phase about sinks.

---

## Phase 9 — Progress and repository acquisition

- [x] **9.1** Replace per-file progress with atomic counters + a 250ms ticker;
  guarantee a final 100% event.

  `progressReporter` in `progress.go`. The scan's hot path does an atomic add
  and a pointer store; a ticker goroutine turns those into events. The reason
  this matters is not the cost of the counter but the cost of the *callback*:
  it fans out synchronously to every connected WebSocket client, the SSE broker
  or the Wails JavaScript bridge, so per-file progress made scan throughput a
  function of how many browsers were watching.

  `Close` waits for the ticker to exit before emitting the final event, rather
  than merely stopping it. Otherwise a tick already in flight can land *after*
  the completion event and leave the consumer resting at 99% — which is the
  precise symptom the final event exists to prevent, occurring only on scans
  that happen to finish near a tick boundary.

- [x] **9.2** `ProgressInterval` option + `CHECKMATE_PROGRESS_INTERVAL`.

  A bare number is read as milliseconds as well as a Go duration. Operators
  write `500` far more often than `500ms`, and rejecting it would hand them the
  default while they believed they had tuned it. Unparseable and non-positive
  values fall through to 250ms: an interval of zero is per-file emission again,
  and it must not be reachable by a typo.

- [x] **9.3** **The API and cron consumers were not, in fact, unmodified — and
  the spec's claim that they would be was wrong.**

  `diagnostics.Progress` and the callback signature are unchanged, so the
  WebSocket write, the SSE broker and the Wails bridge needed nothing. But
  `pkg/api/websocket.go` and `pkg/cron/repository.go` were deriving the *file
  count* from the number of callbacks — `paths = append(paths, ...)` then
  `GenerateModel(len(paths), ...)`. Coalescing makes the number of events a
  function of the scan's duration, so a million-file scan would have been
  reported as a scan of a few dozen files, and the report's risk score,
  computed per file scanned, would have been wrong by five orders of magnitude
  while looking entirely plausible.

  Both now take the count from `Progress.Position`, which is monotonic and
  exact on the final event. This is the failure that "verify the consumers are
  unmodified" was there to catch, and it was only catchable by reading what
  each consumer did with the events rather than what type it received.

- [x] **9.4** Clones run concurrently under a semaphore-bounded `WaitGroup`
  rather than an `errgroup`.

  `errgroup` earns its keep when the first error should cancel the group. Here
  it must not: one archived or unreachable repository has always been logged
  and skipped, and cancelling the other 300 clones because one 404'd would turn
  a partial scan into no scan. `errgroup.SetLimit` with an error return that is
  always nil is just a semaphore with a misleading name, and would also have
  meant a new module dependency.

- [x] **9.5** Shallow by default — already `Depth: 1` on the project path, now
  also on the CLI path, which cloned full history it never opened. Filesystem
  secret scanning reads the working tree only; history scanning is a separate
  concern in the git service layer and asks for its own depth.

- [x] **9.6** Repositories are pipelined into the walker via
  `util.WalkRoots(ctx, <-chan IndexedRoot, opts)`. `WalkFiles` is now a thin
  wrapper that pushes a known slice onto a buffered channel and closes it, so
  its behaviour is unchanged by construction rather than by assertion.

  Local filesystem roots are published before any clone starts, so they are
  usually being scanned while the network is still working. Previously nothing
  at all was read until the last clone returned.

- [x] **9.7** `RepositoryIndex` is assigned from the project's ordered
  repository list before acquisition begins; `rootRegistry` holds each root's
  detail in an `atomic.Pointer` slot filled before that root is published.

  `TestTransposeIsIndependentOfAcquisitionOrder` fills the registry forwards and
  backwards and requires identical output. Completion-order indices would
  attribute findings to whichever repository cloned fastest — varying run to
  run with network weather, and undetectable in the output, because both
  attributions look correct.

  **This also fixed a live defect on the CLI path.** `SearchSecretsOnPaths`
  built the transposer from one iteration of a `map[string]repoCloneAndDetail`
  and the walk roots from a *second, independently randomised* iteration of the
  same map. Whenever the two disagreed — which Go makes likely, not
  hypothetical, with more than one repository — findings were transposed
  against the wrong repository. `determineAndCloneRepositories` is gone;
  `acquirePaths` indexes by the caller's argument position.

- [x] **9.8** `CloneConcurrency` option + `CHECKMATE_CLONE_CONCURRENCY`,
  default 4. Deliberately not higher: the other end is somebody else's Git
  server, and a scan opening a few hundred simultaneous clones against it is
  operationally indistinguishable from an attack.

- [x] **9.9** (unplanned) Fixed a latent panic in the walker exposed by this
  phase. On cancellation `WalkFiles` returned from the middle of its dispatch
  loop and its deferred `close(files)` ran while walkers were still sending on
  that channel — a send on a closed channel, and therefore a crash, but only
  when the timing lined up. The wait now precedes the close.
  `TestWalkRootsSurvivesCancellationMidFlight` cancels mid-stream across 64
  concurrent roots.

**Verified by mutation, not just by a green run.** Reinstating a per-file
`emit` inside `FileDone` makes `TestProgressIsCoalesced` fail with
"emitted 100007 events for 100000 files" — the bound is loose (50 events for
100k files) precisely so it is about coalescing and not about tick timing, and
it still fails by three orders of magnitude.

---

## Phase 10 — Validation, documentation, archive

- [x] **10.1** Full equivalence run across the whole corpus, prefilter on and
  off — green. `TestScanEquivalence`, `TestPrefilterEquivalence`,
  `FuzzPrefilterSoundness`, `TestLineIndexDifferential` and the determinism and
  canonical-ordering suites all pass.
- [x] **10.2** Full suite green under `-race` — all 12 packages.
- [x] **10.3** Final benchmark numbers recorded in `baseline.md`. **Seven of the
  eight performance targets are met; one is accepted as unmet.**

  Met, and by a wide margin: throughput **27×** against a target of 10×
  (873 → 23,572 files/s on 50k files), allocations per file 970 → 22.7, total
  allocated 5.04 GB → 132 MB, peak heap flat in the file count (35 MB at 50k
  files, 735 B/file and falling).

  Not directly instrumented: CPU utilisation ≥ 80% of configured workers. The
  27× speed-up on a 10-core host is consistent with it, but that is inference,
  not measurement.

  **Now measured, in 10.5.** A real 22,542-file scan runs at **656% CPU on a
  10-core host** (`user 640s` over `real 97s`), against a target of ≥ 80% of
  configured workers. Target met, and no longer by inference.

  **Failing: the `< 1s` bound on adversarial single-line inputs.**
  `oneline-json-4mb` takes 22.9s and `base64-blob-2mb` takes 89.1s. A CPU
  profile puts 94.95% of the time in `isVendorSecret`, reached from
  `detectSecret`.

  **Update after Phases 11 and 12:** 8.27s and 5.19s respectively — 6.5× and
  28× better — but the bound is still not met. Both are now dominated by the
  *generic* rules' own regexes over multi-megabyte content, which carry no
  prefilterable literal and represent real detection work rather than waste.
  Closing the last gap requires a detection or coverage change; see the
  Phase 12 entry and `baseline.md`. **This is now a product decision, not an
  outstanding defect.**

  Phase 4 gated the vendor *finders* behind the prefilter, but `detectSecret`
  runs a **second, ungated vendor classification** over each candidate secret
  string — every vendor regex, in full. On these fixtures that string is the
  whole multi-megabyte blob, so several hundred automata each sweep it.

  This predates the change (the baseline was 148s) and no ordinary file reaches
  it. It is nonetheless a denial-of-service surface: one committed minified
  bundle can hold a scan for ninety seconds.

  It is deliberately **not** fixed here. The cheap fix — capping the length
  passed to the vendor rules — changes detection, dropping a real token
  embedded in a large value from Critical vendor confidence down to the entropy
  branch. That is a coverage change and must be made deliberately, not smuggled
  into a validation phase. The principled fix is to feed the gate's existing
  candidate set into `detectSecret`, which preserves results exactly but
  requires threading `ScanContext` through `secretStringFinder.Consume`.

  **Resolved by Phase 11** (the gate reached classification without a length
  cap) **and Phase 12** (the quadratic overlap resolution behind the remaining
  fixture). The `< 1s` bound on multi-megabyte single-line inputs is
  **accepted as unmet** and recorded as a known limitation: what remains is the
  generic rules doing real detection work on pathological input, and closing it
  would require a coverage change. Owner decision, 2026-08-09.

- [x] **10.4** SDK, CLI, API and report-format compatibility verified —
  **all compatible except one documented plugin-API break.**

  Checked mechanically rather than by inspection, by diffing the exported
  surface against a `git worktree` of the pre-change tree:

  | Surface | Method | Result |
  | --- | --- | --- |
  | `pkg/sdk` public API | `go doc -all` diff vs HEAD | identical |
  | REST/WS routes | `HandleFunc` diff vs HEAD | identical |
  | CLI flags | flag-registration diff vs HEAD | identical |
  | Storage schema | `git status` on `migrations/` | unchanged |
  | SARIF 2.1.0 | generated and parsed | valid; `partialFingerprints` present |
  | PDF | generated | 206KB, `%PDF-1.4` |
  | JSON | generated | unchanged shape |

  Behaviour, not just shape: the SDK (`ScanPath`, `ScanStream`,
  `ScanStreamWithProgress`) and the `/api/findsecrets` endpoint — which is the
  one API caller of the changed `GetFinderForFileType` — both return the
  expected findings, and SDK output is byte-stable across three independent
  processes.

  **The break: `pkg/plugin/secrets-finder/pkg` constructor signatures.**
  `GetFinderForFileType` and all seven `New*Finder(s)` constructors lost their
  `rif util.RepositoryIndexedFile` parameter in Phase 1.2/1.3, because
  capturing per-file state at construction is exactly what prevented finder
  reuse. This is the intended change, and it is not reachable from the SDK, the
  CLI, the API or the report formats — but it *is* an exported surface, so
  claiming blanket compatibility would have been false.

  The spec's compatibility list names the SDK, CLI, API, reports and storage,
  and does not cover the plugin package, so this is within scope as written.
  Recording it because "no caller in this repo" is not the same as "no caller":
  anyone embedding the finder constructors directly gets a compile error — loud,
  immediate, and trivially fixed by deleting the argument. Noted in the spec's
  compatibility section rather than left implicit.

- [x] **10.5** `checkmate-app` (Wails) verified end-to-end against a large
  project.

  **First attempt was a false pass and is worth recording.** `go build ./...`
  in `checkmate-app` succeeded immediately — because the app depends on the
  *published* `github.com/adedayo/checkmate v1.3.3`, not this working tree, so
  the build proved only that v1.3.3 still compiles. Re-run with
  `go mod edit -replace` pointing at the local tree, confirmed via
  `go list -m` that the replacement was actually in effect, then built and
  tested: both green. `go.mod`/`go.sum` restored afterwards.

  End-to-end behaviour was then exercised through the same path the app's
  `StartScan` uses — the sqlite `PlatformStore`'s `RunScan` with a
  `SecretScanner`, an SSE broker subscription standing in for the Wails event
  bridge, and a read-back through `GetIssues` for the findings table — against
  a real 22,542-file dependency tree:

  | Measure | Result |
  | --- | --- |
  | Wall clock | 1m37s |
  | CPU utilisation | **656%** on a 10-core host |
  | Findings | 11,575 (11 critical, 2,060 high, 9,504 medium) |
  | Streamed to UI | 11,575 — every finding reached the event bridge |
  | Read back from store | 11,575 |
  | Peak heap | 139 MB |
  | Persisted `file_count` | 22,591 |

  The 656% figure also settles the one performance target 10.3 recorded as
  *inferred rather than measured*: CPU utilisation ≥ 80% of configured workers.

  Correctness on this corpus, which is far more adversarial than the synthetic
  one because it is full of real minified bundles:
  - byte-identical across 3 independent processes;
  - byte-identical with the prefilter on and off (`CHECKMATE_DISABLE_PREFILTER=1`);
  - byte-identical at `CHECKMATE_SCAN_WORKERS` of 1, 10 (default) and 32.

  **Pre-existing defect found, not caused by this change and not fixed here:**
  a scan driven through the sqlite store reports `fileCount: 0` in the
  WebSocket scan summary. `sqlite.RunScan` accepts a `progressMonitor` and
  never calls it, so the API's progress-derived file count stays zero. Verified
  against HEAD (`grep -c "progressMonitor("` → 0), where the previous
  `len(paths)` counter was fed by the same never-called callback and was
  therefore also zero. The *persisted* `file_count` is correct (22,591), since
  it comes from the paths channel rather than from progress. This change
  improved the counter it touches — counting coalesced progress events would
  now under-report by orders of magnitude, so it reads `Position` instead — but
  the sqlite path never delivers progress at all. Filed as a follow-up rather
  than fixed inside a validation phase.

- [x] **10.6** `docs/features.md` and `docs/testing.md` updated.

  `features.md` gains a "Scan Engine Performance & Tuning" section: the five
  environment variables with defaults and precedence, the equivalent
  `SecretSearchOptions` fields, and an explicit statement that tuning cannot
  change results, with the tests that enforce it. `CHECKMATE_PRUNE_DIRS` gets
  its own subsection, because it is the one knob that *does* trade coverage for
  speed and the reason it is off by default is not self-evident.

  `docs/testing.md` gains a "Testing the Scan Engine" section covering the
  reference corpus and canonicalisation, the three distinct equivalence
  properties and why golden-baseline comparison alone is insufficient, the
  prefilter's soundness fuzzing, the differential-against-previous-
  implementation pattern with its two failure modes (vacuous random inputs;
  unverified tests), cross-process determinism checking, and the benchmark
  methodology including the `CHECKMATE_PERF_BASELINE` gate.

- [x] **10.7** "Performance & Large Codebases" section added to `README.md`:
  the tuning table, the finding-identity guarantee, the pruning trade-off with
  a copy-pasteable command, and a pointer to `docs/testing.md`.

- [x] **10.8** `openspec/project.md` updated: `scan-engine` added to the
  accepted-capability list, active change cleared, and the detection-engine
  entry corrected — it claimed the engine lived in the external
  `github.com/adedayo/checkmate-plugin/secrets-finder` module when it is in
  fact in-repo at `pkg/plugin/secrets-finder/`, which is the tree this change
  modified. Two guardrails added, since they are the invariants a future agent
  is most likely to break: performance work must be finding-identical (with
  coverage changes called out as product decisions), and scans must be
  deterministic under parallelism.

- [x] **10.9** Merge `specs/scan-engine/spec.md` into `openspec/specs/` and move
  this change folder to `openspec/archive/`.

  **Decision (owner, 2026-08-09): option 1 — the exception is accepted.**
  The offset-dependence difference is recorded as a second documented exception
  to the governing invariant and the change is archived on that basis.

  Recorded plainly because it is the one place this change departs from its own
  standard of proving rather than arguing equivalence:

  - The difference is **real and reproducible** on real input (49 lost, 29
    gained of 11,595) and under a controlled 400-byte shift of a single file.
  - The **mechanism is inferred from correlation, not proved**. Two synthetic
    reconstructions failed to reproduce it.
  - **No regression test covers it.** `chunkboundary_test.go` states the
    property but passes against the pre-change engine too, so it guards the
    future rather than evidencing the past.
  - Severity is low on inspection: no Critical, no vendor rule, and the four
    lost High findings are heuristic false positives on comment text.

  Accepted on the grounds that the new behaviour is offset-independent and so
  strictly better-defined than the old, and that nothing of value is lost.

  **Follow-ups raised, neither blocking:**
  - `004-chunk-boundary-minimisation` — bisect the known reproducer
    (`css-select/.../filters.js`) to a minimal committed fixture and promote
    `chunkboundary_test.go` to a real guard. Until then the exception rests on
    a correlation.
  - `005-sqlite-progress-reporting` — `sqlite.RunScan` never invokes its
    `progressMonitor`, so the WebSocket scan summary reports `fileCount: 0`.
    Pre-existing, verified at HEAD.

  **What was found.** Against the pre-change engine: 49 findings lost, 29
  gained, out of 11,595. One difference is the pre-change engine's own
  nondeterminism — it is *not stable against itself* on this corpus, differing
  between two runs on `@babel/code-frame/package.json`, which is defect D3/D4
  surviving in the wild. The other 53 are stable and caused by this change.

  **What it is confined to.** Every one of the 33 affected files is larger than
  4,096 bytes, the old `dataChunkSize`. None of the 18,123 files at or below
  4KB differs. A controlled shift — moving a matching region from offset 4,327
  to 3,927 by deleting 400 bytes earlier in the same file — flips the
  pre-change engine's output and not the current engine's. So the old engine's
  results depended on byte offsets relative to a buffer boundary, and the new
  one's do not.

  **Severity.** No Critical and no vendor-rule finding is affected — those match
  on mandatory literals well inside a line. All differences are in the generic
  heuristics. The four lost High-confidence findings were each inspected and are
  false positives on comment text (e.g. `decimal.js:2330`, the comment
  `// naturalLogarithm(x). Example of failure without these extra digits`).
  `findingID` changes for affected findings, since identity includes position,
  so stored findings in those files re-key on the next scan.

  **What is not established.** The mechanism is inferred from the correlation,
  not proved. Two synthetic reconstructions — 50 cases sweeping a straddling
  secret across the seam, and 11 cases reproducing the exact shape of the file
  examined in detail — both showed *zero* divergence between engines.
  `chunkboundary_test.go` keeps the property as a forward-looking guard, but it
  passes against the pre-change engine too, so it is not evidence for this
  difference and its file comment says so plainly.

### The corpus gap this exposed

Worth keeping visible after archive: nine phases of equivalence testing did not
find this, and one scan of a real dependency tree did, within minutes. Every
reference-corpus fixture except the adversarial ones is under 4KB, so no
fixture contained a read-buffer boundary at all; the adversarial ones do, but
they are single-line by construction and are asserted on for time rather than
content. The missing shape — a multi-line file over 4KB — is the commonest
shape in real code.

The general lesson is not "add a bigger fixture". It is that a corpus designed
to cover *code paths* can silently fail to cover *input shapes*, and
equivalence testing is only ever as strong as the corpus's diversity. Scanning
a real dependency tree is now part of the documented validation routine
(`docs/testing.md`) for that reason.

**10.3 was the gate on 10.9** — the change could not be archived claiming R5
while a second, ungated evaluation of the same rule set existed. Phase 11
closed it.

---

## Phase 11 — The ungated vendor classification path

Opened by the Phase 10 validation run. Spec: **R5** (extended) and the new
**R5a — Bounded classification cost**.

### The defect

`detectSecret` classifies each candidate secret by calling `isVendorSecret`,
which runs **every** vendor regex over the candidate with
`FindStringSubmatchIndex`. Phase 4 gated the vendor *finders*; it did not gate
this. The rule set is therefore prefiltered when discovering secrets and
exhaustive when describing them, and the worst case is set by the ungated path
— so the prefilter currently buys nothing at all on adversarial input.

Measured: `base64-blob-2mb` spends **94.95% of 74s** in `isVendorSecret`, 98% of
all samples inside `regexp.(*machine)`. `oneline-json-4mb` is the same shape at
22.9s. Both bounds are `< 1s`.

The exposure is not merely slow scans. The input is attacker-controlled
wherever an attacker can commit a file: a single 2MB base64 asset — entirely
ordinary in a repository, and not itself suspicious — stalls a scan for ninety
seconds, and a handful of them exhaust a scanning window.

### Approach

Thread the existing per-worker `ruleGate` into classification, so the same
candidate set already computed for the file also gates `isVendorSecret`. This
is a **pure performance change: it must be finding-identical**, and that is
what makes it the right fix rather than a length cap.

All three `detectSecret` call sites already hold a `secretFinder`, which
already carries `gate` and `gateIndex` — so nothing new has to be plumbed
through the multiplexer. This is a smaller change than the Phase 10 note
assumed; the plumbing objection recorded there was wrong.

- [x] **11.1** Gate added to `secretContext`, passed from all three
  `detectSecret` call sites (`processAssignment`, `processString`,
  `processXMLAssignment`). A nil gate behaves exactly as before, which is what
  `Test_detectSecret` and any direct caller gets.

  **The gate also had to be attached to more finders than Phase 4 attached it
  to.** `NewScanContext` wired it only into `*secretStringFinder`, on the
  reasoning that the generic assignment and XML finders are not vendor rules
  and would always run anyway. True for rule *discovery* — but those finders
  are exactly the ones that call `detectSecret` on the values they find, so
  leaving them without a gate left the expensive path ungated. Replaced with a
  `gatedFinder` interface implemented by the embedded `secretFinder`, so every
  finder carries it; `gateIndex` still resolves to -1 for the non-vendor
  finders and their own execution is unaffected.

- [x] **11.2** `isVendorSecret` takes a `*prefilter.Set` and skips rules
  outside it, iterating `sortedVendorSecretIDs` as before. Indices are
  precomputed once, positionally aligned, rather than looked up by description
  per rule per candidate.

- [x] **11.3** **The folding hazard is real, so the file-level candidate set is
  not reused.**

  The plan's first option — pass the set already computed for the file — is
  unsound. `detectSecret` classifies `strings.ToLower(candidate)`, which is
  Unicode-aware, while the automaton folds ASCII only. U+212A KELVIN SIGN
  lowercases to an ordinary ASCII `k` that the automaton never saw when reading
  the raw file, so a rule seeded on a literal containing `k` could match the
  lowered value while being absent from the file's candidate set. That is
  under-admission — the one error the prefilter must never make, because it
  loses findings in silence.

  The gate instead makes its own automaton pass over the exact string the
  regexes will receive. That removes the argument rather than relying on it,
  and costs one linear pass per candidate against the hundreds of full regex
  evaluations it replaces. `TestClassificationGateUsesTheClassifiedString`
  pins the hazard so the cheaper design cannot be reintroduced by someone who
  reasons only about substrings.

  A second `prefilter.Set` was needed for this, not a shared one:
  classification happens *between* a file's finder invocations, so sharing
  would let one classified value overwrite the file's candidates and skip every
  vendor rule for the rest of the file.
  `TestClassificationGateSetIsIndependentOfFileSet` covers it.

- [x] **11.4** `TestVendorClassificationGatingIsSound` over a curated candidate
  list, plus `FuzzVendorClassificationGating`. **163,473 executions, no
  divergence.** Both assert the description *and* the boolean: a gated run
  returning `false` where the ungated run named a vendor would still report the
  finding, only downgraded from Critical to the generic entropy branch — which
  is precisely the kind of failure that does not look like one.

- [x] **11.5** `isCommonSecret` and `isEncodedSecret` left alone. Both are
  small rule sets and neither appears in the profile after 11.2; changing them
  would be speculation.

- [x] **11.6** **One bound met, one not — and the reason has changed.**

  | Fixture | Before | After 11.2 | Bound |
  |---|---|---|---|
  | `base64-blob-2mb` | 89.1s | **4.67s** | < 1s |
  | `oneline-json-4mb` | 22.9s | **25.9s** | < 1s |
  | `minified-10mb` | 1ms | 47ms | < 1s |

  `base64-blob-2mb` improved 19×, and `isVendorSecret` has left the profile
  entirely (0.32s of 21s, 1.5%). The vendor classification defect is fixed.

  `oneline-json-4mb` did not move, because it was never dominated by the vendor
  path. A fresh profile puts **71.25% in `core.removeOverlappingIssues`**, with
  a further 11.6% in `CharRange.Contains` called from it. That function is
  **O(n²) in the number of findings in a single file**: the fixture yields on
  the order of 80,000 candidate findings from its 4MB of repeated
  `"value":"0123456789abcdef"`, which subsume down to 2. Eighty thousand
  squared is 6.4×10⁹ range comparisons.

  This is a different defect in a different package, with the same shape of
  consequence — a single attacker-supplied file holding a scan — and
  `diagnostics.SubsumeOverlapping` has the same quadratic structure. Fixing it
  means replacing a positional, first-match-wins double loop with a sweep,
  which must be proved finding-identical including its tie-breaks. That is not
  a footnote to the vendor path.

  **Deferred to Phase 12 — quadratic overlap resolution.**

- [x] **11.7** Equivalence corpus byte-identical with the prefilter on and off;
  `TestVendorSecretEvaluationOrderIsSorted` extended to assert the gated and
  ungated winners agree; full repository suite green under `-race`. **The
  finding set is unchanged**, which is the whole claim.

- [x] **11.8** Recorded in `baseline.md`. Phase 12 closed the remaining fixture;
  10.3 is resolved, with the `< 1s` adversarial bound accepted as unmet.

### Explicitly rejected

Capping the length of the string passed to the vendor rules. It is one line and
it would work, but it silently changes detection: a real `ghp_…` token embedded
in a large value would stop matching the GitHub rule and fall through to the
entropy branch, losing Critical confidence — a genuine secret quietly
downgraded. The gate delivered the bound without it, so the question does not
arise.

---

## Phase 12 — Quadratic overlap resolution

Opened by the Phase 11 measurement. Spec: **R5a — Bounded classification cost**
(the same denial-of-service property, a different mechanism).

`core.removeOverlappingIssues` and `diagnostics.SubsumeOverlapping` both
compare every finding in a file against every other. On ordinary files, where a
handful of findings share a file, this is free and the simplicity is worth
having. On a file that produces tens of thousands of candidates — one
long minified or serialised line does exactly that — it is the dominant cost of
the entire scan: 71% of a 26-second scan of one 4MB file.

- [x] **12.1** Counts measured, not inferred. The `oneline-json-4mb` fixture
  produces **83,888 findings in a single file**, which subsume down to 2. That
  is 7.0×10⁹ range comparisons in the double loop.

- [x] **12.2** **The double loop was not actually order-dependent, which is
  what made an exact replacement possible.**

  It looks order-dependent — there is a `break` in it, and the surrounding
  comments (correctly) stress that the surviving finding must not depend on
  arrival order. But the `break` only ends the search early; every qualifying
  `dj` writes the same value, and exclusion is decided against the *original*
  set rather than the surviving one, so it does not cascade. The predicate is
  purely existential:

      exclude di  ⟺  ∃ dj ≠ di :  dj ⊇ di  ∧  conf(di) ≤ conf(dj)  ∧  di ⊉ dj

  Because `Contains` is inclusive, the last two clauses together mean exactly
  "dj properly contains di" — equal ranges contain each other, so neither
  excludes the other, which is what preserves genuine duplicates.

  Splitting on the start index gives two cases answerable from a running
  maximum instead of a scan: an earlier-starting finding reaching at least as
  far, or an equal-starting one reaching strictly further. The findings are
  already sorted by start, so one pass carrying "largest end seen so far, per
  confidence level" decides both. Confidence has five values, so "at least this
  confident" is a five-element loop.

  **O(n) after the sort the function already performed.** The sort is now
  load-bearing twice: for determinism, and for the sweep's precondition.

- [x] **12.3** `TestRemoveOverlappingIssuesDifferential` keeps the original
  implementation in the test file as the specification and compares against it
  over **3,000 randomised trials**. Ranges are drawn small and dense (offsets in
  [0,24), spans 0–5) so that identical ranges, nested ranges, shared endpoints
  and equal confidences actually occur — sparse random ranges rarely contain one
  another and would make the test vacuous while looking thorough.

  Plus eight hand cases for the boundaries, including the one a naive sweep gets
  wrong: *containment is judged against the original set, not the survivors*. In
  `outer ⊃ mid ⊃ inner`, `mid` is excluded by `outer` but must still exclude
  `inner`; a sweep consulting only survivors would keep `inner`.

  **Verified by mutation.** Relaxing case B's strict inequality to `>=` fails
  the differential on trial 0 and four hand cases, including a single finding
  excluding itself.

- [x] **12.4** `oneline-json-4mb`: **25.9s → 8.27s**. `removeOverlappingIssues`
  is gone from the profile entirely.

  **The `< 1s` bound is still not met, and the remaining cost is not waste.**
  87% of the time is now inside the two generic finders' own regexes
  (`secretStringFinder.Consume` 62%, `assignmentFinder.Consume` 25%) evaluating
  4MB of content. Those rules are generic by construction — an unbroken string,
  an assignment — so they carry no literal for the prefilter to seed on and
  cannot be gated. This is the engine doing the work it exists to do.

  Getting below 1s from here requires either faster generic patterns or a cap
  on per-file scanning work, and the latter is a coverage change. Neither is a
  bug fix, so neither is done unasked.

  Equivalence corpus byte-identical; full suite green under `-race`.

- [x] **12.5** Recorded in `baseline.md`.

### Not changed: `diagnostics.SubsumeOverlapping`

It has the same O(n²) shape, and unlike `removeOverlappingIssues` its loop is
*genuinely* positional — it mutates `subsumed[j]` as it goes, breaks on
self-subsumption, and has an explicit `i < j` tie-break — so the same rewrite
would not be equivalent. It also does not appear in any profile, because
aggregation runs first and hands it an already-reduced set (2 findings, not
83,888). Left alone deliberately: the quadratic term is real but unreachable at
scale on current call paths, and rewriting it would risk the finding-identity
guarantee for no measured gain.
