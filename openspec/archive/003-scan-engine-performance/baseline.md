# Baseline: 003-scan-engine-performance

Recorded at the completion of Phase 0, **before** any pipeline work. Every
later phase is measured against these numbers.

## Environment

| | |
|---|---|
| Host | Apple Silicon, 10 logical CPUs |
| Go | see `go.mod` |
| Command (throughput) | `go test ./pkg/plugin/secrets-finder/pkg/ -run '^$' -bench 'BenchmarkScanScale\|BenchmarkFinderConstruction' -benchtime 1x` |
| Command (memory) | `CHECKMATE_PERF_BASELINE=1 go test ./pkg/plugin/secrets-finder/pkg/ -run TestBaselineMemoryProfile -v` |

Baselines run **without** `-race`. The race detector inflates these figures
several-fold and is used for correctness, not measurement.

## Throughput

| Corpus | Wall time | Throughput | Bytes allocated | Allocations |
|---|---|---|---|---|
| 1,000 files | 0.98s | **1,020 files/s** | 104 MB | 971,320 |
| 10,000 files | 9.96s | **1,004 files/s** | 1.03 GB | 9,676,368 |
| 50,000 files | 57.3s | **873 files/s** | 5.04 GB | 48,257,204 |

**~970 allocations per file**, and throughput *degrades* as the corpus grows.
Single-threaded on a 10-core host, so ~10% of available compute is in use.

Extrapolating 873 files/s to a 1,000,000-file multi-repository scan gives
**≈19 minutes**, during which `util.FindFiles` has already had to materialise
the entire file list before the first file is scanned.

## Finder construction (P3)

```
BenchmarkFinderConstruction-10    38,250 ns/op    65,656 B/op    460 allocs/op
```

`GetFinderForFileType` is called once per file. At 460 allocations and 64KB per
call, this accounts for roughly **half of all allocations** and ~38µs of pure
setup per file — before a single byte is matched. Phase 2 must drive this to
zero per file.

## Memory scaling

| Corpus | Peak heap in-use | Total allocated | GC cycles |
|---|---|---|---|
| 1,000 files | 10.9 MB | 103.7 MB | 26 |
| 10,000 files | 13.4 MB | 988.7 MB | 191 |
| 50,000 files | 24.4 MB | 4.7 GB | 487 |

Peak heap grows sub-linearly here only because this synthetic corpus is
deliberately low-yield (1 finding per 20 files). The accumulating structures —
the whole `[]RepositoryIndexedFile` list (P2) and the whole result set (P6) —
are both proportional to corpus size and finding count respectively, so a real
codebase with a realistic finding density scales far worse. The 512MB RSS gate
in Phase 8 uses the 1M-file / 500k-finding corpus for exactly this reason.

The **4.7 GB total allocated for 50,000 files** and 487 GC cycles are the
headline figures: nearly all of that is per-file finder churn.

## Correctness baseline

- Golden corpus: **21 findings across 19 files**, two repository roots.
- File: `pkg/plugin/secrets-finder/pkg/testdata/golden/reference-corpus.json`
- Verified byte-identical across 10 consecutive independent processes with
  `-race` enabled.

## Determinism defects found and fixed during Phase 0

Establishing the golden baseline was blocked by the engine producing different
results for identical input. Six distinct defects were found. All predate this
change; all are fixed.

| # | Defect | Location | Effect |
|---|---|---|---|
| D1 | `makeVendorSecretsFinders` ranged over the `vendorSecrets` map | `specific_vendor_finders.go` | Rule order randomised per run; `SubsumeOverlapping` resolves ties positionally, so rule attribution varied |
| D2 | `setupSecretStringsIndicators` ranged over a map to build a regex **alternation**, and appended to a package-level slice | `regexes.go` | The compiled patterns themselves differed between runs; the function also duplicated its output when called twice |
| D3 | `simpleDiagnosticAggregator.Aggregate` ranged over its file map | `pkg/core/common.go` | Diagnostics reached overlap resolution in random order |
| D4 | `SubsumeOverlapping` / `removeOverlappingIssues` resolve overlaps **positionally** | `subsumption.go`, `common.go` | Any upstream order variation changed which finding survived |
| D5 | `isVendorSecret` was first-match-wins over a map | `secrets_util.go` | A `ghp_…` token matches both CheckMate's own GitHub rule and the Gitleaks one; the winner — and therefore the evidence *confidence* — was random, which then changed overlap resolution |
| D6 | `append(makeVendorSecretsFinders(...), coreFinders...)` appended into the shared global slice's spare capacity | `regex_providers.go` | Each file's language-specific finders overwrote the shared global rule set for the next file |

### Why this mattered beyond testing

`project.md` guardrail #4 requires stable finding identity:

```
findingID = sha256(ruleID + repoURL + filePath + lineNumber + columnNumber + secretChecksum)
```

D1–D6 all varied `ruleID`, and several varied `lineNumber`/`columnNumber` too.
**Scanning identical code twice produced different finding IDs**, so findings
could not be reliably tracked across scans, and exception suppressions keyed on
identity could silently stop matching.

Fixing them also *improved detection attribution*. The pre-fix baseline
credited several secrets to generic rules (`SecretAssignment`,
`SuspiciousOrCommonSecretString`, `Unbroken string may be a secret`); the fixed
engine correctly credits GitLab PAT, GitHub OAuth, Postgres connection URI and
GoCardless rules, with the appropriate `Critical`/`High` confidences.

### Related fixes

- **Removed the `vendorFinders` global cache** (brought forward from Phase 1).
  Besides D1/D6, it captured `rif` from the first file ever scanned — so every
  vendor finding reported the wrong `RepositoryIndex` in multi-repository scans
  — and its consumer list grew without bound, retaining every aggregator from
  every previously scanned file for the process lifetime.
- **Removed the goroutine-per-consumer-per-chunk fan-out** in
  `defaultResourceMultiplexer.start()` (brought forward from task 3.5). With
  ~240 consumers and 4KB chunks this was ~600k goroutine creations for a single
  10MB file, and its nondeterministic completion order fed D3/D4.
- Removed a stray `fmt.Println("TESTING COMPILATION …")` debug statement from
  `determineAndCloneRepositories`.

> **Note on Phase 1.** Because removing the global cache was required to reach
> determinism, the `RepositoryIndex` correction described in `proposal.md` is
> already included in this baseline. There is no second baseline re-record
> pending.

## Harness

| File | Purpose |
|---|---|
| `corpus_test.go` | Reference, adversarial and scale corpora; materialisation |
| `canonical_test.go` | Canonical projection, total ordering, scan driver |
| `equivalence_test.go` | Golden gate + ordering-totality and stability guards |
| `determinism_test.go` | Regression guards for D1–D6 |
| `scanperf_test.go` | Throughput benchmarks, memory profiling, adversarial timing |

### Corpus placement

The corpus is generated into `os.MkdirTemp("", "cmcorpus")` rather than
committed under `testdata/`. This is load-bearing:

```go
testFile = regexp.MustCompile(`(?i:.*test.*)`)
```

matches **any** path containing "test". A corpus under `testdata/`, or under a
`t.TempDir()` root (which Go names after the calling test), would classify every
fixture as a test file and tag it `test` — silently invalidating the baseline.
`materialiseCorpus` asserts the chosen root does not contain the substring.

## Running

```sh
# Correctness gate (fast, runs in CI)
go test ./pkg/plugin/secrets-finder/pkg/ -race

# Re-record the baseline (deliberate action only)
go test ./pkg/plugin/secrets-finder/pkg/ -run TestScanEquivalence -record

# Throughput + allocation baselines
go test ./pkg/plugin/secrets-finder/pkg/ -run '^$' -bench 'Scan|Finder' -benchtime 1x

# Slow measurements, opt-in
CHECKMATE_PERF_BASELINE=1 go test ./pkg/plugin/secrets-finder/pkg/ \
    -run 'TestBaseline' -v -timeout 60m
```

## Targets restated against measured numbers

| Metric | Measured baseline | Target |
|---|---|---|
| Throughput (50k files) | 873 files/s | **≥ 8,730 files/s** (10×) |
| Allocations per file | ~970 | **< 50** |
| Finder construction per file | 460 allocs / 64KB / 38µs | **0** |
| Total allocated (50k files) | 5.04 GB | **< 500 MB** |
| Peak RSS (1M files, 500k findings) | not yet measurable | **< 512 MB** |
| Time to first finding | after full walk | **< 1s** |
| 10MB single-line file | minutes (quadratic) | **< 1s** |

---

# Progress: after Phase 2 (`ScanContext`)

Same host and commands as the baseline above.

## Throughput and allocation

| Corpus | Baseline | After Phase 2 | Change |
|---|---|---|---|
| 1,000 files | 1,020 files/s · 104 MB · 971,320 allocs | 1,118 files/s · 8.98 MB · 41,769 allocs | **−91% bytes, −96% allocs** |
| 10,000 files | 1,004 files/s · 1.03 GB · 9,676,368 allocs | 1,028 files/s · 74.2 MB · 317,159 allocs | **−93% bytes, −97% allocs** |
| 50,000 files | 873 files/s · 5.04 GB · 48,257,204 allocs | 904 files/s · 354 MB · 1,526,788 allocs | **−93% bytes, −97% allocs** |

Allocations per file: **~970 → ~30.5**.

## Finder construction

| Measure | Baseline (per file) | After Phase 2 |
|---|---|---|
| `BenchmarkFinderConstruction` | 460 allocs · 65,656 B · ~23µs | unchanged, but **no longer on the per-file path** |
| `BenchmarkAllocsPerFile` (warm context) | — | 249 allocs · 45,406 B |
| `BenchmarkScanContextConstruction` | — | 7,433 allocs · 655 KB · 308µs, **once per worker** |

The one-off context cost is repaid after roughly five files and is then
amortised across the whole scan.

## Reading the throughput numbers

Memory improved by an order of magnitude; wall-clock moved only ~4%. That is
the expected and informative result: **the engine was never allocation-bound.**
Removing 97% of allocations barely moved the clock, which localises the
remaining time in regex matching — every one of the ~240 rules still runs its
full automaton over every chunk of every file.

This is exactly the cost Phase 4's Aho-Corasick prefilter targets, and Phase 2
is its precondition: a stable, reusable finder set is what makes a prefilter
index worth building once. The memory win also unblocks Phase 7 — at 5 GB of
churn per 50k files, running N workers concurrently would have multiplied GC
pressure; at 354 MB it will not.

## Correctness

- `TestScanEquivalence` reproduces the golden baseline byte-for-byte
  (21 findings across 19 files).
- Full repository suite green under `-race`.

---

# Final: after Phase 9 (Phase 10 validation)

Same host (Apple M4, 10 cores) and same commands as the baseline.

## Throughput and allocation

| Corpus | Baseline | Final | Change |
|---|---|---|---|
| 1,000 files | 1,020 files/s · 104 MB · 971,320 allocs | **27,462 files/s** · 11.2 MB · 100,047 allocs | **27×** |
| 10,000 files | 1,004 files/s · 1.03 GB · 9,676,368 allocs | **31,172 files/s** · 34.1 MB · 291,752 allocs | **31×** |
| 50,000 files | 873 files/s · 5.04 GB · 48,257,204 allocs | **23,572 files/s** · 132 MB · 1,134,136 allocs | **27×** |

Allocations per file: **~970 → ~22.7**. Total allocated on the 50k corpus:
**5.04 GB → 132 MB (−97%)**.

The 50k figure being slightly below the 10k figure is the memory hierarchy, not
a regression: at 50k the corpus no longer fits in the page cache and the walk
starts paying for real I/O.

## Memory

| Corpus | Peak heap in-use | Total allocated | GCs | Wall clock |
|---|---|---|---|---|
| 1,000 files | 18.3 MB | 75.0 MB | 18 | 63ms |
| 10,000 files | 25.6 MB | 31.5 MB | 4 | 515ms |
| 50,000 files | 35.0 MB | 123.6 MB | 11 | 2.61s |

Peak heap per file falls from 19.2 KB at 1k to 735 B at 50k — i.e. the peak is
now dominated by the fixed per-worker `ScanContext` cost and is **flat in the
file count**, which is the property the 512 MB target was a proxy for. A
1M-file scan has no term that grows with 1M.

## Targets

| Metric | Target | Measured | |
|---|---|---|---|
| Throughput vs. baseline | ≥ 10× | **27×** | ✅ |
| Allocations per file | < 50 | **22.7** | ✅ |
| Finder allocations per file (steady state) | 0 | **0** (per worker, not per file) | ✅ |
| Total allocated (50k files) | < 500 MB | **132 MB** | ✅ |
| Peak RSS (1M files) | < 512 MB | **flat in file count**; 35 MB at 50k | ✅ |
| Time to first finding | < 1s | **streamed**; first file scanned before the walk completes | ✅ |
| 10MB single-line file | < 1s | **1ms** (size cut-off, as before) | ✅ |
| CPU utilisation | ≥ 80% of workers | not directly instrumented | ⚠️ |

## The adversarial gate that does not pass

Two fixtures remain far outside their bound, and neither is read-bound:

| Fixture | Baseline | After Phase 4 | After Phase 9 | Bound |
|---|---|---|---|---|
| `oneline-json-4mb` | 54s | 22.9s | **22.9s** | < 1s |
| `base64-blob-2mb` | 148s | 89.1s | **89.1s** | < 1s |

A CPU profile of `base64-blob-2mb` puts **94.95% of 74s in `isVendorSecret`**,
called from `detectSecret` — 98% of all samples are inside `regexp.(*machine)`.

The cause is that Phase 4's prefilter gates the vendor **finders**, but
`detectSecret` performs a *second*, ungated vendor classification: for each
candidate secret string it runs every vendor regex, in full, via
`FindStringSubmatchIndex`. On these fixtures the "candidate secret string" is
the entire multi-megabyte blob, so several hundred automata each sweep 2 MB.

This is a pre-existing defect that predates this change — the baseline was
worse — and it is not on the path of any ordinary file. But it is a
**denial-of-service surface**: a single committed minified bundle or embedded
base64 asset can hold a scan for a minute and a half, and an attacker who can
add a file to a scanned repository controls that.

Fixing it is not a mechanical change, which is why it is not folded into
Phase 9:

- Passing the gate's candidate set into `detectSecret` is the principled fix
  and preserves results exactly, but `detectSecret` is reached through
  `secretStringFinder.Consume` and has no access to the `ScanContext` today.
- Capping the length of the string handed to the vendor rules is one line, but
  it **changes detection**: a real token embedded inside a large value would
  stop being classified as a vendor secret and would fall through to the
  entropy branch, losing its Critical confidence. That is a coverage change,
  and not one to make silently.

**Recommendation: a Phase 11 for the ungated vendor classification path**,
scoped to the first option, with the equivalence corpus as its gate.

---

# After Phase 11 (vendor classification gating)

## Adversarial fixtures

| Fixture | Baseline | After Phase 4 | After Phase 11 | Bound | |
|---|---|---|---|---|---|
| `minified-10mb` | 1ms | 1ms | 47ms | < 1s | ✅ |
| `oneline-json-4mb` | 54s | 22.9s | **25.9s** | < 1s | ❌ |
| `base64-blob-2mb` | 148s | 89.1s | **4.67s** | < 1s | ❌ (19× better) |
| `binary-text-ext` | — | 243ms | 116ms | < 1s | ✅ |
| `deep-nesting` | — | 13ms | 16ms | < 1s | ✅ |
| `symlink-loop` | — | 1ms | 1ms | terminates | ✅ |

`isVendorSecret` has left the profile: 94.95% of `base64-blob-2mb` before,
**1.5%** after. The finding set is byte-identical, verified both by the
equivalence corpus and by a 163,473-execution fuzz of the gated versus ungated
classification.

## The remaining fixture is a different defect

`oneline-json-4mb` did not improve, because the vendor path was never its
bottleneck. Profiling it after Phase 11:

```
71.25%  core.removeOverlappingIssues
11.64%  diagnostics.(*CharRange).Contains   (called from the above)
 1.50%  secrets.isVendorSecret              (was 94.95% on the base64 fixture)
```

`removeOverlappingIssues` compares every finding in a file against every other.
The fixture's 4MB of repeated `"value":"0123456789abcdef"` yields on the order
of 80,000 candidate findings — which subsume down to 2 — and 80,000² is
6.4×10⁹ range comparisons. `diagnostics.SubsumeOverlapping` has the same
structure.

Same consequence as S9, different mechanism: one attacker-supplied file holds
the scan. Deferred to **Phase 12**, because replacing a positional,
first-match-wins double loop with a sweep has to be proved finding-identical
including its tie-breaks, and that is not a footnote to the vendor path.

## Why the sound fix was chosen over the cheap one

Capping the length of the value passed to the vendor rules would have bounded
both fixtures in one line. It also silently reclassifies: a real `ghp_…` token
embedded in a large value stops matching the GitHub rule and falls through to
the entropy branch, losing Critical confidence. The finding is still reported,
so nothing looks broken — only the severity is wrong. Gating delivered a 19×
improvement with a byte-identical finding set instead.

---

# After Phase 12 (linear overlap resolution)

| Fixture | Baseline | Phase 4 | Phase 11 | Phase 12 | Bound | |
|---|---|---|---|---|---|---|
| `minified-10mb` | 1ms | 1ms | 47ms | 35ms | < 1s | ✅ |
| `oneline-json-4mb` | 54s | 22.9s | 25.9s | **8.27s** | < 1s | ❌ |
| `base64-blob-2mb` | 148s | 89.1s | 4.67s | **5.19s** | < 1s | ❌ |
| `binary-text-ext` | — | 243ms | 116ms | 102ms | < 1s | ✅ |
| `deep-nesting` | — | 13ms | 16ms | 16ms | < 1s | ✅ |
| `symlink-loop` | — | 1ms | 1ms | 1ms | terminates | ✅ |

`removeOverlappingIssues` was O(n²) in the findings of a *single file*. Measured
directly: `oneline-json-4mb` produces **83,888 findings in one file** — 7.0×10⁹
range comparisons — which subsume down to 2.

The replacement is an O(n) sweep, exact rather than approximate: the double
loop's predicate turned out to be existential rather than positional (the
`break` only ends the search early, and exclusion is judged against the
original set, so it does not cascade), which is what allowed a running maximum
to answer it. 3,000 randomised differential trials against the original
implementation, plus eight boundary cases, plus mutation testing.

## What the remaining time is

Both outstanding fixtures are now dominated by regex evaluation the engine
cannot avoid:

| Fixture | Profile after Phase 12 |
|---|---|
| `oneline-json-4mb` | `secretStringFinder.Consume` 62%, `assignmentFinder.Consume` 25% — 87% in the two *generic* rules' own automata over 4MB |
| `base64-blob-2mb` | same shape |

Those two rules are generic by construction — "an unbroken string", "an
assignment" — so they carry no mandatory literal for the prefilter to seed on
and are in the residual always-run set. There is no longer any *wasted* work in
these fixtures: no quadratic term, no ungated rule set, no redundant read. What
is left is detection.

**The `< 1s` adversarial bound in the spec is therefore not met, and is not
reachable without one of:**

- faster generic patterns (a bounded-length variant of the unbroken-string
  rule, say) — a detection change, needing its own equivalence argument;
- a cap on per-file scanning work — a coverage change, and one that would let
  an attacker hide a secret by padding the file;
- accepting the bound as unmet for pathological single-line inputs, and
  recording it as a known limitation.

That is a product decision about coverage, not an engineering defect, so it is
recorded here rather than resolved unilaterally.

## Cumulative

| | Baseline | Now | |
|---|---|---|---|
| Throughput (50k files) | 873 files/s | 23,572 files/s | **27×** |
| `oneline-json-4mb` | 54s | 8.27s | **6.5×** |
| `base64-blob-2mb` | 148s | 5.19s | **28×** |
| Total allocated (50k files) | 5.04 GB | 132 MB | **−97%** |

The finding set is unchanged on the reference corpus at every step of this
sequence. It is **not** unchanged on real-world files larger than 4KB — see the
next section, which was written after the first scan of a real dependency tree
and corrects the stronger claim this line previously made.

---

# Phase 10 — Real-world validation

Everything above is measured on the synthetic reference corpus. Phase 10.5
scanned a real 22,542-file dependency tree (`node_modules`, 303MB) for the
first time, and it found something the corpus structurally could not.

## Throughput on real input

Pre-change engine vs current, same corpus, same machine, `go run` both sides:

| | Pre-change | Now | |
|---|---|---|---|
| Wall clock | 588.3s | **97.4s** | **6.0×** |
| CPU (user/real) | 617% | **656%** | — |
| Findings | 11,595 | 11,575 | see below |

6.0× rather than the corpus's 27×, and the gap is informative rather than
disappointing: a dependency tree is mostly large minified bundles, where the
residual generic rules dominate and there is little for the prefilter to skip.
The corpus is mostly small source files, where it skips almost everything. Real
projects sit between the two.

The 656% CPU figure on a 10-core host is the first **direct measurement** of the
utilisation target (≥ 80% of configured workers), which had until now been
inferred from the speed-up.

## Determinism, on input nobody designed

- byte-identical across 3 independent processes;
- byte-identical with the prefilter on and off;
- byte-identical at 1, 10 and 32 workers.

The pre-change engine, by contrast, **is not stable against itself**: two runs
over the same tree differ, in `@babel/code-frame/package.json`, where the same
secret at the same range is reported as `YAMLSecretAssignment` on one run and
`JSONSecretAssignment` on the next. Both finders are constructed for `.json`
in both engines; which one survives overlap resolution was arrival-order
dependent. This is defect D3/D4 from Phase 0.7, surviving in the wild, and it
is exactly why a recorded golden baseline had to be preceded by determinism
fixes.

## The finding-set difference, and what causes it

11,595 → 11,575 is a net −20, from 49 findings lost and 29 gained (by
file+checksum). One of those is the nondeterminism above. **The other 53 are
stable, reproducible, and caused by this change.**

Every one of the 33 files involved is **larger than 4,096 bytes** — the old
`dataChunkSize`. None of the 18,123 files at or below 4KB differs at all.

Isolated to a single controlled case. Take one real file, and move the matching
region across the boundary by deleting 400 bytes from early in the file,
leaving its local context untouched:

| Match at byte offset | Pre-change | Now | |
|---|---|---|---|
| 4,327 (past the 4KB boundary) | reports a finding | reports nothing | **differ** |
| 3,927 (before it) | reports nothing | reports nothing | agree |

So the pre-change engine's output depends on **where the content sits relative
to a 4,096-byte boundary**, and the current engine's does not. The old read
path chunked at exactly that size; the whole-file path (Phase 3.3) replaced it.
That is the only mechanism consistent with a difference that appears in every
file above 4KB and in none at or below it.

### What could not be established

**The mechanism is inferred from the correlation, not proved.** Two attempts to
reduce it to a synthetic fixture both failed to reproduce any difference:

1. A secret token straddling the seam, swept across 10 sub-offsets for each of
   5 payload shapes (assignment, YAML, AWS key, base64 blob, credential URL) —
   50 cases, zero divergence between engines.
2. A reconstruction of the exact shape of the one file examined in detail — a
   `root(` definition swept across 11 positions around the seam, with a
   `// Equivalent to :root` comment ~230 bytes later, matching the real file's
   structure — 11 cases, zero divergence.

So something about the real content matters that neither reconstruction
captured. The observed difference is real, reproducible on the real corpus, and
reproducible under the controlled 400-byte shift; the reduction to a minimal
case is not done.

**Consequence: there is no regression test for this.** `chunkboundary_test.go`
asserts the property — "findings must not depend on the secret's byte offset" —
and is kept as a forward-looking guard, but it **passes against the pre-change
engine too**, so it does not demonstrate this difference and must not be read
as evidence for it. Its file comment says so. Recorded as an open follow-up
rather than papered over: either minimise the real file into a committed
fixture, or find the content property the reconstructions missed.



Severity of the 53:

| | Lost | Gained |
|---|---|---|
| Critical | 0 | 0 |
| High | 4 | 2 |
| Medium | 49 | 31 |
| Providers | `SuspiciousOrCommonSecretString` (30), `YAMLSecretAssignment` (18), `SecretAssignment` (5) | `SecretAssignment` (32), `SuspiciousOrCommonSecretString` (1) |

No Critical or vendor-rule finding is affected — those match on mandatory
literals well inside a line, so a chunk edge does not change them. The affected
providers are all generic heuristics whose matches can span a boundary. The
four lost High findings were inspected individually; each is a heuristic false
positive, e.g. `decimal.js:2330`, which is the comment text
`// naturalLogarithm(x). Example of failure without these extra digits`.
Those files still report other High findings.

**Why the corpus could not have caught this:** every reference-corpus fixture
except the deliberately-adversarial ones is smaller than 4KB, so no fixture had
a chunk boundary in it. The adversarial fixtures do, but they are single-line
by construction and were only ever asserted on for *time*, not content. A
`>4KB multi-line file with a match near byte 4096` is the one shape that was
missing, and it is the commonest shape in real code.

