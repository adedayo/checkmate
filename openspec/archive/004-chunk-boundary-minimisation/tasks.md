# OpenSpec Tasks: 004-chunk-boundary-minimisation

**Outcome: the mechanism was proved.** Phase 6.1 applies, not 6.2. The
reproducer was reduced from 145 lines to 3, the mechanism identified and
confirmed by a positional experiment, and the regression test verified to fail
against the pre-change engine.

## Phase 1: Capture the reproducer before it disappears

> The only urgent phase. The reproducer currently lives in an **uncommitted**
> `node_modules` tree in a sibling workspace and does not survive `npm ci`.

- [x] **1.1** Copied to
  `pkg/plugin/secrets-finder/pkg/testdata/boundary/css-select-filters.js`.
  5,357 bytes, SHA-256
  `7ec4f4d8b92fac7fae14668f760e7e735968f80b497a145a79a04395858b3c19`, from
  `css-select@6.0.0`. Origin, version and hash recorded in the directory's
  `README.md`.
- [x] **1.2** Re-confirmed from the committed copy, not from `node_modules`:
  pre-change engine reports 1 `SuspiciousOrCommonSecretString`, current engine
  reports 0. Stable across 3 runs per side.
- [x] **1.3** A single reproducer sufficed, and the other 32 were not captured.

  Recording why, since the task warned against losing them casually. Once the
  mechanism was reduced to three ingredients and confirmed by moving the quote
  across the seam, the remaining files were redundant: they could only have
  re-demonstrated the same mechanism. The positional experiment in Phase 4 is
  stronger evidence than 32 more instances of the correlation, because it
  varies the cause rather than accumulating examples. The cost of being wrong
  is also low — `tools/boundarydiff` and the baseline worktree recipe are
  committed, so any future `node_modules` tree can regenerate the population.
- [x] **1.4** Baseline pinned as `0a2362b~1` = `39369e9`, recorded in the
  fixture `README.md` and in `tools/README.md`.

## Phase 2: Build a trustworthy oracle

- [x] **2.1** `tools/boundarydiff`, using `tools/dumpfindings` as the
  comparison format. `dumpfindings` postdates the baseline, so it is copied
  into the baseline worktree; it only uses `SearchSecretsOnPaths`, which exists
  on both sides.

  One thing the design did not anticipate: the baseline tree prints a stray
  `TESTING COMPILATION determineAndCloneRepositories` line to stdout. Left in,
  it registers as a permanent difference and the search never converges. The
  oracle discards non-finding lines.
- [x] **2.2** 3 runs per side, with a three-valued verdict — `same`,
  `diverges`, `unstable`. Collapsing `unstable` into `same` is precisely how a
  flaky oracle steers a search, so it is kept distinct. No instability was
  observed on this input, but the guard is what makes that a finding rather
  than an assumption.
- [x] **2.3** Self-check on a known-negative (13-byte file → `same`) and the
  Phase 1 fixture (→ `diverges`) before any search runs. Both pass.

## Phase 3: Minimise

- [x] **3.1** ddmin over lines: **145 → 3**, in 38 oracle calls.
- [x] **3.2** Byte-level reduction within surviving lines was not run as a
  separate ddmin pass; the three lines were reduced directly by substitution in
  Phase 4, which established that only a single `"` character of line 84 is
  load-bearing. That is a stronger result than a byte-level ddmin would have
  given, since it also identifies *which* byte and why.
- [x] **3.3** Guarded structurally rather than by assertion after the fact.
  Deleted lines are replaced by equal-length whitespace, so the file is
  **exactly 5,357 bytes at every step** and cannot fall below 4,096. The tool
  fails loudly if a reduction ever changes the length. No padding was needed,
  so there is no padding length to record.
- [x] **3.4** Minimal diverging input: 5,357 bytes, 3 content-bearing lines —
  84 (`"nth-last-of-type"...`), 115 (`// Equivalent to :root`), 116
  (`return filters["root"](...)`).

  Also reproduced **synthetically** at 4,200 bytes: one quote line, 100 blank
  padding lines, the comment, the match. This is what two previous manual
  attempts failed to produce.

## Phase 4: Explain the mechanism

- [x] **4.1** `largeChunk` hypothesis **refuted**. The reproducer's lines are
  all short and newline-terminated, so `readChunks` never enters the
  no-newline accumulation branch.
- [x] **4.2** Truncated-entropy hypothesis **refuted**. The finding is a
  fixed-string match with a byte-identical SHA-256 on both sides; nothing is
  being scored over a truncated window.

  This also explains why sweeping a well-formed secret across the seam never
  reproduced anything. Both engines report a well-formed secret wherever it
  sits. The divergence is the **loss of a suppression**, so it can only appear
  for findings the whole-file engine is able to reject — that is, false
  positives. Both earlier attempts were looking for a manufactured or truncated
  match, which is the wrong direction.
- [x] **4.3** Mechanism named, in the `chunkboundary_test.go` header and on the
  fixture.

  Three ingredients are each necessary — a `"` before the seam, a
  `// ... :root` comment after it, a `filters["root"](...)` match after it.
  Remove any one and the engines agree. The old reader passed each chunk to a
  separate `Consume` call, so a suppression rule needing to see both the quote
  and the match could not fire across the seam.

  Confirmed positionally: with the quote at bytes 3,101 / 3,763 / 4,018 the
  engines diverge; at 4,064 / 4,101 / 4,189 they agree. The flip is exactly at
  the newline-aligned chunk split — byte 4,063, the end of line 108 — not at
  the nominal 4,096, because `readChunks` walks back to the last newline. The
  divergence tracks the *real* seam.

## Phase 5: Promote the test

- [x] **5.1** `TestChunkBoundarySuppressionIsNotLost` asserts the minimised
  case, built synthetically so the test does not depend on a 5KB third-party
  fixture. Preconditions (file > 4,096 bytes, match beyond the seam) are
  asserted, not assumed, so the test cannot pass by losing its own premise.
- [x] **5.2** **Verified failing against the pre-change engine.** On the exact
  bytes the test builds: pre-change reports 1 finding, current reports 0, so
  the `want 0` assertion fails on the old engine. The no-quote control returns
  1 on both, so the control is not vacuous.
- [x] **5.3** Header replaced. It now distinguishes the real guard from the two
  forward-looking property tests, which still pass against both engines and are
  labelled as such.
- [x] **5.4** Updated `openspec/specs/scan-engine/spec.md` (second exception)
  and the archived 003 `baseline.md`, which now carries a RESOLVED note. The
  original text is left standing — what was true at the time is part of the
  record.

## Phase 6: Close out

- [x] **6.1** Minimisation succeeded. Spec delta merged and archived.
- [x] **6.2** Not applicable — recorded here so the alternative outcome is not
  silently dropped. The mechanism did not resist the automated search.
