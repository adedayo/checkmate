# OpenSpec Tasks: 004-chunk-boundary-minimisation

## Phase 1: Capture the reproducer before it disappears

> The only urgent phase. The reproducer currently lives in an **uncommitted**
> `node_modules` tree in a sibling workspace and does not survive `npm ci`.

- [ ] **1.1** Copy `css-select/dist/esm/pseudo-selectors/filters.js` (5,357
  bytes) to `pkg/plugin/secrets-finder/pkg/testdata/boundary/` with its origin,
  upstream version and SHA-256 recorded alongside.
- [ ] **1.2** Re-confirm divergence from the committed copy, not from
  `node_modules`, so the fixture itself is known to reproduce.
- [ ] **1.3** Capture the other 32 affected files the same way, or record why
  a single reproducer suffices. Losing 32 of 33 data points to an `npm ci`
  would be careless.
- [ ] **1.4** Record the exact baseline commit (`0a2362b~1`) in the harness.
  "HEAD" drifts the moment anything else lands.

## Phase 2: Build a trustworthy oracle

- [ ] **2.1** `tools/boundarydiff`: given a file and two engine worktrees, emit
  the finding-set diff using `tools/dumpfindings` as the comparison format.
- [ ] **2.2** Run the baseline engine **3× per candidate** and accept only
  divergences stable across all runs.

  Non-optional: the pre-change engine is not stable against itself
  (`YAMLSecretAssignment` vs `JSONSecretAssignment` on the same file, defect
  D3/D4). A flaky oracle will minimise toward the instability rather than
  toward the real mechanism.
- [ ] **2.3** Verify the oracle on a known-negative (a file under 4KB) and a
  known-positive (the Phase 1 fixture) before trusting it to drive a search.

## Phase 3: Minimise

- [ ] **3.1** ddmin over lines.
- [ ] **3.2** ddmin over bytes within surviving lines.
- [ ] **3.3** Guard against false minimisation: reduction must not silently
  drop the file below 4,096 bytes. Divergence vanishing because there is no
  longer a second chunk is **not** a result. Inert padding is permitted; its
  length must be recorded.
- [ ] **3.4** Record the minimal diverging input and its size.

## Phase 4: Explain the mechanism

- [ ] **4.1** Test the `largeChunk` hypothesis directly: does the minimal case
  enter the old chunker's no-newline accumulation branch? Cheapest candidate
  and a different code path, not merely a different offset.
- [ ] **4.2** Test the truncated-entropy hypothesis: are the affected findings
  heuristic rules scoring entropy over a chunk-truncated window rather than a
  whole line? This would explain why sweeping a well-formed secret across the
  seam never reproduced — such a secret scores high either way.
- [ ] **4.3** Name the mechanism in a comment on the fixture, or record that it
  remains unexplained.

## Phase 5: Promote the test

- [ ] **5.1** Rewrite `chunkboundary_test.go` to assert the minimised case.
- [ ] **5.2** Verify it **fails** against the pre-change engine and passes
  against the current one. A test not observed failing is not a guard.
- [ ] **5.3** Replace the file's "statement of intent, not evidence" header
  with what is now actually proved.
- [ ] **5.4** Update the 003 exception record in `openspec/archive/` and the
  `scan-engine` spec's second exception.

## Phase 6: Close out

- [ ] **6.1** If minimisation succeeded: merge the spec delta, archive.
- [ ] **6.2** If it failed: record that the mechanism resisted two manual
  probes and one automated search, leave the exception standing explicitly on
  correlation, and archive anyway.

  This is a legitimate outcome, not a defeat. The prohibited outcome is a test
  that passes for an unrelated reason and is presented as a guard.
