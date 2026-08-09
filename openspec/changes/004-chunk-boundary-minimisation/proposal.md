# OpenSpec Proposal: 004-chunk-boundary-minimisation

**Status:** Draft
**Capability:** `scan-engine`
**Type:** Test hardening — **no functional change intended**

## Goal

Reduce the offset-dependence difference discovered during 003 Phase 10 to a
**minimal, committed fixture**, so that the second documented exception to the
scan-engine governing invariant is supported by a reproducing test rather than
by a correlation.

## Motivation

Change 003 was governed by an invariant: optimisations may not alter the set of
findings. Phase 10.5 scanned a real 22,542-file dependency tree and found that
this invariant does not strictly hold. Against the pre-change engine: **49
findings lost, 29 gained, out of 11,595.**

The owner accepted this on 2026-08-09 as a documented exception, on the grounds
that the new behaviour is offset-independent and therefore better-defined, and
that nothing of value is lost — no Critical findings, no vendor rules, and the
four lost High findings are heuristic false positives on comment text.

That decision is sound. The **evidence for it is weaker than this project's own
standard**, and this change exists to close that gap.

### What is actually established

- The difference is **real and reproducible** on real input.
- Every one of the 33 affected files is larger than **4,096 bytes** — the old
  `dataChunkSize`. **None of the 18,123 files at or below 4KB differs at all.**
- A controlled edit to one real file — deleting 400 bytes earlier in the file to
  move a matching region from offset 4,327 to 3,927 — **flips the pre-change
  engine's output and not the current engine's**.

### What is not established

The obvious explanation is that the old chunked read restarted matching at each
4KB boundary, so a buffer edge could manufacture or truncate a match. **This is
inferred from the correlation and has not been proved.** Two attempts to reduce
it to a synthetic fixture both showed *zero* divergence between engines:

| Attempt | Construction | Result |
|---|---|---|
| `tmp_boundaryprobe` | 50 cases sweeping a secret across the 4096-byte seam | no divergence |
| `tmp_boundaryprobe2` | 11 cases reproducing the shape of the one file examined closely | no divergence |

Some property of the real content is not captured by either reconstruction.
Until that property is identified, the accepted exception rests on a
correlation, and `chunkboundary_test.go` — which passes against **both**
engines — guards the future rather than evidencing the past.

### Why this matters beyond tidiness

An unexplained difference in a security scanner is a standing risk. The benign
reading is "chunk boundaries caused false positives that no longer occur". A
less benign reading is "some other offset-dependent behaviour differs, and the
4KB correlation is coincidental". **Nothing currently distinguishes the two.**
The corpus that would have caught this — a multi-line file over 4KB with a match
near byte 4096 — is the commonest shape in real source code, and no fixture had
it.

## Scope

1. Commit a stable copy of the known reproducer, or a reduction of it, as a
   test fixture. The current reproducer lives in an **uncommitted**
   `node_modules` tree in a sibling workspace and will not survive a reinstall.
2. Automated delta-debugging of that reproducer against a `git worktree` at the
   pre-change commit, bisecting content until the smallest input that still
   diverges is found.
3. Identify the content property that makes real files diverge where synthetic
   reconstructions do not.
4. Promote `chunkboundary_test.go` from an aspirational property test to a
   genuine differential guard, and rewrite its header once it is one.
5. Update the 003 exception record in `openspec/archive/` and the scan-engine
   spec with whatever is actually proved.

## Non-Goals

- **No change to detection behaviour.** If minimisation shows the current engine
  is wrong rather than merely different, that is a separate change with its own
  proposal — not a quiet fix inside a test-hardening effort.
- No revisiting of the accepted exception itself unless evidence warrants it.
- No performance work.

## Risks

- **The reproducer may be lost before it is captured.** `node_modules` is
  uncommitted and one `npm ci` from deletion. Task 1.1 is therefore first and
  is the only genuinely urgent item here.
- **Minimisation may fail again.** Two attempts already have. If a third fails,
  the honest outcome is to record that the mechanism resisted three independent
  attempts and leave the exception standing on correlation — **not** to
  manufacture a test that passes for the wrong reason. A vacuous test is worse
  than no test, because it advertises a guarantee it does not provide.

## Success Criteria

| Dimension | Current | Target |
|---|---|---|
| Reproducer durability | uncommitted `node_modules` | committed fixture |
| Mechanism | inferred from correlation | proved, or explicitly recorded as unproved after a third attempt |
| `chunkboundary_test.go` | passes on both engines (vacuous as a guard) | fails on the pre-change engine, passes on the current one |
| Exception record | "probable cause" | evidenced, or honestly downgraded |
