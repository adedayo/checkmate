# Spec: Scan Engine — Offset Independence

**Change:** 004-chunk-boundary-minimisation
**Status:** Draft

## Overview

This is a **delta** to the accepted `scan-engine` capability spec. It does not
restate that spec; it narrows the second exception to its governing invariant.

## Context: the exception being narrowed

The accepted spec records two exceptions to *"findings MUST be identical to the
pre-change engine"*. The second is offset-dependence: on a real 22,542-file
corpus, 49 findings were lost and 29 gained out of 11,595, confined entirely to
files larger than the old 4,096-byte `dataChunkSize`.

That exception is **accepted** (owner, 2026-08-09). This change does not
reopen it. It replaces the evidence beneath it.

## Requirements

### R1 — Offset independence MUST be a proved property

The engine's output for a given file MUST NOT depend on the byte offset at
which content appears.

Currently asserted by `chunkboundary_test.go`, which **passes against the
pre-change engine as well** and therefore does not demonstrate the property is
new or was ever violated. On completion, the assertion MUST be backed by at
least one case that **fails** against the pre-change engine.

> A test that has never been observed to fail is a claim, not a guard.

### R2 — The reproducer MUST be committed

At least one input reproducing the divergence MUST live in the repository under
`testdata/`, with origin and SHA-256 recorded.

The present reproducer is an uncommitted `node_modules` file in a sibling
workspace, one `npm ci` from deletion. **If it is lost, the exception becomes
permanently unfalsifiable.**

### R3 — The differential oracle MUST tolerate baseline nondeterminism

Any automated comparison against the pre-change engine MUST run the baseline
**at least 3 times** and treat only stable divergences as real.

The pre-change engine is not stable against itself: two runs over the same
corpus disagreed on whether a finding was `YAMLSecretAssignment` or
`JSONSecretAssignment` (defect D3/D4). A single-run oracle would report that
instability as a divergence and drive a search toward noise.

### R4 — Minimisation MUST NOT cross below the chunk threshold undetected

A reduction MUST NOT be accepted if divergence disappears merely because the
input fell below 4,096 bytes. Inert padding is permitted and its length MUST be
recorded.

Otherwise ddmin will "minimise" to a file with only one chunk and report a
trivially non-diverging result as success.

### R5 — Unexplained MUST be recordable as unexplained

If the mechanism resists minimisation, the change MUST record that outcome
plainly and leave the exception standing on correlation.

It MUST NOT introduce a test that passes for an unrelated reason and present it
as a guard. Two manual reconstructions (50-case and 11-case) already showed zero
divergence; a third failure is a real possibility and an acceptable result.

## Out of Scope

- Changing detection behaviour. If minimisation shows the **current** engine is
  wrong rather than merely different, that is a separate change with its own
  proposal.
- Re-litigating the accepted exception absent new evidence.

## Success Criteria

| Requirement | Current | Target |
|---|---|---|
| R1 | passes on both engines | fails on pre-change engine |
| R2 | uncommitted `node_modules` | committed fixture + SHA-256 |
| R3 | single-run comparison | 3× stability gate |
| R4 | unguarded | size floor enforced and recorded |
| R5 | — | outcome recorded either way |
