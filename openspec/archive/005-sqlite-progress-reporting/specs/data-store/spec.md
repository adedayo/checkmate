# Spec: Data Store — Scan Progress Reporting

**Change:** 005-sqlite-progress-reporting
**Status:** Draft

## Overview

A **delta** to the `data-store` capability spec, defining the progress-reporting
obligations of `projects.ProjectManager` implementations.

## Context

`projects.ProjectManager` has two implementations. `simpleProjectManager` emits
progress at 8 lifecycle points; `sqlite.DB` accepts the same
`progressMonitor func(diagnostics.Progress)` parameter and emits **none**. Every
caller supplies a working callback that is silently discarded, so the WebSocket
scan summary reports `fileCount: 0` for every scan.

Pre-existing and verified at the pre-003 commit. The persisted `file_count` is
correct, since it derives from the paths channel rather than from progress —
which is why the defect is invisible in the database and in reports.

## Requirements

### R1 — Every `ProjectManager` implementation MUST emit progress

An implementation accepting `progressMonitor` MUST invoke it across the scan
lifecycle: start, per-repository transitions, during consumption, and
completion.

Accepting the parameter and ignoring it is a defect, not an implementation
choice. **Go does not error on unused function parameters**, so this cannot be
caught by the compiler and MUST be covered by a test.

### R2 — Progress MUST be coalesced, never per-file

Emission MUST pass through the coalescing path bounded by
`CHECKMATE_PROGRESS_INTERVAL` (default 250ms).

Per-file emission on a large corpus produces a callback storm fanning out to
WebSocket and DB writes — the defect change 003 removed. Bypassing coalescing
would reintroduce it **silently**, since the symptom is load-dependent and does
not appear on small test corpora.

### R3 — File counts MUST derive from `Position`, not event counts

Counting coalesced progress events under-reports by orders of magnitude.

### R4 — The observable count MUST be non-zero and monotonic

`fileCount` in the WebSocket scan summary MUST increase monotonically and reach
the true file count.

This MUST be asserted at the API layer. Asserting against persisted
`file_count` proves nothing — it is already correct today, with the defect
present.

### R5 — Implementations MUST be tested for conformance with each other

Progress obligations MUST be verified against **all** `ProjectManager`
implementations from a shared, table-driven test.

Two implementations of one interface silently disagreeing is the root cause
here. Fixing one instance without a conformance check leaves the next
divergence equally likely and equally invisible.

### R6 — Progress reporting MUST NOT alter the finding set

Emitting progress MUST NOT change which findings are produced. Guarded by the
existing `scan-engine` equivalence tests.

## Out of Scope

- The `Progress` type and WebSocket message schema — unchanged.
- Coalescing behaviour and `CHECKMATE_PROGRESS_INTERVAL` — work as designed.
- Persisted `file_count` — already correct.

## Success Criteria

| Requirement | Current | Target |
|---|---|---|
| R1 | `sqlite.DB`: 0 emissions | parity with `simpleProjectManager` |
| R2 | n/a | coalesced at configured interval |
| R3 | n/a | derived from `Position` |
| R4 | `fileCount: 0` always | non-zero, monotonic, accurate |
| R5 | untested | shared test over both implementations |
| R6 | — | byte-identical findings |
