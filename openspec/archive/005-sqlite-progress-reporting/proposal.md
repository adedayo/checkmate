# OpenSpec Proposal: 005-sqlite-progress-reporting

**Status:** Draft
**Capability:** `data-store`
**Type:** Defect fix — pre-existing, not introduced by 003

## Goal

Make `sqlite.DB.RunScan` honour the `progressMonitor` callback it already
accepts, so that scans driven through the SQLite store emit progress and the
WebSocket scan summary reports a correct `fileCount`.

## Motivation

`projects.ProjectManager` has two implementations. They do not behave the same:

| Implementation | `progressMonitor(...)` call sites |
|---|---|
| `projects.simpleProjectManager` (`management.go:883`) | **8** |
| `sqlite.DB` (`store/sqlite/db.go:704`) | **0** |

`sqlite.DB.RunScan` accepts `progressMonitor func(diagnostics.Progress)` at
`db.go:711` and never invokes it. Every caller — `pkg/api/websocket.go:165`,
`pkg/api/platform.go:179`, `pkg/cron/repository.go:252` — passes a real
callback that is silently discarded.

### Observable effect

The WebSocket scan summary reports **`fileCount: 0`** for every scan, because
the API derives that count from progress events that never arrive.

### This is pre-existing, and was not caused by 003

Verified at the pre-003 commit: `grep -c "progressMonitor(" pkg/store/sqlite/db.go`
returns `0` there too. Before 003 the API counted `len(paths)` fed by the same
never-called callback, so it was equally zero. **The defect is older than the
change that found it.**

Change 003 improved the counter it touched — counting coalesced progress events
would now under-report by orders of magnitude, so it reads `Position` instead —
but it could not fix a callback that is never called, and fixing it inside a
validation phase would have been out of scope.

### Why the persisted count looks fine

`file_count` in the database **is** correct (22,591 on the Phase 10 corpus),
because it comes from the paths channel rather than from progress. So the bug
is invisible in the DB and in reports, and shows up only in the live stream.
That asymmetry is why it survived this long.

### Why it matters

Live progress is the feature that tells a user a long scan is alive. Change 003
took whole-tree scans from 588s to 97s, but a 97-second scan that reports
`fileCount: 0` throughout still looks hung. **The performance work is partly
wasted while this is broken** — the desktop app and API are exactly where the
improvement should be most visible.

## Scope

1. Emit progress from `sqlite.DB.RunScan` at the same lifecycle points as
   `simpleProjectManager.RunScan`, so the two implementations agree.
2. A test asserting a non-zero, monotonic `fileCount` through the SQLite path.
3. A conformance test applied to **both** implementations, so they cannot drift
   apart again.

## Non-Goals

- No change to progress *coalescing* (`CHECKMATE_PROGRESS_INTERVAL`), which
  works as designed.
- No change to the `Progress` type or the WebSocket message schema.
- No change to persisted `file_count`, which is already correct.

## Risks

- **Progress volume.** The 003 work coalesces progress deliberately; a naive
  per-file emission from the SQLite path would reintroduce the fan-out that
  coalescing exists to prevent. The fix must emit through the same coalescing
  path, not around it.
- **Interface drift is the actual root cause.** Two implementations of one
  interface silently disagreeing is the underlying defect; fixing only the
  symptom leaves the next divergence just as likely. Hence scope item 3.

## Success Criteria

| Dimension | Current | Target |
|---|---|---|
| `progressMonitor` call sites in `sqlite.DB.RunScan` | 0 | parity with `simpleProjectManager` |
| WebSocket summary `fileCount` | always `0` | accurate, monotonic |
| Progress events per scan | 0 | coalesced at `CHECKMATE_PROGRESS_INTERVAL` |
| Cross-implementation conformance | untested | shared test over both |
