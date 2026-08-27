# Design: 005-sqlite-progress-reporting

## Root cause

`projects.ProjectManager` is an interface with two implementations. Only one
honours the `progressMonitor` parameter.

```
  pkg/api/websocket.go:165 ──┐
  pkg/api/platform.go:179  ──┼──► ProjectManager.RunScan(..., progressMonitor, ...)
  pkg/cron/repository.go:252 ┘                │
                                              ├─► simpleProjectManager  → 8 calls  ✓
                                              └─► sqlite.DB             → 0 calls  ✗
```

The signature at `db.go:711` accepts the callback, so the compiler is satisfied
and the omission is invisible at every call site. **An unused function
parameter is not a compile error in Go**, which is precisely why this survived.

Callers pass a working `progressMon`. The API's `fileCount` is derived from
those events, so it stays at zero forever.

## Where the reference implementation emits

`simpleProjectManager.RunScan` calls `progressMonitor` at
`management.go:903, 938, 953, 965, 988, 997, 1006, 1018` — scan start,
per-repository lifecycle, during consumption, and completion. That set is the
de facto contract, and the SQLite implementation should match its *semantics*
rather than copy its line-for-line placement, since the two differ in how they
persist.

## Two possible fixes

**A. Mirror the emission points inside `sqlite.DB.RunScan`.**
Direct and local. But it duplicates the lifecycle logic in a second place, and
duplicated lifecycle logic is exactly how the two implementations drifted apart
to begin with. It fixes this instance and leaves the mechanism intact.

**B. Extract the shared scan-driving lifecycle so both implementations share
one progress-emitting path**, with each supplying only its own persistence.
More invasive, but it makes the class of defect impossible rather than merely
fixing today's instance.

**Recommendation: A now, B considered separately.** The defect is user-visible
and the fix should not be gated on a refactor. But B should be written down as
a follow-up rather than forgotten, because A leaves the root cause standing.
Scope item 3 — a conformance test over both implementations — is the cheap
mitigation that catches the next drift without requiring B.

## The coalescing constraint

Change 003 deliberately coalesced progress: emitting per-file on a 22,542-file
scan produced a callback storm that fanned out to WebSocket and DB writes.
`CHECKMATE_PROGRESS_INTERVAL` (250ms default) exists to bound that.

**The fix must emit through the coalescing path, not around it.** Reintroducing
per-file emission from the SQLite side would restore a defect 003 spent effort
removing — and it would do so silently, since the symptom is load-dependent and
would not show on a small test corpus.

The counter must also read `Position` rather than counting events. Counting
coalesced events under-reports by orders of magnitude, which is the trap 003
already documented.

## Testing

The current test suite passes with this defect present, which is the more
interesting problem. A test asserting only *"a scan completes"* cannot catch
`fileCount: 0`.

1. **Direct:** drive `sqlite.DB.RunScan` over a small fixture tree, collect
   progress events, assert non-zero and monotonic `Position` ending at the
   known file count.
2. **Conformance:** run the same assertions against **both** implementations
   from one table-driven test. This is what actually prevents recurrence — it
   converts "these two should behave alike" from a comment into a check.
3. **Regression:** assert the WebSocket summary's `fileCount` is non-zero, so
   the fix is verified at the layer the user observes rather than only at the
   layer it was made.

Test 3 matters because the persisted `file_count` is *already* correct — a test
asserting against the database would pass today and prove nothing.
