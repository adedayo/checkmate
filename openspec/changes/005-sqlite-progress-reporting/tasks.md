# OpenSpec Tasks: 005-sqlite-progress-reporting

## Phase 1: Establish a failing test first

> The defect is currently invisible to the whole suite. Writing the fix first
> would leave no proof the test can detect the fault.

- [x] **1.1** Test driving `sqlite.DB.RunScan` over a small fixture tree,
  collecting `diagnostics.Progress` events. `pkg/store/sqlite/progress_test.go`.
- [x] **1.2** Assert non-zero, monotonic `Position` reaching the known file
  count. **Confirmed failing** against `e6eee16` with
  *"RunScan emitted no progress events; progressMonitor is accepted but never
  invoked"*, then passing after the fix.
- [x] **1.3** Assert the WebSocket summary's `fileCount` is non-zero.

  Asserted at the progress layer the summary is derived from, not against
  persisted `file_count`: that column was already correct (22,591) while
  progress was entirely absent, so asserting on it would have passed both
  before and after and proved nothing.

## Phase 2: Emit progress

- [x] **2.1** Mapped `simpleProjectManager`'s emission points onto the SQLite
  lifecycle.

  The root cause was narrower than the proposal assumed. `sqlite.DB.RunScan`
  does not call `scanner.Scan` at all — it calls `secrets.SearchSecretsOnPaths`
  directly, and *that function had no progress parameter*. So the callback was
  not merely unused; there was no route by which it could have been called.
- [x] **2.2** Added `secrets.SearchSecretsOnPathsWithProgress`, with
  `SearchSecretsOnPaths` delegating to it with a nil callback. Additive, so the
  CLI and SDK signatures are untouched.
- [x] **2.3** Emitted through the **coalescing** reporter, not per file.
  Measured 399–418 events for 22,591 files — approximately 4/second at the
  250ms default, as intended.
- [x] **2.4** Count derived from `Position` via `FileDone`, not from counting
  events.
- [x] **2.5** Phase 1 tests pass; `-race` clean.

## Phase 3: Prevent recurrence

- [ ] **3.1** Table-driven conformance test running the same progress
  assertions against **both** `ProjectManager` implementations.

  Not done. The two implementations diverge more deeply than a shared test can
  paper over — one drives `scanner.Scan`, the other calls the finder directly —
  so a genuine conformance test needs the lifecycle extraction in 5.3 first.
- [ ] **3.2** Audit `sqlite.DB` for other accepted-but-unused parameters.

  Not done. Note `RunScan` also accepts a `scanner` argument it never uses,
  which is the same class of defect and currently harmless only by luck.

## Phase 4: Verify at scale

- [x] **4.1** `tools/e2echeck` against the 22,542-file corpus: progress arrives,
  final position 22,591/22,591 (previously 0).

  The harness itself was discarding progress, which is part of why this went
  unnoticed. It now counts and reports it.
- [x] **4.2** Throughput: **100.2s / 101.6s vs a 97s baseline — a real ~3–4%
  regression**, consistent across runs and not measurement noise.

  This is the cost of an atomic increment and pointer store per file across
  22,591 files. Judged an acceptable trade for progress reporting that works at
  all, but recorded as a cost rather than described as free.
- [x] **4.3** Findings byte-identical: 11,575 before and after, `cmp` clean
  against a worktree at `e6eee16`.

## Phase 5: Close out

- [ ] **5.1** Update `docs/features.md` if user-visible progress behaviour
  changes.
- [ ] **5.2** Note in the archived 003 record that its filed follow-up is
  resolved.
- [ ] **5.3** Consider follow-up: extract the shared scan lifecycle so both
  implementations use one progress-emitting path (design option B). This change
  fixes the instance; it does not remove the duplication that caused it.
- [ ] **5.4** Merge spec delta into `openspec/specs/` and archive.
