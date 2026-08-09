# OpenSpec Tasks: 005-sqlite-progress-reporting

## Phase 1: Establish a failing test first

> The defect is currently invisible to the whole suite. Writing the fix first
> would leave no proof the test can detect the fault.

- [ ] **1.1** Test driving `sqlite.DB.RunScan` over a small fixture tree,
  collecting `diagnostics.Progress` events.
- [ ] **1.2** Assert non-zero, monotonic `Position` reaching the known file
  count. **Confirm it fails** against current `main`.
- [ ] **1.3** Assert the WebSocket summary's `fileCount` is non-zero.

  Must assert at the API layer, not the DB: persisted `file_count` is already
  correct (22,591 on the Phase 10 corpus), so a DB-level assertion passes today
  and proves nothing.

## Phase 2: Emit progress

- [ ] **2.1** Map `simpleProjectManager`'s emission points
  (`management.go:903, 938, 953, 965, 988, 997, 1006, 1018`) onto the SQLite
  lifecycle. Match semantics, not line placement — the two persist differently.
- [ ] **2.2** Emit from `sqlite.DB.RunScan`.
- [ ] **2.3** Emit through the **coalescing** path, not around it.

  Per-file emission on a 22,542-file scan is the callback storm that 003
  removed. Reintroducing it would be silent: the symptom is load-dependent and
  will not appear on a small test corpus.
- [ ] **2.4** Derive the count from `Position`, not from counting events.
  Counting coalesced events under-reports by orders of magnitude.
- [ ] **2.5** Confirm Phase 1 tests now pass.

## Phase 3: Prevent recurrence

- [ ] **3.1** Table-driven conformance test running the same progress
  assertions against **both** `ProjectManager` implementations.

  This is the task that addresses the root cause. An unused parameter is not a
  compile error in Go, so nothing but a test can detect the next silent
  divergence.
- [ ] **3.2** Audit `sqlite.DB` for other accepted-but-unused parameters, since
  the same class of defect may exist elsewhere in the same file.

## Phase 4: Verify at scale

- [ ] **4.1** Re-run `tools/e2echeck` against the 22,542-file corpus; confirm
  progress arrives and `fileCount` is correct.
- [ ] **4.2** Confirm no throughput regression against the 97s baseline.

  A progress fix that reintroduces fan-out would partly undo 003's 6.0×
  improvement.
- [ ] **4.3** Confirm findings remain byte-identical. Progress reporting must
  not perturb the finding set.

## Phase 5: Close out

- [ ] **5.1** Update `docs/features.md` if user-visible progress behaviour
  changes.
- [ ] **5.2** Note in the archived 003 record that its filed follow-up is
  resolved.
- [ ] **5.3** Consider follow-up: extract the shared scan lifecycle so both
  implementations use one progress-emitting path (design option B). This change
  fixes the instance; it does not remove the duplication that caused it.
- [ ] **5.4** Merge spec delta into `openspec/specs/` and archive.
