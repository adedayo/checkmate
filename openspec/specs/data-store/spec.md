# Spec: Data Store — SQLite

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

Replaces the Badger KV store (`checkmate-badger-project-manager`) with a relational SQLite database via `modernc.org/sqlite` (CGO-free, pure Go).

## Driver Choice

`modernc.org/sqlite` — a pure-Go port of the SQLite C library. No CGO, no C compiler, single static binary cross-compiles for all targets. WAL mode enabled for concurrent read performance.

## Migration Tool

`golang-migrate/migrate/v4` — versioned SQL migration files embedded in the binary via `embed.FS`. Applied automatically at startup.

## Schema

See `pkg/store/sqlite/migrations/001_initial_schema.up.sql` for the full schema.

Key tables:
- `projects` — project metadata + full serialised JSON
- `scans` — scan lifecycle (queued/running/complete/failed)
- `findings` — individual secrets, stable deterministic `finding_id`
- `exceptions` — suppression rules with expiry and audit trail
- `audit_log` — immutable record of all mutations
- `api_keys` — bcrypt-hashed API key records (plaintext never stored)
- `git_config` — singleton GitServiceConfig
- `webhooks` — registered push notification endpoints

## Finding ID Stability

`finding_id = sha256(rule_id + repo_url + file_path + line_number + column_number + secret_checksum)`

Same physical secret across different scans always has the same `finding_id`. The `findings` table uses a composite primary key `(finding_id, scan_id)` so the same finding appears once per scan while remaining deduplicated by stable ID.

## Connection Settings

```go
db.SetMaxOpenConns(1)   // single writer — prevents SQLITE_BUSY
db.SetMaxIdleConns(1)
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

## Scan Progress Reporting

Merged from change 005-sqlite-progress-reporting.

`projects.ProjectManager` has two implementations. Before v1.5.0
`simpleProjectManager` emitted progress and `sqlite.DB` accepted the same
`progressMonitor func(diagnostics.Progress)` and emitted none, so every desktop
scan reported `fileCount: 0` until it completed.

- **R1** — An implementation accepting `progressMonitor` MUST invoke it across
  the scan lifecycle. Accepting the parameter and ignoring it is a defect, not
  an implementation choice. Go does not error on unused function parameters, so
  this cannot be caught by the compiler and MUST be covered by a test.
- **R2** — Emission MUST pass through the coalescing path bounded by
  `CHECKMATE_PROGRESS_INTERVAL` (default 250ms), never per file. Per-file
  emission produces the callback storm change 003 removed, and would reappear
  silently because the symptom is load-dependent and absent on small corpora.
- **R3** — File counts MUST derive from `Position`, not from counting events.
  Counting coalesced events under-reports by orders of magnitude.
- **R4** — The observable count MUST be non-zero and monotonic, and MUST be
  asserted at the progress layer the summary derives from. Asserting against
  persisted `file_count` proves nothing: it was already correct while progress
  was entirely absent.
- **R6** — Progress reporting MUST NOT alter the finding set. Guarded by the
  existing `scan-engine` equivalence tests; verified byte-identical over 11,575
  findings.

### Accepted exception: R5 is not met

R5 as drafted required progress obligations to be verified against all
implementations from a shared, table-driven conformance test. **This is not
implemented.** The two implementations do not share a scan lifecycle — one
drives `scanner.Scan`, the other calls the secrets finder directly — so a
shared test could only assert what they already have in common, which would
pass without constraining the behaviour that broke.

Recorded rather than quietly dropped, because R5 addresses the root cause and
R1–R4 only address the instance. It is blocked on extracting a shared scan
lifecycle, filed as a follow-up in change 005.

Known consequence of the same root cause, still open: `sqlite.DB.RunScan` also
ignores the `wsSummariser` parameter that `simpleProjectManager` honours, so
workspace summaries are not recomputed after a SQLite-backed scan.
