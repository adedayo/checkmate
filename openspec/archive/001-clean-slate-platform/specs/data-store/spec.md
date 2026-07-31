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
