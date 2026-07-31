# Spec: Exception Management

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

Exceptions are first-class DB entities that suppress specific findings from scan results. They replace the legacy hand-edited `.checkmate.yaml` approach with a full CRUD API, audit trail, expiry tracking, and bulk import/export.

## Data Model

Each exception is a row in the `exceptions` table with the following key fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | TEXT (PK) | Prefixed `exc_` + 12-char UUID fragment |
| `rule_id` | TEXT | Rule this exception applies to, or `*` for all rules at this scope |
| `scope_type` | TEXT | One of: `value`, `line`, `file`, `directory`, `project`, `global` |
| `scope_json` | JSON | `{ repoUrl, path, lineStart, lineEnd, secretChecksum }` |
| `reason` | TEXT | Structured reason: `false_positive`, `test_data`, `revoked`, `acceptable_risk`, `mitigated` |
| `justification` | TEXT | Free-text explanation |
| `created_by` | TEXT | User or system identity |
| `created_at` | TEXT | RFC 3339 timestamp |
| `expires_at` | TEXT | RFC 3339 timestamp or NULL (permanent) |
| `status` | TEXT | `active`, `expired`, `revoked` |
| `evidence_json` | JSON | `{ fileHash, commitSha }` for drift detection |
| `tags` | JSON | Array of user-defined tags |

## Scope Hierarchy

Exception scopes form a narrowing hierarchy:

```
global → project → directory → file → line → value
```

A `value`-scoped exception matches by `secretChecksum` — it follows the secret wherever it moves. A `line`-scoped exception is pinned to `(repoUrl, path, lineStart, lineEnd)`. A `global` exception suppresses the rule everywhere.

## Audit Trail

Every mutation to an exception generates an immutable row in the `audit_log` table:

- **action:** `exception.created`, `exception.updated`, `exception.revoked`
- **actor:** User or `system`
- **resource_type:** `exception`
- **resource_id:** The exception ID
- **diff:** Free-text description of the change

Audit events are returned inline on `GET /v1/exceptions/{id}` as the `auditTrail` array.

## Expiry

- When `expires_at` is set, the exception becomes inactive after that timestamp.
- The API filters expired exceptions from active suppression but retains them in the database for audit purposes.
- Status transitions: `active → expired` (automatic) or `active → revoked` (manual via `DELETE`).

## Drift Detection

The `evidence_json` field captures the file hash and commit SHA at exception creation time. Future drift detection can compare current file state against the evidence to flag exceptions that may no longer be valid (not yet implemented — deferred).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/exceptions` | List all exceptions |
| `POST` | `/v1/exceptions` | Create a new exception |
| `GET` | `/v1/exceptions/{exceptionId}` | Get exception by ID (includes audit trail) |
| `PATCH` | `/v1/exceptions/{exceptionId}` | Update mutable fields (expiry, justification, tags) |
| `DELETE` | `/v1/exceptions/{exceptionId}` | Soft-delete: marks status as `revoked` |
| `GET` | `/v1/exceptions/export` | Export all active exceptions as JSON |
| `POST` | `/v1/exceptions/import` | Bulk import exceptions from JSON |
| `POST` | `/v1/exceptions/validate` | Validate an exception payload without persisting |

### Create Request

Required fields: `ruleId`, `scope` (object with `type`), `reason`. The server assigns `id`, `createdAt`, and initial `status = active`.

### Update Request (PATCH)

Mutable fields: `expiresAt`, `justification`, `tags`. Each update appends an `exception.updated` audit event.

### Import/Export

- **Export** returns only `active` exceptions (filters out `revoked`). Content-Disposition header suggests `checkmate.json`.
- **Import** accepts a JSON array of exception objects. Returns `{ imported, skipped, errors }`. Existing IDs are skipped.

## Interplay with Findings

When a scan produces findings, the exception engine matches active exceptions against each finding by `(rule_id, scope)`. Matched findings have `suppressed = 1` and `exception_id` set in the `findings` table.
