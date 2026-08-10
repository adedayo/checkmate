# Spec Delta: Data Store — Membership & Findings History

**Change:** 006-account-wide-repository-discovery
**Status:** Draft
**Delta against:** `openspec/specs/data-store/`

## Added Schema

All migrations are additive and nullable. Existing projects load unchanged with
no backfill.

### `account_bindings`

One row per account-derived project: provider, login, account type, service ID
(nullable), filter JSON, `authenticated`, `resolved_at`, watch configuration.

Storing the **filter** is what makes re-resolution a diff of the account rather
than a diff of the query. Storing `authenticated` is what lets an
authenticated-then-anonymous re-resolution be recognised as an auth downgrade
rather than a mass disappearance.

### `repository_memberships`

One row per `(project_id, repository_location)` ever observed:

| Column | Notes |
|---|---|
| `first_observed_at` | never updated after insert |
| `last_observed_at` | advanced on every resolution that sees it |
| `membership_state` | `present` \| `absent` \| `confirmed_removed` |
| `absent_since` | set on transition to `absent`, cleared on reappearance |
| `last_resolution_id` | FK to `account_resolutions` |

Requirements:

- Rows MUST NOT be deleted when a repository disappears. `DELETE` on this table
  is reserved for project deletion.
- `first_observed_at` MUST be immutable. A reappearing repository MUST update
  `membership_state` and `last_observed_at` only.
- The table MUST support point-in-time queries — "which repositories were
  `present` at time *T*" — via `account_resolution_memberships` below.

### `account_resolutions`

One row per resolution attempt: timestamp, authenticated flag, transport,
outcome, repository count, rate-limit state, and whether it was applied.

Failed and unapplied resolutions MUST be recorded too. "We could not look" is a
distinct fact from "we looked and found nothing", and a gap in monitoring is only
visible if the failed attempt is stored.

### `account_resolution_memberships`

Join of resolution to the repositories it observed. This is what makes membership
a genuine time series rather than a current-state row with timestamps on it, and
what allows `GET /v1/projects/{id}/repositories?at=<t>` to be answered exactly.

## Modified

- `findings` gain no new column; membership state is derived by joining
  `repository_memberships` on repository location. Denormalising it onto findings
  would require rewriting historical rows whenever a repository's state changed,
  which is both expensive and a way to corrupt history.
- Scan summaries gain the covered repository set, so a posture trend can be read
  against coverage.

## Retention Requirements

- Deleting checked-out code MUST NOT touch any table in this delta. Code
  retention and data retention are independent (`repository-discovery` R16).
- Findings, exceptions, membership rows and resolutions MUST survive repository
  disappearance, absence, and confirmed removal.
- Project deletion remains the only operation that removes them.

## Query Requirements

- Current posture queries MUST filter to `membership_state = 'present'`.
- Historical queries MUST NOT filter by membership state.
- The default for any dashboard, score or trend MUST be current posture, and the
  distinction MUST be explicit at the query layer rather than left to callers.
  A caller that forgets which one it wanted gets the conservative answer.
