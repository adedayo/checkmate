# Spec Delta: API Contract — Account Resolution & Enrolment

**Change:** 006-account-wide-repository-discovery
**Status:** Draft
**Delta against:** `openspec/specs/api-contract/`

All routes are under `/v1/` per project convention. `openapi.yaml` MUST be
updated in the same change and MUST pass Spectral lint.

## Added Endpoints

### `POST /v1/accounts/resolve`

Resolve an account reference to a repository set **without** creating a project.

Request:

```json
{
  "reference": "https://github.com/adedayo",
  "serviceId": "optional-git-service-uuid",
  "filter": {
    "includeArchived": false,
    "includeDisabled": false,
    "includeForks": false,
    "includePrivate": true,
    "includeNames": [],
    "excludeNames": []
  }
}
```

Response `200`:

```json
{
  "provider": "github",
  "login": "adedayo",
  "accountType": "user",
  "authenticated": false,
  "serviceId": null,
  "potentiallyIncomplete": true,
  "incompletenessReason": "anonymous: private repositories not visible",
  "repositories": [
    { "location": "https://github.com/adedayo/checkmate.git",
      "name": "checkmate", "private": false, "fork": false,
      "archived": false, "sizeBytes": 10485760, "defaultBranch": "main" }
  ],
  "resolvedCount": 37,
  "excludedCounts": { "archived": 4, "disabled": 0, "forks": 11, "name": 0 },
  "totalSizeBytes": 812345678,
  "rateLimit": { "remaining": 54, "limit": 60, "resetAt": "2026-08-10T12:00:00Z" }
}
```

- MUST be side-effect free: no project, no clone, no scan.
- MUST succeed with no `serviceId` and no credentials, returning public
  repositories with `authenticated: false`.
- `potentiallyIncomplete` MUST be `true` for any anonymous resolution, and
  `incompletenessReason` MUST be populated when it is. Clients MUST surface it;
  a client rendering an anonymous result as a complete account picture is
  non-conforming (`repository-discovery` R3).
- `repositories` MUST be sorted per `repository-discovery` R5, identically on
  both transports.
- An explicitly supplied `serviceId` whose credential is invalid MUST return
  `401` and MUST NOT silently fall back to anonymous.
- Exceeding `CHECKMATE_ACCOUNT_MAX_REPOS` (default 500) MUST return `413` with
  the observed count, and MUST NOT return a truncated list.
- A reference naming a repository rather than an account MUST return `400` with
  a distinct error code, not a resolution of the owner.
- Rate-limit exhaustion MUST return `429` with `Retry-After`, and the error body
  MUST recommend authentication when the resolution was anonymous.

### `POST /v1/accounts/enrol`

Resolve and create a single project from the result.

Request: the `resolve` body plus `name`, `workspace`, `description`, and an
optional `scanPolicy`. Response is the created `Project`, `201`.

- MUST be idempotent on `(provider, login, workspace)`: a second call MUST return
  `409` referencing the existing project rather than creating a duplicate.
- MUST NOT begin a scan. Scanning is the existing scan endpoints, unchanged.

### `POST /v1/projects/{projectId}/account/reresolve`

Re-resolve the enrolled account and return a **diff**, per `repository-discovery` R13.

Response `200`:

```json
{ "added": [ … ], "removed": [ … ], "unchanged": 34, "apply": false }
```

- With `?apply=true`, applies the diff and returns the updated project.
- Without it, MUST be side-effect free.
- MUST reuse the filter set stored at enrolment.
- MUST return `400` if the project was not created from an account.
- If the stored binding was authenticated and the re-resolution is anonymous, the
  response MUST flag the auth downgrade, and `?apply=true` MUST be **refused**.
  Applying it would report every private repository as removed.

### `PUT /v1/projects/{projectId}/account/watch`

Enable or configure account watch, per `repository-discovery` R14.

```json
{ "enabled": true, "schedule": "0 3 * * *", "autoScanNewRepositories": true }
```

- Watch MUST be disabled by default.
- A `schedule` whose request rate cannot be sustained within the applicable rate
  limit MUST be rejected at `400` here, not discovered at runtime.
- `DELETE` disables watch.
- `GET` returns current watch configuration and the last resolution outcome.

### `GET /v1/projects/{projectId}/repositories`

Current membership, with history, per `repository-discovery` R11.

```json
{
  "repositories": [
    { "location": "https://github.com/acme/api.git",
      "membershipState": "present",
      "firstObservedAt": "2026-01-04T09:12:00Z",
      "lastObservedAt": "2026-08-10T03:00:00Z",
      "absentSince": null }
  ],
  "counts": { "present": 34, "absent": 2, "confirmedRemoved": 1 }
}
```

- MUST support `?at=<timestamp>` returning membership **as it stood** at that
  instant. Attack surface monitoring is a question about change and cannot be
  answered from current state alone.
- MUST support `?state=present|absent|confirmed-removed`.
- Absent repositories MUST be included by default, not filtered out. Their
  absence is the interesting part.

### `POST /v1/projects/{projectId}/repositories/{repositoryId}/confirm-removal`

Operator confirmation moving an `absent` repository to `confirmed-removed`.

- MUST NOT delete findings, exceptions or membership history.
- MUST be reversible by re-resolution observing the repository again.

## Findings

Finding representations gain a `repositoryMembershipState` field, and finding
queries MUST distinguish:

- **current posture** — findings in `present` repositories only, the default for
  any dashboard or score;
- **historical** — all findings ever recorded, including those from `absent` and
  `confirmed-removed` repositories.

A finding whose repository is no longer scanned MUST carry state `unscanned`, and
MUST NOT be reported as `resolved`, `fixed` or `remediated`
(`repository-discovery` R12). Any endpoint returning remediation counts or trends
MUST report coverage alongside them — the number of repositories scanned in the
period — so an improvement caused by shrinking coverage is visible rather than
flattering.

## Webhook Events

A new event type `account.repository.discovered` MUST be emitted when watch
observes a repository not previously enrolled, carrying the project, the account,
the repository, and the observation time.

This event fires on *appearance*, independently of whether the subsequent scan
finds anything. New public attack surface is itself the signal.

A second event `account.repository.disappeared` MUST be emitted when a previously
present repository stops appearing. It MUST state that the cause is unknown —
deletion, visibility change, or API failure are indistinguishable from outside —
and MUST NOT be phrased as removal.

## Modified

- `Project` representations gain an optional `account` object
  (`provider`, `login`, `accountType`, `serviceId`, `filter`, `authenticated`,
  `resolvedAt`, `watch`). Absent for hand-entered projects. MUST be additive —
  existing clients that ignore it MUST continue to work.
- Scan summary representations gain `repositoriesAttempted`,
  `repositoriesSucceeded`, `repositoriesFailed`, and a `repositoryFailures`
  array of `{location, error}` per `repository-discovery` R9.
- Scan summaries for account projects MUST carry `shallowClone` and the
  resolution's `potentiallyIncomplete` marker, so a report cannot be read as
  more complete than the scan behind it.

## Streaming

Per project convention, progress for an account scan flows over the existing
WebSocket and SSE scan streams. No new stream is added. Progress events MUST
identify the repository currently being scanned so a 200-repository scan is
legible while it runs.

## Auth

All endpoints require an authenticated CheckMate session or a scoped API key
outside `CHECKMATE_DEV_MODE`.

Note the distinction that matters here: **CheckMate authentication** and **GitHub
authentication** are independent. Anonymous *GitHub* resolution is the default and
requires no token; it is still only reachable by an authenticated *CheckMate*
caller, because resolution consumes shared rate-limit quota and can enumerate
private repositories when a service is configured.
