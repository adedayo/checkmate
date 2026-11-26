# Tasks: 006-account-wide-repository-discovery

**Status:** In progress — Scoped v1 implemented (Phases 1, 2, 3, 5, and CLI `checkmate account resolve` / `scan`). Persistent project enrolment, time-series membership, scheduled watch, webhooks, and REST API endpoints (Phases 4, 7, 8, 9) remain deferred for v2.

**Note on Decision #5 (R8 full-history default):** Kept `008`'s shallow (`--git-depth 1`) clone default in v1 with opt-in `--full-history` / `--git-depth 0`, because the current scan engine scans working trees rather than Git commit history objects; defaulting to full-history clones across up to 500 repos would incur heavy network/disk cost without additional detection until commit-history scanning is implemented.

## Decisions in force

| # | Decision |
|---|---|
| 1 | Anonymous by default (REST); token optional (GraphQL) for private repositories |
| 2 | Forks excluded by default, `includeForks` to opt in |
| 3 | Snapshot enrolment + opt-in account watch that enrols and scans new repositories (deferred to v2) |
| 4 | `CHECKMATE_ACCOUNT_MAX_REPOS` default 500, fail rather than truncate |
| 5 | Shallow working-tree clones by default in v1 (`--full-history` opt-in); revisit when commit-history scanning lands |
| 6 | Repository membership tracked as a time series; findings history independent of code retention (v2) |
| 7 | Checked-out code deleted after scan by default; retention opt-in, never coupled to history |

## Phase 1 — Primitive hygiene

- [x] Fix `github.GetRepositories` to propagate the paging error it currently logs
      and swallows (`pkg/gitservice/github/github.go`). An exhaustive
      resolver cannot otherwise distinguish completion from failure.
- [x] Test: a mid-pagination error surfaces to the caller (`pkg/gitservice/github/github_test.go`).

## Phase 2 — Resolver core (transport-agnostic)

- [x] `pkg/gitservice/account`: `AccountRef`, `AccountFilter`,
      `ResolvedRepository`, `AccountResolution`, `AccountResolver`, `repoLister`.
- [x] `ParseAccountRef`: URL, `provider:login`, login+serviceID; reject repository
      URLs with `ErrNotAnAccount`.
- [x] Filtering with per-filter exclusion counts; `excludeNames` beats
      `includeNames`; `includePrivate` records nothing on anonymous.
- [x] Canonical sort by clone URL — implemented **here only**.
- [x] `CHECKMATE_ACCOUNT_MAX_REPOS` cap (default 500); fail, never truncate.
- [x] Non-advancing-cursor / non-advancing-page detection.
- [x] Authentication state and `PotentiallyIncomplete` marking.

## Phase 3 — GitHub transports

- [x] **Anonymous REST lister:** `/users/{login}/repos`, `Link`-header pagination,
      `per_page=100`, `GET /users/{login}` for account type.
- [x] **Authenticated GraphQL lister:** `repositoryOwner(login:)` `__typename`
      probe for account type and cursor pagination behind `repoLister`.
- [x] Credential lookup: explicit token / `ServiceID`, else matching registered
      service, else env token, else anonymous. `ErrAmbiguousService` on multiple
      matches; `ErrInvalidCredential` on an explicit bad credential — never a
      silent anonymous fallback.
- [x] Rate-limit surfacing for both (60/hr anonymous, 5,000 pts/hr authenticated),
      `ErrRateLimited` recommending authentication when anonymous.
- [x] Fixture tests per transport: user, organisation, empty, single page, multi
      page, cap exceeded, rate limited, repository-URL-as-account.
- [x] **Transport conformance test:** same fixture account both ways ⇒ identical
      output for commonly-visible repositories.
- [x] Determinism test: shuffled page arrival ⇒ identical output, both transports.

## Phase 4 — Persistence

- [ ] Migration: `account_bindings` (provider, login, account type, service ID,
      filter JSON, authenticated, resolved-at, watch config).
- [ ] Migration: `repository_memberships` (first/last observed, state,
      absent-since, last resolution).
- [ ] Migration: `account_resolutions` — including **failed and unapplied**
      attempts, so gaps in monitoring are visible.
- [ ] Migration: `account_resolution_memberships` join, enabling point-in-time
      membership queries.
- [ ] `projects.Project.Account *AccountBinding`; nil for hand-entered projects.
- [ ] Membership transition logic: `present` ⇄ `absent`, operator-only
      `confirmed_removed`; `first_observed_at` immutable.
- [ ] Current-posture vs historical query helpers, with current posture as the
      default so a forgetful caller gets the conservative answer.
- [ ] Round-trip test; existing projects load unchanged.
- [ ] Test: `first_observed_at` survives disappear-then-reappear.
- [ ] Test: no table in this phase is affected by deleting checked-out code.

## Phase 5 — SDK

- [x] `ResolveAccount`, `ParseAccountRef`, `DefaultAccountFilter`, typed errors.
- [x] Test: no GitHub type in the exported surface.
- [x] Test: `AccountFilter{}` is not mistaken for defaults.
- [x] Test: anonymous resolution succeeds with no configuration at all.

## Phase 6 — Enrolment & scanning

- [ ] Enrolment: resolution ⇒ single `Project` with sorted `Repositories`.
- [ ] Idempotency on `(provider, login, workspace)` ⇒ `409`.
- [ ] Bounded-concurrency checkout, full history by default, shallow opt-in
      recorded on the scan.
- [ ] Per-repository failure isolation; summary counts attempted/succeeded/failed
      plus failure list.
- [ ] All-failed ⇒ scan failure, not a clean zero-finding scan.
- [ ] `potentiallyIncomplete` and `shallowClone` propagate into scan summary and
      reports.
- [ ] **Regression test for scan-engine exception 1:** two repositories with an
      identical vendored file ⇒ distinct `findingID`, correct `RepositoryIndex`.
- [ ] Checked-out code deleted after scan by default for account projects.
- [ ] Opt-in retention: `0700` checkout root, configurable disk budget,
      least-recently-scanned eviction.
- [ ] Test: `deleteAfterScan: true` leaves every finding, membership row,
      exception and scan summary intact.
- [ ] Document that retained checkouts contain plaintext secrets and change the
      security posture of the host. Do not let this become a footnote.

## Phase 7 — Re-resolution, membership & watch

- [ ] Diff with **four** categories: added, disappeared, newly-excluded-by-filter,
      unchanged. Disappeared and newly-excluded MUST NOT be merged.
- [ ] Side-effect free by default; reuses the stored filter.
- [ ] `apply=true` preserves project ID, scan history, findings, exceptions and
      membership history.
- [ ] Refuse `apply=true` on an auth downgrade (stored authenticated, current
      anonymous) — it would report every private repository as disappeared.
- [ ] Findings from `absent` repositories: excluded from current posture, retained
      in history, marked `unscanned` — never `resolved`/`fixed`/`remediated`.
- [ ] Exceptions retained through absence and reapplied on reappearance, not
      recreated.
- [ ] Watch: `robfig/cron` schedule, opt-in, off by default.
- [ ] Watch auto-enrols and scans newly appeared repositories; audit event each.
- [ ] Watch may set `absent`; MUST NOT set `confirmed_removed`.
- [ ] `lastObservedAt` advances on every resolution, including no-change ones.
- [ ] Every scheduled scan records the repository set it actually covered.
- [ ] Empty-where-previously-non-empty or failed resolution ⇒ not applied, alert
      raised, **and the failed attempt recorded**. Test this explicitly; it is the
      quiet-failure case.
- [ ] Watch respects the cap; stops and alerts rather than exceeding it.
- [ ] Reject watch schedules unsustainable within the applicable rate limit at
      configuration time.

## Phase 8 — Webhooks

- [ ] `account.repository.discovered`: project, account, repository, observation
      time. Fires on appearance, independent of findings.
- [ ] `account.repository.disappeared`: phrased as unknown-cause disappearance,
      not removal.
- [ ] Delta into `openspec/specs/webhooks/`.

## Phase 9 — API

- [ ] `POST /v1/accounts/resolve`, `POST /v1/accounts/enrol`,
      `POST /v1/projects/{projectId}/account/reresolve`,
      `GET|PUT|DELETE /v1/projects/{projectId}/account/watch`.
- [ ] `GET /v1/projects/{projectId}/repositories` with `?at=` point-in-time and
      `?state=` filtering; absent repositories included by default.
- [ ] `POST /v1/projects/{projectId}/repositories/{repositoryId}/confirm-removal`.
- [ ] Findings queries distinguish current posture from historical; current
      posture is the default.
- [ ] Trend and remediation endpoints report coverage alongside the numbers.
- [ ] Status codes: `400` not-an-account / unsustainable schedule, `401` bad
      explicit credential, `409` duplicate, `413` cap exceeded, `429` +
      `Retry-After` rate limited.
- [ ] CheckMate auth required on all endpoints outside dev mode, independent of
      GitHub auth state.
- [ ] Update `openspec/specs/api-contract/openapi.yaml`; Spectral lint passes.
- [ ] Progress events name the repository currently being scanned.

## Phase 10 — CLI & app

- [x] `checkmate account resolve <ref>` — prints the set, scans nothing, works with
      zero configuration.
- [x] `checkmate account scan <ref>` — resolve and scan in one pass.
- [ ] `checkmate account repos <project>` — membership incl. absent, `--at` (v2, depends on Phase 4).
- [x] Flags: `--service`, `--include-forks`, `--include-archived`, `--include`,
      `--exclude`, `--git-depth`/`--full-history`, `--max-repos`, `--retain-code`.
- [x] Pre-scan disclosure of repository count and total size (R15).
- [x] **Anonymous results visibly marked incomplete in CLI output.** This is the
      main place a user will misread a clean result.
- [ ] Desktop app: enrol-by-account entry point, incompleteness banner, re-resolve
      diff view, watch toggle (in sibling `checkmate-app` repo).

## Phase 11 — Docs

- [ ] `docs/features.md`: account-wide scanning, anonymous vs authenticated,
      filters, defaults, the cap, watch.
- [ ] Document snapshot-plus-watch semantics explicitly: the existing set is
      stable, new repositories are added by watch, removals are never automatic.
- [ ] Document that findings history is independent of checked-out code — deleting
      code loses nothing. `DeleteCheckedOutCode` currently reads as a retention
      policy and is not one; say so.
- [ ] Document that retained checkouts contain plaintext secrets, and that
      enabling retention makes the host a credential store.
- [ ] Document the difference between a finding that was fixed and one whose
      repository stopped being scanned.
- [ ] Document the anonymous rate limit (60/hr per IP) and that a token raises it
      as well as widening visibility.
- [ ] State plainly that an anonymous clean result says nothing about private
      repositories.

## Phase 12 — Archive

- [ ] Merge `specs/repository-discovery/` into `openspec/specs/`.
- [ ] Merge api-contract, sdk, data-store and webhooks deltas into their accepted
      specs.
- [ ] Add `repository-discovery` to accepted capabilities in `project.md`.
- [ ] Move `changes/006-account-wide-repository-discovery/` to `openspec/archive/`.
