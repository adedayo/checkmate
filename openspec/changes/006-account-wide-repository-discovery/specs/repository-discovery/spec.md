# Spec: Repository Discovery — Account-Wide Enrolment

**Change:** 006-account-wide-repository-discovery
**Status:** Draft

## Overview

This capability turns a **git hosting account** into a resolved, ordered set of
repositories that can be enrolled into a single CheckMate project and scanned as
one codebase.

It defines resolution, filtering, enrolment and re-resolution. It defines nothing
about detection or scan execution: an account scan MUST be indistinguishable, at
the scan engine boundary, from a multi-repository scan whose repository list was
typed in by hand.

## Governing Invariant

> Enrolling an account MUST produce a `projects.Project` whose `Repositories`
> field is the resolved set, and MUST NOT introduce any scan path that a
> hand-entered multi-repository project does not already take.

---

## Requirements

### R1 — Account reference forms

The system MUST accept an account reference in each of the following forms and
resolve them to the same account:

| Form | Example |
|---|---|
| Account URL | `https://github.com/adedayo` |
| Account URL with trailing slash | `https://github.com/adedayo/` |
| Provider-qualified shorthand | `github:adedayo` |
| Login + explicit service ID | `{"login":"adedayo","serviceId":"…"}` |

- A reference that resolves to a *repository* rather than an account (for example
  `https://github.com/adedayo/checkmate`) MUST be rejected with a distinct error,
  not silently treated as an account named `adedayo`.
- The system MUST NOT require the caller to state whether the login is a user or
  an organisation. It MUST determine the account type itself and MUST report the
  determined type in the resolution result.

### R2 — Credential-optional resolution and transport selection

Resolution MUST succeed with **no credentials**, returning the account's public
repositories.

- Where no usable credential is available, resolution MUST use the provider's
  anonymous transport (for GitHub, the REST API). GitHub's GraphQL API requires
  authentication and MUST NOT be attempted anonymously.
- Where a credential is available, resolution MUST use the authenticated
  transport (for GitHub, GraphQL) and include private repositories subject to
  `includePrivate`.
- Absence of a credential MUST NOT be an error. Only an explicitly supplied
  credential that is invalid or expired is an error, and it MUST NOT silently
  degrade to anonymous — a user who supplied a token and got public-only results
  has been misled about their coverage.
- Both transports MUST populate the same `Resolution` type. Fields unavailable on
  a transport MUST be explicitly absent rather than defaulted to a plausible
  value, and `sizeBytes` in particular MUST NOT be reported as `0` when it is
  merely unknown.

### R3 — Authentication visibility in results

Every resolution result MUST record whether it was authenticated, and where it
was, the identity or service ID used.

A result that is anonymous, or authenticated with a credential lacking
organisation visibility, MUST be marked as **potentially incomplete**. Consumers
— API responses, CLI output, reports, the desktop app — MUST surface that marker.

Rationale: the most dangerous output of this feature is a clean anonymous scan of
an account whose secrets are all in private repositories. The result is correct
and the conclusion drawn from it is wrong. The marker is what separates them, and
it is a requirement rather than a presentation detail.

### R4 — Exhaustive enumeration

Resolution MUST enumerate **all** repositories visible to the supplied
credentials — or publicly, where none are supplied — for the account, following
pagination to completion.

- The caller MUST NOT be required to drive pagination. The existing
  cursor-returning browse feed (`discoverGitHub`) is a distinct operation and is
  unchanged by this spec.
- Enumeration MUST terminate. A page that returns `hasNextPage: true` with an
  unchanged cursor MUST be treated as an error, not retried indefinitely.
- Enumeration MUST be bounded by a configurable maximum repository count
  (`CHECKMATE_ACCOUNT_MAX_REPOS`, default **500**). On exceeding the cap,
  resolution MUST fail with the observed count and MUST NOT return a truncated
  set.

### R5 — Deterministic ordering

The resolved repository list MUST be sorted by canonical clone URL, ascending,
byte-wise, before it is returned or persisted.

Rationale: `RepositoryIndex` is assigned by position in `Project.Repositories`,
and finding grouping in reports derives from it. Sorting makes enrolment order
independent of page arrival order and independent of transport, satisfying
Guardrail 6.

### R6 — Filtering

Resolution MUST apply a filter set, with these members:

| Filter | Default | Behaviour |
|---|---|---|
| `includeArchived` | `false` | Archived repositories excluded |
| `includeDisabled` | `false` | Disabled repositories excluded |
| `includeForks` | `false` | Forks excluded |
| `includePrivate` | `true` | Private repositories included where visible |
| `includeNames` | `[]` | Glob patterns; empty means all |
| `excludeNames` | `[]` | Glob patterns; applied after `includeNames` |

- Filtering MUST be applied at resolution time, and the result MUST record both
  the filtered set and the count excluded by each filter, so a surprising result
  is explainable without re-running.
- `excludeNames` MUST take precedence over `includeNames`.
- `includePrivate` has no effect on an anonymous resolution and MUST NOT be
  reported as having excluded anything there; the absence of private
  repositories in that case is covered by the R3 incompleteness marker.

### R7 — Enrolment as a single project

Enrolling a resolved account MUST create exactly one `projects.Project` with:

- `Repositories` set to the resolved, sorted set, each with
  `LocationType: "git"` and `GitServiceID` set to the resolving service where one
  was used.
- A single `ScanPolicy` applied to all repositories.
- Account provenance persisted on the project: provider, login, account type,
  service ID (where any), filter set, authentication state, and resolution
  timestamp.

A scan of that project MUST produce **one** scan ID, one score and one report
covering all repositories.

### R8 — Clone depth

Account scans MUST default to **full-history** clones.

Shallow (depth-1) cloning MUST be available as an explicit opt-in, and a scan
performed with it MUST be marked as such in its result. Secrets that were
committed and later removed are within CheckMate's detection scope, and a shallow
clone cannot see them; narrowing detection MUST therefore be a stated choice and
never a default taken for speed.

### R9 — Per-repository isolation of failure

A repository that cannot be checked out or scanned MUST NOT fail the scan.

- The failure MUST be recorded against that repository with the underlying error.
- The scan MUST continue with the remaining repositories.
- The scan result MUST report the count of repositories attempted, succeeded and
  failed, and a scan in which **any** repository failed MUST be distinguishable
  from one in which none did.
- A scan in which **every** repository failed MUST be reported as a failure, not
  as a clean scan with zero findings.

### R10 — Finding attribution

Every finding from an account scan MUST carry the `RepositoryURL` of the
repository it was found in.

- `findingID` remains `sha256(ruleID + repoURL + filePath + lineNumber +
  columnNumber + secretChecksum)` (Guardrail 4), so identical files in two
  repositories of the same account MUST yield two distinct findings.
- Vendor-rule findings MUST carry the correct `RepositoryIndex`, not that of the
  first-scanned repository. This is a regression guard on the defect recorded as
  exception 1 in the scan-engine spec, and MUST be covered by a test over at
  least two repositories containing an identical vendored file.

### R11 — Repository membership history

The set of repositories enrolled in an account project MUST be tracked as a
**time series**, not as a current-state list.

For every repository ever observed under the account, the system MUST persist:

| Field | Meaning |
|---|---|
| `firstObservedAt` | first resolution in which it appeared |
| `lastObservedAt` | most recent resolution in which it appeared |
| `membershipState` | `present` \| `absent` \| `confirmed-removed` |
| `absentSince` | first resolution in which it stopped appearing |
| `lastResolutionId` | resolution that produced the current state |

Requirements:

- A repository that stops appearing MUST transition to `absent`, **not** be
  deleted. `confirmed-removed` MUST be reachable only by explicit operator
  confirmation (R13).
- A repository that reappears MUST return to `present` with its original
  `firstObservedAt` intact and its absence interval retained. Reappearance is
  itself a signal — a repository flipped private and back, or deleted and
  recreated — and overwriting the record erases it.
- The system MUST be able to answer, for any past instant, which repositories
  were enrolled at that time. Attack surface monitoring is a question about
  change, and it cannot be answered from current state alone.
- Membership transitions MUST be recorded as auditable events carrying the
  resolution that caused them and its authentication state.

### R12 — Findings history is independent of membership

Findings MUST outlive the repositories they came from.

- Removing, archiving, or losing visibility of a repository MUST NOT delete,
  alter, or hide its historical findings.
- Findings belonging to a repository that is `absent` or `confirmed-removed`
  MUST be excluded from **current posture** figures and MUST remain available in
  **historical** views, and the two MUST be distinguishable in the API.
- A finding that disappears because its repository is no longer scanned MUST NOT
  be recorded as *resolved*, *fixed*, or *remediated*. It MUST carry a distinct
  state (`unscanned`) naming the reason.

Rationale: this is the difference between "we fixed 40 secrets" and "we stopped
looking at the repository containing them". Conflating them makes the security
posture trend — the primary output of continuous monitoring — silently
untrustworthy, and biased in the flattering direction. A tool whose numbers
improve when coverage shrinks is worse than one with no trend at all.

- Exceptions attached to a repository MUST be retained through absence and MUST
  reapply on reappearance rather than being recreated. An operator who triaged a
  finding once MUST NOT be asked to triage it again because of a transient
  visibility change.

### R13 — Re-resolution

An enrolled account MUST be re-resolvable against the provider.

Re-resolution MUST report, and MUST NOT apply without explicit confirmation:

- repositories **added** to the account since enrolment,
- repositories **disappeared** — no longer visible, for any reason,
- repositories **newly excluded by filter** (for example newly archived),
- repositories **unchanged**.

"Disappeared" and "newly excluded" MUST be reported as distinct categories. The
first is a change in the account or in visibility; the second is a change the
stored filter predicted. Merging them hides which one happened.

Applying a re-resolution MUST preserve the project ID, its scan history, all
existing exceptions keyed to repositories that remain enrolled, and the full
membership history under R11.

Re-resolution MUST reuse the filter set stored at enrolment, so that a diff
reflects change in the account rather than change in the query.

### R14 — Account watch (continuous attack surface monitoring)

An enrolled account MAY be placed under **watch**. Watch is opt-in and MUST be
off by default.

A watched account MUST:

- re-resolve on a configurable schedule via the existing `robfig/cron` scheduler,
  reusing the stored filter set;
- **automatically enrol** repositories that have appeared since the last
  resolution, and scan them;
- update repository membership history per R11 on every resolution, whether or
  not anything changed — `lastObservedAt` advancing is itself evidence that the
  repository was looked for and found;
- record each automatic enrolment as an auditable event carrying the repository,
  the time it was first observed, and the resolution that introduced it;
- emit a webhook event on newly observed repositories, so appearance of new
  attack surface is notifiable independently of findings.

Constraints:

- Watch MUST NOT automatically **remove** repositories, and MUST NOT transition
  one to `confirmed-removed`. Disappearance may mean deletion, privacy change,
  or a transient API failure. Watch MAY move a repository to `absent`, which is
  reversible and destroys nothing. Confirmation is an operator action, per R13.
- A resolution that fails, or returns an empty set where the previous resolution
  was non-empty, MUST be treated as suspect: it MUST NOT be applied, and MUST
  raise an alert. Silent scope collapse would turn a monitoring feature into a
  false assurance.
- Automatic enrolment MUST respect `CHECKMATE_ACCOUNT_MAX_REPOS` and MUST stop
  and alert rather than exceed it.
- Snapshot semantics still hold for the *existing* set: a scheduled scan of
  unchanged repositories covers the same set as the previous scan, so
  scan-to-scan comparison remains meaningful. Watch adds to the set; it does not
  make the set fluid.
- Every scheduled scan MUST record the repository set it actually covered, so a
  posture trend can be read against coverage rather than in isolation.

### R15 — Pre-enrolment disclosure

Before any repository is cloned, resolution MUST report the number of
repositories resolved and, where the provider supplies it, their aggregate size.

Rationale: an organisation scan can be three orders of magnitude larger than the
user expects, and the first signal of that MUST NOT be a full disk.

### R16 — Checked-out code retention

Checked-out repository content is **working data, not history**. Findings history
(R12) and membership history (R11) MUST be complete and durable regardless of
whether any checked-out code is retained.

- Retention of checked-out code MUST NOT be required for any historical query.
  No report, trend, finding, or membership answer may depend on the working tree
  still existing.
- For account projects, checked-out code MUST be deleted after scan by default.
- Retention MAY be enabled explicitly, and where enabled:
  - the checkout root MUST be created with owner-only permissions (`0700`);
  - retained content MUST be subject to a configurable disk budget, evicted
    least-recently-scanned first, and eviction MUST NOT affect findings or
    membership history;
  - the system MUST document that retained checkouts contain **plaintext secret
    values**, which Guardrail 3 excludes from CheckMate's own storage but which
    are unavoidably present in the source it scans.
- Deleting checked-out code MUST never delete findings, exceptions, membership
  records or scan summaries.

Rationale: the retention decision is a disk-and-exposure trade with no bearing on
what CheckMate remembers. Coupling the two — as `DeleteCheckedOutCode` invites —
would make an operator choose between disk headroom and historical accuracy.

### R17 — Rate limit behaviour

- Resolution MUST surface the provider's remaining rate-limit quota in its result.
- On a rate-limit response, resolution MUST back off and retry within the
  provider-supplied reset window rather than failing immediately, up to a bounded
  number of attempts.
- Exhausting those attempts MUST fail with an error naming the rate limit, and
  MUST NOT be reported as "account not found" or "no repositories".
- The anonymous transport is subject to a substantially tighter per-IP limit
  (GitHub REST: 60 requests/hour). Because this is the **default** path,
  resolution MUST report remaining anonymous quota in its result and MUST
  recommend authentication in the rate-limited error rather than merely failing.
- Watch schedules MUST account for this limit; a watch interval that cannot be
  sustained within quota MUST be rejected at configuration time, not discovered
  at runtime.

### R18 — Provider neutrality

Resolution MUST be expressed behind a provider-neutral interface:

```go
type AccountResolver interface {
    Supports(ref AccountRef) bool
    Resolve(ctx context.Context, ref AccountRef, f Filter) (Resolution, error)
}
```

Only the GitHub implementation is in scope for this change, in both its anonymous
and authenticated transports. No GitHub type (`GitHubProject`, cursor, GraphQL or
REST payload) may appear in the interface, in `Resolution`, or in any persisted
project field.

### R19 — Credentials

- Resolution MUST use existing `gitutils.GitService` records for credentials and
  MUST NOT introduce a new credential store.
- A token MUST NOT be written into `Project.Repositories[].Location` or any other
  persisted field.
- Where an account reference supplies no service ID, the system MUST select a
  registered service matching the provider and instance. Where none matches, it
  MUST proceed anonymously rather than fail. Where more than one matches, it MUST
  fail with `ErrAmbiguousService` rather than choose.

---

## Out of Scope

- GitLab groups and Bitbucket workspaces (interface accommodates, implementation
  does not ship).
- Changes to detection, chunking, or scan concurrency.
- Per-repository scan schedules. Watch (R14) is an account-level schedule.
- Any change to the `discoverGitHub` browse feed.
