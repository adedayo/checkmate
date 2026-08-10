# OpenSpec Proposal: 006-account-wide-repository-discovery

**Status:** Draft
**Capabilities:** `repository-discovery` (new), `api-contract`, `data-store`, `sdk`, `webhooks`
**Type:** Feature

## Goal

Let a user point CheckMate at a **GitHub account** — `https://github.com/adedayo`,
an organisation, or a bare login — and have every repository owned by that
account enrolled into a **single project** and scanned as one codebase, with one
scan ID, one score and one report.

**No credentials are required for the default case.** Anonymous resolution
answers "what is publicly exposed from this account?", which is the question most
worth making frictionless. Supplying a token widens the same operation to private
repositories.

## Motivation

CheckMate already has all the parts and none of the join.

- `pkg/gitservice/github.GetRepositories` can page an account's repositories over
  GraphQL (`projectsQuery` takes `user(login:)` / `organization(login:)`).
- `projects.Project.Repositories` is already a **list**, and the scan engine
  already scans multiple roots in one pass, tagging each finding with a
  `RepositoryIndex` (scan-engine R1).
- The desktop app and API can create a project from an explicit repository list.

What is missing is the step in between: turning an *account* into that list. Today
a user with 40 repositories adds 40 URLs by hand, and gets it wrong when the 41st
appears. The `discoverGitHub` handler that exists (`pkg/gitservice/api/github.go:59`)
is a **paged browse-and-pick UI feed**, not an enrolment mechanism: it requires a
pre-registered `ServiceID`, returns a cursor for the caller to drive, and produces
nothing that can be handed to project creation.

This is also the natural unit of a security question. "Do I have secrets in my
code?" is asked of an organisation, not of a repository. Answering it per
repository and asking the user to mentally union 40 reports is answering a
different question.

## Scope

1. **Account resolution.** Accept an account URL (`https://github.com/<login>`),
   a `github:<login>` shorthand, or a login plus an explicit service ID, and
   determine whether it is a user or an organisation without the caller having to
   say which. Resolution MUST work with no credentials.
2. **Two transports.** Anonymous resolution over the REST API; authenticated
   resolution over GraphQL. One provider-neutral result type from both.
3. **Exhaustive enumeration.** Page the account's repositories to completion —
   not the caller-driven single page that `discoverGitHub` returns — respecting
   GitHub rate limits and returning a stable, ordered list.
4. **Filtering at enrolment.** Archived, disabled and fork repositories are
   excluded by default; private repositories are included where a token can see
   them. Name globs allow include/exclude patterns.
5. **Enrolment into one project.** A single `Project` whose `Repositories` is the
   resolved set, so that the existing multi-root scan path is reused unchanged.
6. **Account watch.** An opt-in schedule that re-resolves a watched account and
   enrols and scans newly appeared repositories, for continuous attack surface
   monitoring.
7. **Membership history.** Repository appearance and disappearance tracked as a
   time series, with findings history durable and independent of it.
8. **Re-resolution.** An enrolled account can be re-resolved on demand so
   repositories created or archived since enrolment are picked up, without
   duplicating already-enrolled repositories or discarding their scan history.
9. **CLI, API and SDK surfaces** for the above.

## Non-Goals

- **No new scan engine behaviour.** Account scanning MUST reduce to an existing
  multi-repository scan. If it needs an engine change, the design is wrong.
- **GitLab, Bitbucket, self-hosted GitHub Enterprise.** The abstraction MUST be
  provider-neutral (`AccountResolver`), but only the GitHub implementation ships
  in this change. GitLab groups are the obvious follow-on and the interface
  exists to accommodate them; shipping two providers at once would test neither.
- **No credential storage change.** Account resolution uses the existing
  `gitutils.GitService` credential records. CheckMate does not gain a new secret.
- **No per-repository scheduling.** Monitoring cadence stays a project-level
  concern, as it is today.

## Guardrail Interactions

- **Guardrail 4 (stable finding identity)** already includes `repoURL`, so
  findings from 40 repositories in one project cannot collide. No change needed —
  but this change is the first to exercise that at scale, and MUST test it.
- **Guardrail 6 (determinism).** Enumeration order comes from a paged remote API.
  The resolved repository list MUST be sorted canonically before it is persisted,
  or `RepositoryIndex` — and therefore report grouping — becomes a function of
  network timing.
- **Scan-engine exception 1** records a defect where `RepositoryIndex` on
  vendor-rule findings reported the first scanned repository for all repositories
  in multi-repository scans. That defect was fixed in 003; this change makes
  multi-repository scans the *common* case rather than the rare one, so it MUST
  carry a regression test rather than trusting the fix.

## Risks

- **Blast radius.** Pointing at a large organisation can enrol thousands of
  repositories and hundreds of gigabytes of checkout. Enrolment MUST report the
  count and total size before cloning, and MUST be bounded by a configurable cap
  that fails loudly rather than silently truncating.
- **Rate limiting is now a first-order concern, not a footnote.** Anonymous REST
  is **60 requests/hour per IP** — roughly 6,000 repositories/hour at 100 per
  page, which sounds ample until several users share an egress IP, or an account
  watch re-resolves on a schedule. Authenticated GraphQL is 5,000 points/hour and
  far roomier. So the *default, zero-setup* path is the *most* rate-limited one,
  which is the opposite of the usual arrangement and easy to get wrong.
  Resolution MUST surface remaining quota, back off, and say plainly when it is
  rate-limited rather than reporting an empty account.
- **Silent scope narrowing.** Anonymous resolution of an account that owns
  private repositories returns only the public ones — correctly, but a user who
  forgot they were anonymous will read "3 repositories, no findings" as a clean
  bill of health for all 40. Every result MUST state whether it was authenticated
  and MUST NOT present a public-only result as complete.
- **Partial failure is the normal case.** With 200 repositories, some clone will
  fail — permissions, LFS, size. A scan that aborts wholesale on one bad
  repository is useless at this scale. Per-repository failures MUST be recorded
  and reported, and MUST NOT fail the scan.
- **Two transports, one contract.** REST and GraphQL return different shapes and
  differ in available fields. If they diverge in what they report, the same
  account scanned with and without a token differs for reasons unrelated to
  visibility. A conformance test over both is required, not optional.
- **Watch amplification.** A watched account that scans new repositories
  automatically can, on a large organisation with active development, trigger
  substantial unplanned clone and scan load. Watch MUST be bounded and MUST be
  opt-in.
- **One project or many?** Merging 200 repositories into one project makes the
  aggregate question answerable and the per-repository question harder. This is
  a deliberate trade; reports MUST retain per-repository breakdown.

## Resolved Decisions

Answered 2026-08-10. This proposal is no longer blocked.

1. **Unauthenticated by default.** `https://github.com/adedayo` MUST resolve with
   no credentials, returning public repositories. This is the headline use case:
   *what is publicly exposed?* — a question that should require no setup. A token
   is optional and extends the result to private repositories.

   **Consequence:** GitHub's GraphQL API requires authentication, so the
   unauthenticated path cannot use it. Two transports are therefore mandatory,
   not optional — REST for anonymous, GraphQL when a token is present. See
   `design.md`; this is the largest single piece of work in the change, and it
   was not visible before this decision.

2. **Forks excluded by default,** with `includeForks` available to opt in.

3. **Snapshot semantics,** with an opt-in **account watch** for continuous attack
   surface monitoring. The enrolled set is fixed at enrolment so scan-to-scan
   comparison stays meaningful, but a watched account re-resolves on a schedule
   and a newly appeared repository is enrolled and scanned. A new public
   repository is a new piece of attack surface, and noticing it late is the
   failure this feature exists to prevent.

   **Repository membership is tracked as a time series** — appearance and
   disappearance over time, not a current-state list — so "what were we scanning
   in March?" is answerable. **Findings history is durable and independent of
   this:** a repository disappearing never deletes its findings, and a finding
   that stops being reported because nobody looked is marked `unscanned`, never
   `resolved`.

4. **Enrolment cap 500,** overridable, failing rather than truncating.

5. **Full-history clones by default;** shallow is opt-in. Secrets committed and
   later removed are a substantial fraction of real leaks, and depth-1 cannot see
   them. Speed does not justify silently narrowing detection.

6. **Checked-out code is deleted after scan by default; retention is opt-in.**
   Code retention is decoupled from history entirely — no report, trend, finding
   or membership answer may depend on a working tree still existing. Retaining
   full-history clones of 500 repositories is both a disk problem and a security
   one: a retained checkout is a complete plaintext copy of every secret found,
   on the same host. Retention remains available because incremental fetch
   genuinely matters for nightly watch at organisation scale, but it is a stated
   choice with a documented cost. See `design.md` for the full argument.

## Open Questions

None outstanding.

## Success Criteria

| Dimension | Current | Target |
|---|---|---|
| Enrolling an account | manual, per repository | one URL |
| Repositories per project | practical limit ~tens, hand-entered | 500 default cap |
| Enumeration | one caller-driven page | exhaustive, paged, sorted |
| New repository in account | missed until noticed | picked up on re-resolution |
| Failed clone in a 200-repo scan | scan outcome undefined | recorded, scan completes |
| Repository disappearing | undefined | `absent`, findings retained, never `resolved` |
| "What were we scanning in March?" | unanswerable | point-in-time membership query |
| Posture trend vs coverage | trend alone | trend always reported with coverage |
| Report | one per repository | one project report, per-repository breakdown |
