# Design: 006-account-wide-repository-discovery

**Status:** Draft
**Decisions resolved:** 2026-08-10 (see `proposal.md`)

## Two transports, because the default is anonymous

The decision that anonymous resolution is the default is the one that most shapes
this design, and it is worth being explicit about why.

GitHub's **GraphQL API requires authentication.** There is no anonymous GraphQL.
So the existing `pkg/gitservice/github` code — `projectsQuery`, `queryProjects`,
the cursor machinery — is unusable for the default path. Anonymous resolution
must go over REST:

| | Anonymous | Authenticated |
|---|---|---|
| Transport | REST `/users/{login}/repos` | GraphQL `projectsQuery` |
| Pagination | `Link` header, `page`/`per_page` | cursor, `pageInfo.endCursor` |
| Rate limit | **60/hour per IP** | 5,000 points/hour |
| Page size | 100 max | 100 practical |
| Private repositories | never | subject to visibility |

Two paging models, two rate-limit models, two error shapes. This is the largest
piece of work in the change, and it was not visible until the anonymous default
was chosen. Planning as though the existing GraphQL code covers most of the
provider work would badly under-estimate this.

The mitigation is a narrow seam. Both transports implement:

```go
type repoLister interface {
    List(ctx context.Context, login string, p pageToken) ([]ResolvedRepository, pageToken, error)
}
```

Everything above it — filtering, sorting, cap, dedup, assembly of `Resolution` —
is transport-agnostic and written once. If filtering or sorting appears inside
either transport implementation, the seam is in the wrong place.

**A conformance test over both is mandatory** (spec R2): the same fixture account
resolved anonymously and authenticated must agree, field for field, on every
repository visible to both. Without it, "I scanned with a token and got different
results" becomes an unfalsifiable support burden.

### Rate limiting is inverted from the usual case

The zero-setup default path has 60 requests/hour per IP; the path requiring setup
has 5,000 points/hour. The easy path is the *less* forgiving one, which is the
opposite of the usual arrangement.

- A shared egress IP — CI, an office, a container host — exhausts anonymous quota
  quickly, and for everyone behind it.
- A watched account on an anonymous schedule can consume its own quota entirely.
  Hence spec R17: unsustainable watch intervals are rejected at configuration
  time, not discovered at runtime.
- The rate-limited error MUST recommend authentication. A user hitting 60/hour
  has an easy fix and no way to guess it from a bare 403.

## Account type detection

`projectsQuery` requires the caller to commit to `user(login:)` or
`organization(login:)`; the wrong choice is a GraphQL error, not an empty result.

- **Authenticated:** a `repositoryOwner(login:)` probe returning `__typename`.
  `RepositoryOwner` is implemented by both `User` and `Organization`, so one query
  settles it. Rejected the alternative — try `user`, fall back on the "not found"
  error — because its correctness rests on matching an error message GitHub is
  free to reword: the kind of dependency that works in testing and breaks
  silently in a year.
- **Anonymous:** REST `GET /users/{login}` returns `"type": "User" |
  "Organization"` directly. `/users/{login}/repos` works for both, so on this path
  the type is informational rather than load-bearing.

## Resolution is not discovery

`pkg/gitservice/api/github.go:59` already has `discoverGitHub`, and it is tempting
to extend it. That would be a mistake.

`discoverGitHub` is a **UI paging feed**: it takes a `GitHubPagedSearch` with a
`NextCursor`, returns one page plus a cursor, and expects the *caller* to loop. Its
contract is caller-driven and partial, because it exists so a picker can render
"next page".

This change needs **exhaustive, terminating, sorted resolution** — everything or
an error. Those are different contracts, and overloading one function with both
yields a function that is exhaustive *sometimes*. So: new code path,
`pkg/gitservice/account/`, `discoverGitHub` untouched.

`GetRepositories` is reused as the authenticated paging primitive, but carefully:
it loops `for len(projects) < pagedSearch.PageSize` and breaks on error **without
returning it** (`github.go:29-31` logs and breaks). A caller cannot distinguish
"that's all of them" from "the third page 500'd". Either it gains a propagated
error or the resolver drives `queryProjects` directly — prefer the former, since
the silent break is a latent defect regardless of this change.

With two transports this matters more than it first appears: a swallowed error on
the authenticated path that silently under-reports would be nearly
indistinguishable from a legitimate visibility difference between transports.

## Layering

```
CLI (cmd/account.go)  ─┐
API (/v1/accounts/…)  ─┼─► pkg/sdk (ResolveAccount) ─► pkg/gitservice/account
Desktop app           ─┤                                  │ AccountResolver
cron (watch)          ─┘                                  ├─► github/rest    (anon)
                                                          └─► github/graphql (auth)
```

Sorting, filtering and cap enforcement live in `pkg/gitservice/account`, **not**
in the SDK wrapper, **not** in the handler, **not** in the transports. Four call
sites means four chances to forget to sort, and an unsorted list is a determinism
violation (Guardrail 6) that manifests as report grouping changing between runs —
an observation that would take a long time to trace back to here.

## Incompleteness is a first-class result field

Spec R3 requires every resolution to record its authentication state and mark
public-only results as potentially incomplete. This is not presentation polish.

The failure mode: a user resolves `https://github.com/acme` anonymously, gets 3
public repositories and no findings, and concludes the organisation is clean —
while 37 private repositories were never looked at. The result was *correct*; the
conclusion was wrong; nothing in the output distinguished the two. Since anonymous
is now the default, this is the *expected* path rather than an edge case, which is
precisely why the marker has to be structural rather than a note in the docs.

## Storage of account provenance

`projects.Project` gains an optional `Account *AccountBinding` — an additive,
nullable migration in `pkg/store/sqlite/migrations/`, no backfill, hand-entered
projects simply `NULL`.

The binding stores the **filter** and the **authentication state** alongside the
login. Without the filter, re-resolution cannot reproduce the original selection
and would silently widen the set on first re-resolve. Without the auth state, a
re-resolution that happened to run anonymously would read as "37 repositories
removed" rather than "we could not see them this time" — which is exactly the
scope collapse R14 forbids applying.

## Snapshot, plus watch

The chosen semantics separate two things that are easy to conflate:

- **The enrolled set is a snapshot.** Scan *N* and scan *N+1* cover the same
  repositories, so a change in findings is a change in code. This is what makes
  the numbers usable in an argument.
- **Watch grows the set, deliberately and auditably.** A new repository is new
  attack surface; noticing it late is the failure this feature exists to prevent.
  So watch adds it, scans it, records why, and fires a webhook.

Watch never removes. Disappearance is ambiguous — deletion, privacy change,
transient API failure, or an anonymous resolution that cannot see what an
authenticated one could — and discarding scan history on that basis is not
recoverable. Removals are reported for confirmation.

The dangerous case is a resolution that returns empty or errors: applied blindly, a
monitoring feature silently reduces its own scope to nothing and then reports no
findings forever. Hence R14's rule that an empty-where-previously-non-empty result
is suspect, unapplied and alerted. **A monitoring feature that fails quiet is worse
than no monitoring feature**, because it is trusted.

## Two kinds of history, and they are not the same thing

It is easy to hear "continuous monitoring needs history" and reach for retaining
checked-out code. They are unrelated, and conflating them produces a system that
is both expensive and lossy.

| | What it is | Requirement |
|---|---|---|
| **Findings history** | every finding ever recorded, with its repository | durable, never deleted |
| **Membership history** | which repositories were enrolled, when | durable, a time series |
| **Checked-out code** | working tree used to produce a scan | disposable |

Spec R16 makes this explicit: no historical query may depend on a working tree
still existing. That is the property that lets retention be decided purely on
disk and exposure grounds, with no correctness cost.

The existing `DeleteCheckedOutCode` flag quietly invites the opposite reading —
it sounds like a retention policy, and an operator low on disk might reasonably
fear that enabling it loses history. It does not, and the docs should say so.

## Membership as a time series

The naive model stores `Project.Repositories` as current state and diffs it. That
cannot answer "what were we scanning in March?", which is the question every
posture trend implicitly depends on.

So membership is `present` / `absent` / `confirmed-removed` with
`firstObservedAt` / `lastObservedAt` / `absentSince`. Three consequences worth
stating:

1. **Absence is reversible and cheap; removal is neither.** A repository flipped
   private, or an anonymous re-resolve where the previous was authenticated, both
   look exactly like deletion from outside. `absent` costs nothing and is
   undone by the repository reappearing. Only an operator moves it further.
2. **Reappearance must preserve `firstObservedAt`.** A repository that vanishes
   and returns is a signal — deleted and recreated, or toggled private — and
   overwriting the record erases the one thing worth noticing.
3. **`lastObservedAt` advances even when nothing changes.** "We looked and it was
   there" is different from "we have not looked since March", and only an
   explicit timestamp distinguishes them.

## The trend must not be flattered by shrinking coverage

This is the failure this part of the design exists to prevent, and it is worth
being blunt about.

If a repository disappears and its findings silently vanish with it, the posture
graph improves. If findings from an unscanned repository are marked *resolved*,
the graph improves and the remediation count goes up. Both are wrong in the
direction most likely to be believed, and neither produces an error anywhere.

Hence R12: findings outlive their repositories, findings from `absent`
repositories are excluded from *current posture* but retained in *history*, and a
finding that disappears because nobody looked carries state `unscanned` — never
`fixed`. And hence the API requirement that any trend or remediation count is
reported alongside coverage. **A number that improves when you stop looking is
worse than no number**, because it is acted upon.

## Checked-out code retention — recommendation

You asked for a view. Mine is: **delete by default for account projects, allow
opt-in retention, and never couple it to history.**

The case for deleting:

- **Disk.** 500 repositories at full history is plausibly hundreds of gigabytes,
  and R15's pre-enrolment disclosure exists precisely because users will not
  predict this. Retention-by-default turns one enthusiastic org scan into a full
  disk, and the scanner is then down.
- **Exposure, which is the stronger argument.** Guardrail 3 says CheckMate never
  stores secret values in plaintext — only `secretChecksum` and
  `evidenceRedacted`. A retained checkout is a complete plaintext copy of every
  secret the scan just found, sitting on the same host. The guardrail is about
  CheckMate's own storage and is not violated, but the *spirit* of it is hard to
  square with leaving the originals lying around. A secrets scanner that hoards
  full-history clones is a high-value target: compromising the CheckMate host
  yields not just findings but the credentials themselves, and their history.
- **Retention is not needed for anything CheckMate promises.** Reports, trends,
  membership and exceptions are all derived at scan time and persisted
  independently.

The honest case for retaining:

- **Incremental fetch.** This is the real one. Nightly watch over 500
  full-history repositories means re-cloning everything every night — bandwidth,
  time, and provider load that `git fetch` would reduce by orders of magnitude.
  For continuous monitoring at organisation scale, delete-always is genuinely
  expensive, and I do not want to pretend otherwise.

I considered retaining a **bare mirror** (`--mirror`) and materialising an
ephemeral working tree per scan: full history for incremental fetch, no plaintext
tree. It is a modest improvement — it defeats a careless `grep -r` or an
accidentally served static path — but **it is not a security control**. The
secrets are still there in the packfiles and trivially recoverable by anyone with
read access. Worth doing for tidiness; worth *not* claiming as protection.

So the proposed shape:

- Default `deleteAfterScan: true` for account projects.
- Retention opt-in, and most defensible for **watched** projects, where
  incremental fetch pays for itself.
- Where retained: `0700` checkout root, a configurable disk budget with
  least-recently-scanned eviction, and eviction that touches no history.
- Documented plainly: *retained checkouts contain plaintext secrets; this host
  becomes a credential store; back it up and access-control it accordingly.*

The part most likely to be skipped is that last line, and it is the part that
matters. An operator who enables retention for performance reasons will not
independently derive that they have changed the security posture of the host.

## Failure isolation

R9 requires per-repository failure not to fail the scan. The natural place is the
checkout loop, not the scan engine — the engine takes roots and should keep taking
roots. A repository that fails to clone is simply not contributed as a root, and
its failure is recorded on the scan.

The trap: if failures are only logged, a scan of 200 repositories where 190 fail
to clone reports a near-clean result and looks like good news. Hence R9's
requirement that all-failed is a scan *failure* and any-failed is
*distinguishable*. Those counts are not cosmetic; they are what stops this feature
from lying.

## Scale

At 500 repositories with full-history clones (R8), clone time and disk dominate —
003 took whole-tree scanning to 97s, so detection is not the bottleneck. Clones
should run on a bounded worker pool.

Full history was chosen over depth-1 deliberately: secrets committed and later
removed are exactly what CheckMate is for, and depth-1 cannot see them. The cost is
real — hours rather than minutes on a large org — which is why shallow remains
available as a marked, explicit opt-in, and why incremental fetch under opt-in
retention is the mitigation that actually helps a nightly watch.

## Testing

- Resolver against recorded fixtures **on both transports**: user account,
  organisation, empty account, single page, multi page, cap exceeded, rate limited,
  repository URL mistaken for an account.
- **Transport conformance:** same account, both transports, identical output for
  commonly-visible repositories.
- Sorting determinism: shuffle page arrival order, assert identical output.
- Auth-state marking: anonymous resolution of an account with private repositories
  is marked incomplete.
- **Two repositories with an identical vendored file**, asserting distinct
  `findingID` and correct per-repository `RepositoryIndex` — the regression guard
  for scan-engine exception 1 required by R10.
- Failure isolation: one clone fails ⇒ scan completes, counts right, failure in the
  summary. All clones fail ⇒ scan reports failure, not a clean zero.
- Re-resolution diff: add, disappear, archive; scan history, findings and
  exceptions on survivors preserved.
- **Membership time series:** appear ⇒ disappear ⇒ reappear, asserting
  `firstObservedAt` is preserved across the gap and the absence interval is
  retained.
- **Coverage honesty:** a repository goes absent ⇒ its findings are excluded from
  current posture, retained in history, and marked `unscanned` rather than
  `resolved`. This is the test that stops the trend flattering itself.
- **History survives deletion of code:** run a scan with `deleteAfterScan: true`,
  assert every finding, membership record, exception and summary is intact.
- Watch: new repository appears ⇒ enrolled, scanned, webhook fired, event audited.
  Empty resolution ⇒ **not** applied, alert raised.
