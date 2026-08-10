# Spec Delta: SDK — Account Resolution

**Change:** 006-account-wide-repository-discovery
**Status:** Draft
**Delta against:** `openspec/specs/sdk/`

`pkg/sdk` MUST expose account resolution and enrolment without requiring an HTTP
server or a subprocess, consistent with the existing SDK contract.

## Added Surface

```go
// AccountRef identifies a hosting account. Provider-neutral.
type AccountRef struct {
    Provider  string // "github"
    Login     string
    ServiceID string // optional; empty resolves anonymously or by lookup
}

// ParseAccountRef accepts an account URL, "github:login", or a bare login with
// an explicit provider. It returns an error for a repository URL.
func ParseAccountRef(s string) (AccountRef, error)

type AccountFilter struct {
    IncludeArchived bool
    IncludeDisabled bool
    IncludeForks    bool
    IncludePrivate  bool // default true; requires a credential to have effect
    IncludeNames    []string
    ExcludeNames    []string
}

// DefaultAccountFilter returns the documented defaults. The zero value of
// AccountFilter is NOT the defaults — see requirements below.
func DefaultAccountFilter() AccountFilter

type ResolvedRepository struct {
    Location      string
    Name          string
    Private       bool
    Fork          bool
    Archived      bool
    SizeBytes     int64
    DefaultBranch string
}

type AccountResolution struct {
    Ref                   AccountRef
    AccountType           string // "user" | "organization"
    Authenticated         bool
    PotentiallyIncomplete bool
    IncompletenessReason  string
    Repositories          []ResolvedRepository // sorted by Location
    ExcludedCounts        map[string]int
    TotalSizeBytes        int64
    RateLimit             RateLimitStatus
}

// ResolveAccount resolves without credentials where none are available.
func ResolveAccount(ctx context.Context, ref AccountRef, f AccountFilter) (AccountResolution, error)
```

## Requirements

- `ResolveAccount` MUST succeed with no credentials configured, returning public
  repositories with `Authenticated: false` and `PotentiallyIncomplete: true`.
  Absence of a credential is not an error.
- `ResolveAccount` MUST be side-effect free — no clone, no project, no disk write
  beyond credential reads.
- `AccountResolution.Repositories` MUST be sorted per `repository-discovery` R5,
  and `pkg/gitservice/account` MUST be the single place that sorting happens, so
  the SDK, API, CLI and watch scheduler cannot diverge from it.
- Transport selection (REST anonymous vs GraphQL authenticated) MUST be invisible
  in the SDK surface. No GitHub-specific type, and no transport indicator beyond
  `Authenticated`, may appear in any exported signature.
- `PotentiallyIncomplete` MUST NOT be omitted from any downstream rendering the
  SDK controls. Where the SDK formats a resolution for display, an incomplete
  result MUST say so.
- `AccountFilter`'s zero value is **not** the defaults. `IncludePrivate` defaults
  to `true` while its zero value is `false`, so the SDK MUST provide
  `DefaultAccountFilter()` and MUST document that `AccountFilter{}` is not it. A
  silently wrong default here means silently not scanning private repositories —
  the failure mode most likely to go unnoticed, and now doubly so, since a
  correct anonymous result looks identical to a wrongly-filtered authenticated
  one.
- Errors MUST be typed and distinguishable: `ErrNotAnAccount`,
  `ErrAccountNotFound`, `ErrTooManyRepositories`, `ErrRateLimited`,
  `ErrAmbiguousService`, `ErrInvalidCredential`.
- `ErrInvalidCredential` MUST be returned — never a silent anonymous fallback —
  when an explicitly supplied `ServiceID` fails to authenticate.
