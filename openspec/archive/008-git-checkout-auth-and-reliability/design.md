# Design: 008-git-checkout-auth-and-reliability

**Status:** Implemented

## Current Defect Map

Today CheckMate has **two** separate Git acquisition implementations in `pkg/plugin/secrets-finder/pkg/roots.go`:

1. `acquireRepositories` (`roots.go:196`) — used only by the legacy `SearchSecrets` / `simpleProjectManager` path. Reads `pm.GetGitConfigManager()` and populates `GitCloneOptions.Auth` via `service.MakeAuth()`.
2. `acquirePaths` (`roots.go:342`) — used by `checkmate search`, `pkg/sdk`, `sqlite.DB.RunScan`, `checkmate api`, `checkmate-app`, and `checkmate mcp serve`. Passes `Auth: nil`, hardcodes `Depth: 1`, logs clone errors and drops them, and deletes checkouts in `SearchSecretsOnPathsWithProgress`'s `defer`.

Meanwhile, `pkg/core/git/git.go`:
- Only constructs `http.BasicAuth` (no `transport/ssh` support).
- Hardcodes `InsecureSkipTLS: true`.
- Uses `path.Base(repository)` in `GetCheckoutLocation`, which **collides** when two different orgs in the same scan share a repo name (e.g. `orgA/service` and `orgB/service` both map to `<BaseDir>/service`).
- Reuses a non-empty directory via `repo.FetchContext`, which fetches refs into `.git/` **without updating the working tree** (`Worktree.Pull` / `Reset`), meaning rescans on a retained checkout scan stale files!

## Architecture

### 1. Unified `AuthResolver` (`pkg/core/git/auth.go`)

```go
type AuthResolver interface {
    Resolve(repoURL string, serviceID string) (transport.AuthMethod, error)
}
```

Precedence order for resolving auth for a given `(repoURL, serviceID)`:

1. **Explicit `serviceID`** looked up in `GitServiceConfig` (`git_config` table in SQLite or `GitServiceConfig.yaml`). If `serviceID` is supplied and not found -> return `ErrServiceNotFound` (never silently fall back to anonymous).
2. **Host-matched `GitService`** in `GitServiceConfig` (matching `url.Hostname()` against configured `InstanceURL`, e.g. `github.com`, `gitlab.com`, or self-hosted `git.corp.internal`).
3. **Explicit caller override** (`GitAuth` passed via CLI `--git-token` / `--ssh-key` or `sdk.Options`).
4. **Environment fallback (opt-in / well-known tokens):**
   - `CHECKMATE_GIT_TOKEN` (any HTTPS host)
   - `GITHUB_TOKEN` (only for `github.com` or `GITHUB_HOST`)
   - `GITLAB_TOKEN` (only for `gitlab.com` or `GITLAB_HOST`)
   - For SSH URLs (`git@...`, `ssh://...`, `git+ssh://...`): `CHECKMATE_SSH_KEY_PATH` (with optional `CHECKMATE_SSH_KEY_PASSPHRASE`), falling back to `ssh.NewSSHAgentAuth(user)` when `SSH_AUTH_SOCK` is set.
5. **Anonymous (`nil`)** for public HTTPS repositories.

Every URL logged or persisted passes through `SanitiseRepoURL(rawURL)` which strips `u.User` so embedded tokens never leak into logs, findings, or SQLite.

### 2. Collision-Free Checkout Paths & Fresh Working-Tree Updates (`pkg/core/git/git.go`)

- Fix `GetCheckoutLocation(repository, baseDirectory)` to incorporate a short deterministic hash of the canonical repository URL (`<repoName>-<sha256[:8]>`) so `orgA/api` and `orgB/api` never collide inside the same `BaseDir`.
- Fix existing-checkout refresh: when reusing a non-empty retained checkout directory, perform `FetchContext` followed by `worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Hash: remoteHead})` (or re-clone cleanly into a fresh dir if the existing directory is corrupt or on a detached/conflicting state).
- Respect `GitCloneOptions.InsecureSkipTLS` (default `false`) and `GitCloneOptions.Depth` (`0` = full history, `1` = shallow default for working-tree scans).
- Create `BaseDir` and checkout subdirectories with `0700` permissions.

### 3. Structured `AcquisitionOutcome` & Failure Propagation

Add `AcquisitionReport` emitted alongside findings/files:

```go
type AcquisitionErrorKind string

const (
    AcqErrAuth       AcquisitionErrorKind = "auth_failed"
    AcqErrNotFound   AcquisitionErrorKind = "not_found"
    AcqErrNetwork    AcquisitionErrorKind = "network"
    AcqErrTLS        AcquisitionErrorKind = "tls"
    AcqErrInvalidURL AcquisitionErrorKind = "invalid_url"
    AcqErrIO         AcquisitionErrorKind = "io"
)

type AcquisitionFailure struct {
    Target    string               `json:"target"` // sanitised (no credentials)
    ErrorKind AcquisitionErrorKind `json:"errorKind"`
    Message   string               `json:"message"`
}

type AcquisitionReport struct {
    Attempted       int                  `json:"attempted"`
    Succeeded       int                  `json:"succeeded"`
    Failed          int                  `json:"failed"`
    Failures        []AcquisitionFailure `json:"failures,omitempty"`
    RetainedPaths   map[string]string    `json:"retainedPaths,omitempty"` // sanitisedURL -> localDir (only when KeepCheckouts=true)
}
```

Classification helper maps `go-git` / `net` / `x509` errors (`transport.ErrAuthenticationRequired`, `transport.ErrAuthorizationFailed`, `transport.ErrRepositoryNotFound`, `x509.UnknownAuthorityError`, `net.Error`) into stable `AcquisitionErrorKind` values so CLI, API, Desktop App, and MCP can present actionable guidance (e.g. "configure a GitHub token in Settings or set GITHUB_TOKEN").

### 4. Wiring Across Surfaces

| Surface | Auth Source | Failure Handling |
|---|---|---|
| `sqlite.DB.RunScan` (Desktop App, API, MCP) | `d.GetGitConfigManager()` + env fallback | Persists `AcquisitionReport` in `scans.additional_info`; if `Succeeded == 0 && Failed > 0`, calls `markScanFailed` with error details instead of marking `complete` with 0 findings. |
| `checkmate search` (CLI) | `--git-token`, `--ssh-key`, env vars, optional `~/.checkmate` git config | Prints structured warnings to stderr for partial failures; exits non-zero if all targets fail to clone. |
| `pkg/sdk.Scanner` | `Options.GitAuth` / `Options.AuthResolver` + env fallback | Exposes `ScanPathWithReport(ctx, paths...) (*ScanReport, error)` returning both `[]Finding` and `AcquisitionReport`; keeps `ScanPath` backward-compatible (returns error if all targets fail). |

### 5. Checkout Lifecycle (`KeepCheckouts`)

- Default: `SecretSearchOptions.KeepCheckouts == false` -> cloned directories are deleted in `defer` as today.
- Opt-in: `SecretSearchOptions.KeepCheckouts == true` -> cloned directories remain under `CloneBaseDir` (mode `0700`) and their `sanitisedURL -> localPath` map is returned in `AcquisitionReport.RetainedPaths`. The caller owns cleanup (or eviction via retention policy).
