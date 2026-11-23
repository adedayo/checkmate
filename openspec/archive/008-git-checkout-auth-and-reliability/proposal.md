# OpenSpec Proposal: 008-git-checkout-auth-and-reliability

**Status:** Implemented
**Capabilities:** `git-acquisition` (new), `data-store`, `sdk`
**Type:** Feature / Reliability Fix

## Goal

Make automated Git repository checkout **consistent, authenticated, transparent, and reliable across every CheckMate surface** — CLI (`checkmate search`), Go SDK (`pkg/sdk`), SQLite store (`sqlite.DB.RunScan`), REST API (`checkmate api`), Desktop App (`checkmate-app`), and MCP server (`checkmate mcp serve`).

Private HTTPS and SSH repositories must clone smoothly without embedding plaintext tokens in URLs, clone failures must surface explicitly instead of masquerading as clean zero-finding scans, and callers must be able to control clone depth and checkout retention cleanly.

## Motivation

Live verification and code inspection revealed five structural gaps in CheckMate's current Git acquisition path:

1. **Private repositories are unauthenticated on the primary SQLite/CLI/SDK/MCP path.** `sqlite.DB.RunScan` calls `SearchSecretsOnPathsWithProgress` -> `acquirePaths` (`pkg/plugin/secrets-finder/pkg/roots.go:342`), which invokes `gitutils.Clone` with `Auth: nil`. Only the legacy `acquireRepositories` path (`roots.go:196`) consults `pm.GetGitConfigManager()`. As a result, tokens saved in `git_config` (via the Desktop App or API) are completely ignored during SQLite-backed scans.
2. **SSH URLs (`git@host:owner/repo.git`, `ssh://...`) are not supported.** `gitutils.Clone` (`pkg/core/git/git.go:47`) only constructs `http.BasicAuth` and never configures SSH key or `ssh-agent` authentication, even though `gitURL` matches `git@` and `GetCheckoutLocation` converts `git@` to `https://`.
3. **Clone failures fail silently and report as "0 findings".** When a clone fails (401/403 authentication error, bad URL, unreachable host, disk error), `acquirePaths` logs to stderr and emits no roots. The scan completes with `status: complete`, `filesScanned: 0`, and `totalFindings: 0` — indistinguishable from a clean repository.
4. **Checkout depth is hardcoded to `Depth: 1` and cannot be configured.** Callers cannot request full-history clones or specific branches/refs when scanning via `acquirePaths`, nor can existing checkouts be updated cleanly when a branch changes.
5. **Checkouts are unconditionally deleted on scan completion.** `SearchSecretsOnPathsWithProgress` unconditionally executes `os.RemoveAll(location)` in its `defer` block. Workflows that need post-scan file inspection (such as MCP agent triage of remote repositories, or Desktop App code-context viewing) lose access to the checked-out files immediately.

## Scope

1. **Unified Auth Resolution (`pkg/core/git`):**
   - Support HTTPS token/basic auth, SSH (`ssh-agent`, configured private key path with optional passphrase, known_hosts), and environment-based credential fallback (`CHECKMATE_GIT_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `CHECKMATE_SSH_KEY_PATH`).
   - Support per-URL credential resolution from `git_config` (by explicit `GitServiceID` or host/instance URL match) across **every** surface, including `sqlite.DB.RunScan`, CLI, SDK, API, and MCP.
   - Never persist raw credentials in URLs, scan records, findings, or logs (redact any userinfo in URLs before logging or storing).
2. **Unified Clone Options & Failure Reporting (`pkg/plugin/secrets-finder/pkg`):**
   - Thread an `AuthResolver` (or per-target `GitAuth`), configurable `CloneDepth` (default `1` for fast working-tree scans, `0` for full history), `KeepCheckouts` opt-in flag, and TLS verification toggle (`InsecureSkipTLS` opt-in rather than hardcoded `true`) into `SecretSearchOptions` and `acquirePaths`.
   - Return structured per-target `AcquisitionOutcome` (`Succeeded`, `ClonePath`, `Branch`, `Error`, `ErrorKind`: `auth_failed | not_found | network | tls | invalid_url | io`) from scan execution rather than swallowing errors in `log.Printf`.
   - Distinguish partial failure (some repos cloned, some failed -> scan completes with `warnings` / `failedTargets`) from total failure (all targets failed -> scan marked `failed` with actionable error message, never a clean `0 findings` report).
3. **SQLite, CLI, and SDK Propagation:**
   - Wire `sqlite.DB.RunScan` to pass a `git_config`-backed `AuthResolver` and record acquisition outcomes in `scans.additional_info` (and fail the scan when all targets fail to clone).
   - Add CLI flags on `checkmate search`: `--git-token` / `--git-token-env`, `--ssh-key`, `--git-depth`, `--insecure-skip-tls`.
   - Expose typed auth and acquisition error fields on `pkg/sdk.Options` and `pkg/sdk.ScanResult`.

## Non-Goals

- **Git commit-history walking engine changes.** Full-history commit-by-commit diff scanning is separate from working-tree acquisition; this change ensures checkout depth and ref checkout are configurable and reliable, without redesigning the scanner's file walker.
- **GitHub/GitLab account-wide enumeration.** Handled by `006-account-wide-repository-discovery`, which builds directly on the auth and failure-isolation primitives defined here.
- **Interactive credential prompts.** CheckMate runs headless in CI, MCP, and daemons; authentication MUST fail fast with a clear `auth_failed` error rather than blocking on stdin.

## Guardrail Interactions

- **Guardrail 3 (No plaintext secrets stored):** Git tokens and SSH keys MUST never be written to `scans.targets`, `findings.file_path`, `audit_log`, or stdout/stderr logs. Any embedded userinfo (`https://user:token@host/repo`) MUST be stripped when persisting locations or logging.
- **Guardrail 5 & 6 (Finding-identical & deterministic):** Acquisition changes MUST NOT alter findings for successfully checked-out trees. Repository ordering and `RepositoryIndex` assignment remain pinned to input order regardless of clone completion order.
- **Host security when `KeepCheckouts` is enabled:** Retained checkouts contain plaintext repository contents (including leaked secrets). Retained checkout directories MUST be created with `0700` permissions and documented clearly as opt-in.

## Decisions

| # | Decision |
|---|---|
| 1 | Unify auth across `acquirePaths` and `acquireRepositories` via a single `gitutils.AuthResolver` interface so SQLite, CLI, SDK, API, and MCP all resolve credentials identically. |
| 2 | Support both HTTPS (`http.BasicAuth` / bearer token) and SSH (`ssh-agent` + explicit key file via `go-git/plumbing/transport/ssh`). Never silently rewrite `git@` to `https://` when SSH auth is available. |
| 3 | Total acquisition failure (0 of N targets acquired) fails the scan loudly; partial failure (k of N acquired) completes with explicit `failedTargets` recorded on the scan and returned to callers. |
| 4 | Change `InsecureSkipTLS` from hardcoded `true` to opt-in (`false` by default, configurable per `GitService` or `--insecure-skip-tls`) to prevent silent MITM on public/enterprise endpoints. |
| 5 | Keep `KeepCheckouts: false` as the safe default (delete temporary checkouts on scan completion); allow callers (e.g. MCP remote-URL triage in `009`) to opt in to `0700`-scoped retention with explicit cleanup. |
