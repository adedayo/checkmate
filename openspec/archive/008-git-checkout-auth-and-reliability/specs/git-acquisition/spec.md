# Spec: Git Acquisition (`git-acquisition`)

**Change:** 008-git-checkout-auth-and-reliability
**Status:** Draft

## Requirements

### R1 — Unified Authentication Across All Surfaces

Every CheckMate scanning entry point (CLI, SDK, SQLite/Desktop App, API, MCP) MUST resolve Git credentials through a single `gitutils.AuthResolver` contract supporting:

1. Explicit `GitServiceID` lookup in `GitServiceConfig` (hard error if specified ID does not exist; never silent anonymous fallback).
2. Host-matched `GitService` lookup in `GitServiceConfig` (matching repository hostname against configured `InstanceURL`).
3. Explicit per-call credentials (`--git-token`, `--ssh-key`, `sdk.Options.GitAuth`).
4. Environment variables (`CHECKMATE_GIT_TOKEN`, `GITHUB_TOKEN` for GitHub hosts, `GITLAB_TOKEN` for GitLab hosts, `CHECKMATE_SSH_KEY_PATH` / `SSH_AUTH_SOCK` for SSH URLs).
5. Anonymous access when no credentials are configured (for public HTTPS repositories).

### R2 — Native SSH Support

`gitutils.Clone` MUST support SSH URLs (`git@host:owner/repo.git`, `ssh://...`, `git+ssh://...`) via `go-git/v5/plumbing/transport/ssh` (explicit private key file with optional passphrase, or `ssh-agent`). SSH URLs MUST NOT be silently converted to `https://` during transport cloning.

### R3 — Credential Redaction

Embedded credentials in URLs (e.g. `https://user:token@host/org/repo.git`) MUST be stripped via `SanitiseRepoURL` before appearing in logs, `findings.file_path`, `findings.repo_url`, `scans.targets`, `AcquisitionReport`, or `audit_log`.

### R4 — Collision-Free & Fresh Checkouts

- Checkout directories under `BaseDir` MUST disambiguate repositories with identical basenames from different owners/hosts (e.g. `<repoName>-<sha256[:8]>`).
- Checkout directories MUST be created with mode `0700`.
- When reusing a retained non-empty checkout directory, `Clone` MUST update the working tree to the fetched remote `HEAD` (not merely fetch into `.git/`).

### R5 — TLS Safety by Default

`GitCloneOptions.InsecureSkipTLS` MUST default to `false`. Skipping TLS verification is opt-in only (via `GitService` setting or explicit `--insecure-skip-tls` flag).

### R6 — Explicit Acquisition Failure Reporting

- Every scan MUST produce an `AcquisitionReport` containing `attempted`, `succeeded`, `failed`, and structured `failures[]` (`target`, `errorKind`, `message`).
- Partial failure (some targets succeed, some fail) MUST isolate failed targets, scan all healthy targets, and report `failures[]` clearly.
- Total failure (`succeeded == 0 && failed > 0`) MUST fail the scan loudly (status `failed` in SQLite; non-zero exit code in CLI; non-nil error in SDK) rather than reporting a clean 0-finding scan.

### R7 — Configurable Depth & Opt-In Checkout Retention

- `SecretSearchOptions.CloneDepth` defaults to `1` (shallow working tree) and accepts `0` for full history or any positive integer depth.
- `SecretSearchOptions.KeepCheckouts` defaults to `false` (temporary checkouts deleted on scan completion). When `true`, checkouts are preserved under `CloneBaseDir` (mode `0700`) and mapped in `AcquisitionReport.RetainedPaths`.
