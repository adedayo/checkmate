# Tasks: 008-git-checkout-auth-and-reliability

**Status:** Implemented

## Phase 1 — Core Git Auth & Clone Reliability (`pkg/core/git`)

- [x] Add `AuthResolver` interface and `ChainedAuthResolver` (`git_config` by `serviceID` -> `git_config` by host -> explicit override -> env token / SSH key / `ssh-agent` -> anonymous).
- [x] Add SSH authentication support in `gitutils.Clone` via `go-git/v5/plumbing/transport/ssh` (`ssh-agent` + explicit key file with optional passphrase); stop rewriting `git@` URLs to `https://` when cloning over SSH.
- [x] Add `SanitiseRepoURL` to strip embedded userinfo credentials before logging, tagging, or persisting.
- [x] Make `GetCheckoutLocation` collision-free (`<repoName>-<sha256[:8]>`) and enforce `0700` permissions on checkout directories.
- [x] Fix non-empty directory refresh in `gitutils.Clone` to reset the working tree to fetched remote HEAD (not fetch-only).
- [x] Change `InsecureSkipTLS` to default `false` (configurable via `GitCloneOptions.InsecureSkipTLS`).
- [x] Add `ClassifyCloneError` mapping `go-git` / TLS / network errors to `AcquisitionErrorKind`.
- [x] Unit tests using local bare repos, local `httptest` smart-HTTP git server (public + basic-auth protected), colliding repo names (`orgA/app` vs `orgB/app`), and URL credential redaction.

## Phase 2 — Unified Acquisition Pipeline (`pkg/plugin/secrets-finder/pkg`)

- [x] Extend `SecretSearchOptions` with `AuthResolver`, `CloneDepth`, `KeepCheckouts`, and `InsecureSkipTLS`.
- [x] Update `acquirePaths` to resolve auth via `options.AuthResolver`, honour `CloneDepth` and `InsecureSkipTLS`, and record per-target `AcquisitionFailure` / `RetainedPaths` in `AcquisitionReport`.
- [x] Update `SearchSecretsOnPathsWithProgress` to skip `os.RemoveAll` when `options.KeepCheckouts == true` and expose `AcquisitionReport` to callers.
- [x] Tests: auth-required repo succeeds with resolver, fails with `AcqErrAuth` without resolver; partial failure isolates bad repo and scans healthy repo; `KeepCheckouts: true` preserves checkout on disk.

## Phase 3 — SQLite Store, CLI, and SDK Integration

- [x] Wire `sqlite.DB.RunScan` to pass a `git_config`-backed `AuthResolver` (matching both `repo.GitServiceID` and repository hostname) plus env fallback.
- [x] Persist `AcquisitionReport` into `scans.additional_info` and mark scan `failed` when `Succeeded == 0 && Failed > 0`.
- [x] Add `GetScanAcquisitionReport(scanID)` to `store.PlatformStore` / `sqlite.DB`.
- [x] Add CLI flags to `cmd/secretSearch.go`: `--git-token`, `--git-token-env`, `--ssh-key`, `--git-depth`, `--insecure-skip-tls`; exit non-zero when all targets fail acquisition.
- [x] Extend `pkg/sdk` with `Options.GitAuth`, `Options.AuthResolver`, `Options.GitDepth`, `Options.KeepCheckouts`, and `ScanPathWithReport`.
- [x] End-to-end tests covering authenticated SQLite scan, failed-clone scan status (`failed` instead of `complete` with 0 findings), and CLI exit code on unreachable/unauthenticated repo.
