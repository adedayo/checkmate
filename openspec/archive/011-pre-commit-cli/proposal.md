# OpenSpec Proposal: 011-pre-commit-cli

**Status:** Implemented
**Capabilities:** `pre-commit-cli` (new), `scan-engine` (delta)
**Type:** Feature / Bug Fix / Performance

## Goal

Make CheckMate a **fast, ergonomic, first-class CLI secret scanner for Git `pre-commit` hooks** (both standalone `.git/hooks/pre-commit` and the `pre-commit` framework) without slowing down developer Git workflows.

Developers get sub-30ms typical staged-commit checks, accurate Git index (staged blob + added-line hunk) scanning, reliable non-zero exit codes, clean redacted terminal output, shared `.checkmate.yaml` + inline `checkmate:ignore` suppressions, and one-command hook installation (`checkmate hook install`).

## Motivation

A thorough audit of CheckMate's CLI (`cmd/secretSearch.go`) and scan engine (`pkg/plugin/secrets-finder/pkg/`) identified concrete blockers that currently prevent reliable pre-commit adoption:

1. **Always exits `0` on findings.** `runSearchCommand` returns `0` unconditionally after scanning, so a hook never aborts a commit unless wrapped in custom `jq` scripting. Invalid `--exclusion` paths/YAML also warn and continue instead of failing closed.
2. **Silently skips commonly leaked file types.** `consumePathGated` gates content scanning on a case-sensitive allowlist (`common.TextFileExtensions`) that omits `.env`, `.env.local`, `.env.production`, `.properties`, `.ini`, `.cfg`, `.toml`, `.tf`, `.tfvars`, `.hcl`, `.npmrc`, `.pypirc`, `.netrc`, `.tsx`, `.jsx`, and `.cjs`. Even the reference corpus's `repo-a/.env` fixture (containing a MySQL password URI and a Stripe key) produced zero findings. `DangerousFileNames` also omits modern SSH private keys (`id_ed25519`, `id_ecdsa`).
3. **No Git index / staged diff awareness.** Scanning working-tree paths fails when staged blobs differ from working-tree edits (`git add -p`), flags untouched legacy lines in modified files, and lacks `--stdin` support.
4. **Exclusion bugs under file-list invocations and `.checkmate.yaml`.**
   - `runSearchCommand` sets `ExcludeContainer.Repositories = args`. When individual files are passed (`checkmate search src/app.go`), `ShouldExclude` strips the file path from itself, yielding `""` and breaking `PerFileExcludedStrings`, `PerFileExcludedHashes`, and `PathRegexExcludedRegex`.
   - `secrets.MergeExclusions` drops `GloballyExcludedHashes` and `PerFileExcludedHashes`, silently discarding hash suppressions written by CheckMate's own LSP Quick Fixes to `.checkmate.yaml`.
   - `MakeCommonExclusions` uses leading `.*/` patterns (e.g. `.*/package-lock.json`, `.*/node_modules/.*`) that fail to match root-relative paths passed by Git hooks.
   - `checkmate search` does not auto-discover repo-root `.checkmate.yaml` or read shared SQLite exceptions (unlike `checkmate lspServe`).
5. **Startup & per-commit latency.** `pkg/plugin/secrets-finder/pkg/regexes.go` parses `gitleaks.toml` and compiles every Gitleaks regex **twice** inside `init()` (~50ms before `main()` even runs), and `NewScanContext` eagerly builds all 8 language finder classes (~85ms cold start for a single file). On empty commits or small staged diffs, this overhead is pure waste.
6. **Poor terminal UX for developers.** `--json` defaults to `true`, `--json=false` prints no findings at all, `--sarif` combined with default `--json` corrupts stdout, empty JSON outputs `null` instead of `[]`, raw secrets are printed unredacted, there is no `--min-confidence` threshold, no inline `checkmate:ignore` pragma, and no `.pre-commit-hooks.yaml`.

## Scope

1. **Startup & Scan-Path Performance (`scan-engine` delta):**
   - Remove eager Gitleaks TOML parsing and double regex compilation from `init()`.
   - Validate imported Gitleaks patterns with `regexp/syntax.Parse`, build the Aho-Corasick prefilter directly from pattern strings (`prefilter.BuildPatterns`), and compile each vendor regex lazily on first admission behind a per-rule `sync.Once`.
   - Lazily initialise each `finderClass` inside `ScanContext` on first encountered extension rather than constructing all 8 classes up front.
   - Short-circuit empty staged sets before touching the scan engine or SQLite.
2. **Engine Coverage & Exclusion Correctness (`scan-engine` delta):**
   - Expand scannable text/config extensions (`.env`, `.properties`, `.ini`, `.cfg`, `.toml`, `.tf`, `.tfvars`, `.hcl`, `.npmrc`, `.pypirc`, `.netrc`, `.tsx`, `.jsx`, `.cjs`, `.kts`, `.dockerfile`, `.htpasswd`, `.pgpass`, `.dockercfg`, `.kubeconfig`, plus any `.env.*` filename), perform case-insensitive extension lookup, and add modern SSH key names (`id_ed25519`, `id_ecdsa`, `id_ed25519_sk`, `id_ecdsa_sk`) to `DangerousFileNames` and `checkConfidential`.
   - Deliberately re-record `testdata/golden/reference-corpus.json` to capture the newly detected secrets in `repo-a/.env`.
   - Fix `secrets.MergeExclusions` to preserve `GloballyExcludedHashes` and `PerFileExcludedHashes`.
   - Fix `ShouldExclude` / `ShouldExcludeHashOnPath` and CLI `ExcludeContainer.Repositories` so file-path arguments never strip `pathContext` to `""`.
   - Fix `MakeCommonExclusions` regexes (`(?:^|.*/)...`) to match both root-relative and nested paths while preserving directory pruning.
   - Support inline suppression comments (`checkmate:ignore` on the finding line or `checkmate:ignore-next-line` on the preceding line).
3. **Fast Git Staged & Stdin Scanning (`pkg/precommit`):**
   - Scan staged changes directly from the Git index using a single `git diff --cached -U0 --no-color --no-ext-diff --diff-filter=ACMR` pass (to obtain staged paths and added/modified line ranges) paired with a single `git cat-file --batch` subprocess (to stream all staged blobs without per-file fork/exec overhead).
   - Scan whole staged blobs for full-file context and accurate line numbers, then filter to added/modified line ranges in diff mode (while always reporting newly added confidential files such as private keys or `.p12` keystores).
   - Support `--stdin` with `--filename` for streaming single-blob scans.
4. **CLI Upgrades & `checkmate hook` Subcommand (`cmd/`):**
   - Upgrade `checkmate search` with `--fail-on-findings`, `--format <json|text|sarif|pdf>`, `--redact`, `--min-confidence <info|low|medium|high|critical>`, `--staged`, `--diff-only`, `--stdin`, `--filename`, `--no-auto-exclusion`, `--data-path`, and `--no-db`; fix JSON empty-result `[]` output, mutually exclusive `--sarif`/`--pdf` stdout handling, and strict failure (exit `2`) on unreadable/invalid explicit `--exclusion` files.
   - Add `checkmate hook run`, `checkmate hook install [--force]`, and `checkmate hook uninstall` with pre-commit-tuned defaults (`--staged`, `--diff-only`, `--format text`, `--redact`, `--fail-on-findings`, `--min-confidence medium`, repo `.checkmate.yaml` auto-discovery).
   - Add a root `.pre-commit-hooks.yaml` manifest for the `pre-commit` framework.

## Non-Goals

- **Remote AI triage in pre-commit hooks.** Pre-commit execution must remain 100% local, offline, deterministic, and fast.
- **Changing `isTestPath` semantics.** Existing `TestIsTestPathMatchesRegex` pins `isTestPath` to `(?i:.*test.*)`; `checkmate hook run` leaves `--exclude-tests` off by default so paths like `latest/` or `attestation/` are never accidentally skipped.
- **Full Git history scanning (`pre-push` / commit-range rewriting).** This change focuses on staged/working-tree pre-commit prevention.

## Guardrail Interactions

- **Guardrail 3 (No plaintext secrets stored):** Redaction (`--redact`, default in `checkmate hook run`) masks raw secret values to `first4****last4` (or `****` for short values) while preserving exact SHA-256 checksums for `.checkmate.yaml` suppressions.
- **Guardrail 5 (Finding-identical performance work):** Lazy vendor compilation and lazy `ScanContext` class construction are proved finding-identical via `TestPrefilterEquivalence` and `TestScanEquivalence`. Expanding `.env`/config coverage is an explicit product decision documented here and verified by a deliberate golden baseline re-record.
- **Guardrail 6 (Determinism):** Staged file scanning sorts outputs canonically and `MergeExclusions` deduplicates hashes in deterministic order.
- **Prose check (`tools/prosecheck`):** All user-visible CLI help text, terminal output, and error messages MUST contain no em dashes.

## Decisions

| # | Decision |
|---|---|
| 1 | Keep `checkmate search` backwards-compatible (`--json` default `true`, exit `0` unless `--fail-on-findings` is passed) so existing CI integrations (`action.yaml`, scripts) do not break unexpectedly. |
| 2 | Provide `checkmate hook run` / `install` / `uninstall` as the zero-config pre-commit UX with fast staged-diff scanning, redacted text output, `--min-confidence medium`, and exit codes `0` (clean), `1` (findings), `2` (error). |
| 3 | Use single-invocation `git diff --cached -U0` + `git cat-file --batch` rather than `go-git` index walking or per-file `git show` subprocesses, ensuring sub-10ms Git I/O even on large repositories with sparse indexes, LFS filters, or worktrees. |
| 4 | Defer Gitleaks regex compilation out of `init()` and compile each vendor rule lazily via per-rule `sync.Once` behind `prefilter.BuildPatterns`, eliminating ~50ms of wasted startup work on every commit. |
| 5 | Keep SQLite exception lookup in `checkmate hook run` read-only and skipped whenever `~/.checkmate/checkmate.db` does not exist (opt-out via `--no-db`), avoiding migration or DB-creation latency during commits. |
