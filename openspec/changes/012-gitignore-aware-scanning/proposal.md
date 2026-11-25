# OpenSpec Proposal: 012-gitignore-aware-scanning

**Status:** Draft
**Capabilities:** `scan-engine` (delta), `pre-commit-cli` (delta)
**Type:** Feature / Security Ergonomics / Performance

## Goal

Make CheckMate's working-tree directory scans **Git-aware and `.gitignore`-respecting by default** while preserving **zero blind spots on tracked, staged, or explicitly targeted secrets**, and add first-class `--tracked-only` and `--no-ignore` controls for pre-push hooks, CI pipelines, and full-filesystem audits.

Developers running `checkmate search .` or `checkmate hook run src supabase` inside a Git repository will no longer get blocked by legitimate untracked local files (such as `.env.local`, `.temp/`, `dist/`, or `node_modules/`), while any secret that is force-staged, already tracked in Git (even if it matches `.gitignore`), or explicitly passed as a file argument continues to be detected without exception.

## Motivation

Real-world pre-commit and pre-push adoption against TypeScript/Angular/Supabase repositories revealed three concrete friction points caused by CheckMate ignoring `.gitignore`:

1. **False alarms on legitimate local secret stores:** Developer machines are expected to keep sandbox credentials in gitignored `.env.local` files and local runtime artefacts in `.temp/` directories. Running `checkmate search src supabase` or a pre-push hook against working-tree directories currently flags untracked gitignored files as if they were repository leaks.
2. **Boilerplate duplication in `.checkmate.yaml` and Git hooks:** Every repository must manually duplicate `.gitignore` entries into `.checkmate.yaml` (`PathExclusionRegExs`) or wrap CheckMate in custom `git ls-files -z` shell loops inside `.githooks/pre-push`. Worse, adding `.env.local` to `.checkmate.yaml` creates a real security regression if someone later runs `git add -f .env.local`, because `.checkmate.yaml` suppresses staged scans too.
3. **Avoidable I/O on build artefacts and dependency trees:** Walking untracked ignored directories (`dist/`, `.angular/`, `supabase/.temp/`, `coverage/`, `node_modules/`) burns CPU and disk I/O scanning machine-generated files that Git will never commit or push.

At the same time, naively matching paths against `.gitignore` introduces dangerous blind spots in a security scanner:

- A file that was committed before being added to `.gitignore`, or force-added with `git add -f`, is **tracked by Git** and WILL be pushed even though it matches `.gitignore`.
- Staged blobs in `checkmate hook run --staged` represent what is about to enter Git history and MUST NEVER be skipped because of `.gitignore`.
- Non-Git directories (for example extracted container images, server mounts, or tarballs) have no Git tracking boundary; silently skipping `.env` files there would weaken incident-response and filesystem audits.

This change resolves both sides cleanly by anchoring ignore decisions to Git's own index and ignore rules rather than naive path globbing.

## Scope

1. **Git-Aware Streaming File Discovery (`scan-engine` delta, `R15`):**
   - Add opt-in `RespectGitIgnore` and `TrackedOnly` fields to `secrets.SecretSearchOptions` (zero value `false` to preserve strict backwards compatibility for `pkg/sdk`, `pkg/api`, `TestScanEquivalence`, and golden-corpus baselines).
   - Implement a streaming Git-worktree file enumerator (`pkg/core/util/gitwalk.go` or equivalent) backed by a single streaming `git -c core.quotepath=false ls-files -z` subprocess per Git worktree root:
     - `RespectGitIgnore` (default CLI directory mode): `--cached --others --exclude-standard -- <relPath>`, which emits **every Git-tracked file (even if it matches `.gitignore`)** plus **untracked non-ignored files**, while respecting nested `.gitignore`, `.git/info/exclude`, `core.excludesFile`, and `!negation` patterns with exact Git fidelity.
     - `TrackedOnly`: `--cached -- <relPath>`, emitting strictly Git-tracked files under the target path (skipping deleted working-tree entries gracefully).
   - Preserve streaming discovery (`R1`), bounded memory (`R3`), context cancellation (`R10`), and deterministic lexical path ordering (Guardrail 6).
   - Fall back cleanly to `util.WalkFiles` whenever a target is outside a Git worktree or `git` is unavailable on `PATH` (for `RespectGitIgnore`), and fail closed with exit `2` if `--tracked-only` is requested outside a Git repository.

2. **CLI Defaults, Overrides & Pre-Push Ergonomics (`pre-commit-cli` delta, `R8`):**
   - Add `--no-ignore` and `--tracked-only` flags to both `checkmate search` and `checkmate hook run`.
   - Default working-tree directory targets in `checkmate search <dir>` and `checkmate hook run <dir>` inside a Git worktree to `RespectGitIgnore = true` (opt-out via `--no-ignore`).
   - Enforce strict security invariants:
     - `--staged` NEVER applies `.gitignore` (Git index is ground truth; force-staged ignored files are always scanned).
     - `--stdin` NEVER applies `.gitignore`.
     - Explicit file arguments (for example `checkmate search .env.local` or `checkmate hook run .env.local`) NEVER skip the target because of `.gitignore`.
     - Git-tracked files that match `.gitignore` are ALWAYS scanned.
     - Non-Git directories NEVER apply `.gitignore` rules.
   - Support `--tracked-only` on `checkmate search` and `checkmate hook run` so pre-push hooks and CI jobs can scan tracked files in a single command without shell `git ls-files` wrappers.
   - Document the new flags and recommended pre-push recipe in `checkmate describe` (JSON and Markdown manifests) and CLI `--help`.

## Non-Goals

- **Implementing a custom `.gitignore` parser in Go for non-Git directories.** Relying on Git's own `ls-files --exclude-standard` inside Git worktrees guarantees exact precedence for nested `.gitignore`, `.git/info/exclude`, global excludes, and `!negation` without duplicating Git's semantics. Non-Git directory scans remain full-tree scans governed by `.checkmate.yaml` and `CHECKMATE_PRUNE_DIRS`.
- **Changing `pkg/sdk` or server/API default coverage.** Library callers and the server/API continue to default to `RespectGitIgnore: false` and `TrackedOnly: false` unless explicitly opted in.
- **Full Git commit-history rewriting or multi-commit range diff scanning.** `--tracked-only` scans the current tracked working tree; commit-range diff scanning (`@{u}..HEAD`) can compose on top in a follow-up change.
- **Altering `.checkmate.yaml` or inline `checkmate:ignore` semantics.** Explicit policy exclusions continue to layer on top of file discovery as before.

## Guardrail Interactions

- **Guardrail 3 (No plaintext secrets stored):** Unchanged; `--redact` and SHA-256 checksum behaviour apply identically to Git-enumerated files.
- **Guardrail 5 (Finding-identical performance work vs explicit product decisions):** Skipping untracked gitignored files is a **coverage change** (explicit product decision), NOT a silent performance optimisation. Therefore:
  - `SecretSearchOptions` and `WalkOptions` keep zero-value defaults (`RespectGitIgnore: false`, `TrackedOnly: false`) so `TestScanEquivalence`, `TestPrefilterEquivalence`, and `testdata/golden/reference-corpus.json` remain 100% invariant.
  - CLI directory scans make the behaviour explicit, documented, and reversible via `--no-ignore`.
- **Guardrail 6 (Determinism):** `git ls-files -z` emits paths in Git's deterministic index/tree order and the walker deduplicates and sorts/streams paths canonically per root, preserving `RepositoryIndex` assignment and deterministic finding ordering.
- **Prose check (`tools/prosecheck`):** All new CLI flag descriptions, help text, `checkmate describe` entries, and user-facing docs MUST contain no em dashes.

## Decisions

| # | Decision |
|---|---|
| 1 | Use streaming `git -c core.quotepath=false ls-files -z --cached --others --exclude-standard` (instead of a hand-rolled `.gitignore` matcher) so tracked-but-ignored files, nested `.gitignore`, `.git/info/exclude`, global excludes, worktrees, and `!negation` rules match Git 100%. |
| 2 | Enable `RespectGitIgnore` by default on CLI working-tree directory scans (`checkmate search <dir>`, `checkmate hook run <dir>`) inside Git worktrees, with `--no-ignore` as the full-filesystem escape hatch. |
| 3 | Keep `SecretSearchOptions` zero value unchanged (`RespectGitIgnore: false`, `TrackedOnly: false`) so `pkg/sdk`, `pkg/api`, and golden-corpus equivalence tests experience zero silent coverage changes. |
| 4 | Never apply `.gitignore` to `--staged`, `--stdin`, explicit file paths, or non-Git directories; never skip Git-tracked files even when they match `.gitignore`. |
| 5 | Provide `--tracked-only` on `checkmate search` and `checkmate hook run` (exiting `2` if invoked outside a Git repository) to make `pre-push` and CI repo audits single-command and immune to local untracked files. |
| 6 | If `--no-ignore` and `--tracked-only` are passed together, fail closed with exit code `2` and a clear mutually-exclusive flag error rather than silently letting one override the other. |
