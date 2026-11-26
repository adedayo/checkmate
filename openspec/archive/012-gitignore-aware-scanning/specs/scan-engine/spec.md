# Spec Delta: Scan Engine (`scan-engine`)

**Change:** 012-gitignore-aware-scanning
**Status:** Draft

## Delta Requirements

### R15 - Git-Aware `.gitignore` & Tracked-File Discovery (Product Decision)

- `util.WalkOptions` and `secrets.SecretSearchOptions` MUST support two additive boolean options whose zero values remain `false` (preserving strict backwards compatibility for SDK, API, and golden-corpus equivalence tests):
  - `RespectGitIgnore`: when scanning a directory inside a Git worktree, discover **all Git-tracked files plus untracked non-ignored files** (matching `git ls-files --cached --others --exclude-standard`).
  - `TrackedOnly`: when scanning inside a Git worktree, discover **strictly Git-tracked files** (matching `git ls-files --cached`).
- **Tracked-file safety invariant:** A file tracked in the Git index MUST NEVER be skipped because it matches `.gitignore`, `.git/info/exclude`, or global `core.excludesFile`.
- **Explicit file invariant:** When `RespectGitIgnore` is true (and `TrackedOnly` is false), an explicit regular-file target MUST be scanned regardless of `.gitignore` rules.
- **Git-fidelity ignore semantics:** Inside a Git worktree, ignore resolution MUST honour nested `.gitignore` files, `.git/info/exclude`, global `core.excludesFile`, and `!negation` patterns identically to Git.
- **Streaming & bounded memory:** Git file enumeration MUST stream NUL-delimited paths (`git -c core.quotepath=false ls-files -z ...`) into the scan pipeline without buffering the entire repository file list in memory (`R1`, `R3`), MUST honour `context.Context` cancellation (`R10`), and MUST emit deterministic paths preserving `RepositoryIndex` and relative/absolute prefix conventions (Guardrail 6).
- **Resilience:** Tracked entries deleted from the working tree (`ENOENT`), gitlink/submodule directory entries, conflicted duplicate index entries, and filenames containing spaces or non-ASCII characters MUST be handled cleanly without crashing or failing the scan.
- **Non-Git behaviour:** Outside a Git worktree (or when `git` is unavailable):
  - `RespectGitIgnore` MUST fall back to standard filesystem walking (`util.WalkFiles`) so non-Git audits never silently drop `.env` or build files.
  - `TrackedOnly` MUST fail closed with an operational error.
- **Exclusion layering:** Policy exclusions (`ExclusionProvider`, `.checkmate.yaml`, `WalkOptions.PruneDirs`, and inline `checkmate:ignore`) MUST continue to apply on top of Git-aware discovery.
