# Spec Delta: Pre-Commit CLI & Git Hook Integration (`pre-commit-cli`)

**Change:** 012-gitignore-aware-scanning
**Status:** Draft

## Delta Requirements

### R8 - Gitignore-Aware Directory Scanning, `--no-ignore`, and `--tracked-only` Pre-Push Mode

- Both `checkmate search` and `checkmate hook run` MUST provide two additive flags:
  - `--no-ignore`: disable `.gitignore`-aware filtering and scan all files on disk, including untracked gitignored files (such as local `.env.local`, build outputs, and temporary directories).
  - `--tracked-only`: restrict scanning to Git-tracked files (`git ls-files --cached`), suitable for `pre-push` hooks and CI repository audits.
- **Default CLI directory behaviour:** When scanning local directory targets inside a Git worktree without `--no-ignore` or `--tracked-only`, both `checkmate search <dir>` and `checkmate hook run <dir>` MUST default to `RespectGitIgnore = true` (scanning all tracked files plus untracked non-ignored files).
- **Non-negotiable security boundaries:**
  - `checkmate hook run --staged` (and default `checkmate hook run` with no positional arguments and without `--tracked-only`) MUST NEVER consult `.gitignore`; force-staged gitignored secrets (for example `git add -f .env.local`) MUST always be scanned and blocked.
  - `checkmate search --staged` and `checkmate search --stdin` MUST NEVER consult `.gitignore`.
  - Explicit file arguments (for example `checkmate search .env.local` or `checkmate hook run .env.local`) MUST be scanned regardless of `.gitignore` unless `--tracked-only` is explicitly set.
  - Git-tracked files that also match `.gitignore` MUST always be scanned.
  - Local directory targets outside a Git worktree MUST scan all files on disk (`.gitignore` rules MUST NOT silently skip files in non-Git directories).
- **Pre-push convenience (`checkmate hook run --tracked-only`):**
  - Invoking `checkmate hook run --tracked-only` with no positional paths MUST scan all tracked files under the current Git repository root (or the supplied subdirectories/files when positional paths are passed).
  - Invoking `--tracked-only` outside a Git repository MUST fail closed with exit code `2`.
- **Mutually exclusive flag validation:** Combining `--no-ignore` with `--tracked-only`, or combining `--tracked-only` with `--staged` or `--stdin`, MUST fail closed with exit code `2` and a clear error message.
- **Agent discovery & structured reporting:**
  - `checkmate describe` (both JSON and Markdown formats) MUST document `--no-ignore`, `--tracked-only`, the default `.gitignore` behaviour on directory scans, and a `pre-push` hook usage recipe.
  - Structured `--format agent` / `--format json` hook envelopes MUST include an `ignoreMode` field (`"gitignore"`, `"tracked-only"`, `"none"`, or `"staged"`) so automated agents can verify the exact scan scope.
