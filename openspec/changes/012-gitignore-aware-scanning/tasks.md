# Tasks: 012-gitignore-aware-scanning

**Status:** Draft

## Phase 1 - Git-Aware Streaming File Discovery (`pkg/core/util`)

- [ ] Add `RespectGitIgnore bool` and `TrackedOnly bool` fields to `util.WalkOptions` in `pkg/core/util/walk.go` (zero value preserves exact legacy `WalkFiles` behaviour).
- [ ] Implement streaming Git worktree enumeration in `pkg/core/util/gitwalk.go`:
  - Resolve worktree root via `git -C <dir> rev-parse --show-toplevel` (with per-walk caching).
  - Stream NUL-delimited paths via `git -c core.quotepath=false ls-files -z --cached --others --exclude-standard -- <relPath>` (when `RespectGitIgnore`) or `--cached -- <relPath>` (when `TrackedOnly`).
  - Handle deleted working-tree files (`ENOENT`), gitlink/submodule directory entries, duplicate merge-conflict index entries, and context cancellation (`exec.CommandContext`).
  - Preserve `WalkOptions.PruneDirs` filtering, original root-relative path formatting, and `RepositoryIndex` assignment.
  - Ensure explicit regular-file targets bypass `.gitignore` under `RespectGitIgnore`, and verify tracked status under `TrackedOnly`.
  - Fall back cleanly to `walkDir` for non-Git directories when `RespectGitIgnore` is true and `TrackedOnly` is false; return a typed error when `TrackedOnly` is requested outside a Git worktree.

## Phase 2 - Scan Engine Wiring (`pkg/plugin/secrets-finder/pkg`)

- [ ] Add `RespectGitIgnore bool` and `TrackedOnly bool` fields to `secrets.SecretSearchOptions` (zero value `false`).
- [ ] Propagate `RespectGitIgnore` and `TrackedOnly` into `util.WalkOptions` inside `pkg/plugin/secrets-finder/pkg/secrets_finder.go` (and propagate non-Git `TrackedOnly` errors cleanly through target acquisition reporting).
- [ ] Verify `TestScanEquivalence`, `TestPrefilterEquivalence`, and `testdata/golden/reference-corpus.json` remain 100% unchanged under default library options.

## Phase 3 - CLI Flags, Pre-Push Mode & Agent Discovery (`cmd/`)

- [ ] Add `--no-ignore` and `--tracked-only` flags to `cmd/secretSearch.go`:
  - Default `RespectGitIgnore: !searchNoIgnore` and `TrackedOnly: searchTrackedOnly` for local path scans.
  - Validate mutual exclusion (`--no-ignore` + `--tracked-only` -> exit `2`; `--tracked-only` + `--staged` or `--stdin` -> exit `2`).
  - Ensure `--staged` and `--stdin` never consult `.gitignore`.
  - Exit `2` on `--tracked-only` outside a Git repository.
- [ ] Add `--no-ignore` and `--tracked-only` flags to `cmd/hook.go` (`checkmate hook run`):
  - Keep `--staged` (default when no args and `!hookTrackedOnly`) 100% immune to `.gitignore`.
  - Support `checkmate hook run --tracked-only [paths...]` (defaulting to repo root `.` when no paths are passed) with structured envelope mode `"tracked-files"`.
  - Default explicit directory targets (`checkmate hook run src supabase`) to `RespectGitIgnore: !hookNoIgnore` while keeping explicit file targets unaffected by `.gitignore`.
- [ ] Add `ignoreMode` (`"gitignore"`, `"tracked-only"`, `"none"`, `"staged"`) to the structured agent/hook JSON envelope (`pkg/precommit/format.go`).
- [ ] Update `cmd/describe.go` (JSON and Markdown manifests) with `--no-ignore`, `--tracked-only`, and a pre-push hook recipe.

## Phase 4 - Unit & Real-Git Integration Tests

- [ ] Add unit and real-`git` repository integration tests covering:
  - Untracked gitignored `.env.local` and ignored directories (`dist/`, `.temp/`, `node_modules/`) are skipped by default in `checkmate search <dir>` and `checkmate hook run <dir>`.
  - **Tracked file matching `.gitignore`** (committed via `git add -f .env.local` or ignored after commit) is **still detected** under both default `.gitignore` mode and `--tracked-only`.
  - **Force-staged gitignored `.env.local`** (`git add -f .env.local`) is **always detected** by `checkmate hook run --staged` and `checkmate search --staged`.
  - **Explicit file argument** (`checkmate search .env.local`, `checkmate hook run .env.local`) is **always detected** even when untracked and gitignored.
  - Nested `.gitignore`, `.git/info/exclude`, and `!negation` rules (`!.env.example`) match Git's exact behaviour.
  - `--no-ignore` detects secrets inside untracked gitignored `.env.local` and ignored build directories.
  - `--tracked-only` skips untracked non-ignored files as well as untracked ignored files, scans tracked files (including tracked-but-ignored files), and exits `2` outside a Git repo.
  - Non-Git directory scan defaults to scanning all files (including `.env.local`).
  - Mutually exclusive flags (`--no-ignore --tracked-only`) fail closed with exit `2`.
  - Deleted tracked files (`rm tracked.go` without `git rm`) and filenames with spaces/Unicode do not error or hang.
  - Context cancellation terminates streaming `git ls-files` cleanly with `-race`.

## Phase 5 - Documentation & Validation

- [ ] Update `README.md`, `docs/features.md`, and `docs/index.html` to document `.gitignore`-aware directory scans, `--no-ignore`, and `--tracked-only` pre-push usage.
- [ ] Run full validation: `go build ./...`, `go vet ./...`, `go test -race ./...`, `go run ./tools/prosecheck`, and `golangci-lint run`.
- [ ] Benchmark `checkmate search` and `checkmate hook run --tracked-only` against a real TypeScript/Supabase repository with `.env.local` and `.temp/` artefacts.
