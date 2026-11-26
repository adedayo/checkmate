# Tasks: 012-gitignore-aware-scanning

**Status:** Implemented & Archived

## Phase 1 - Git-Aware Streaming File Discovery (`pkg/core/util`)

- [x] Add `RespectGitIgnore bool` and `TrackedOnly bool` fields to `util.WalkOptions` in `pkg/core/util/walk.go` (zero value preserves exact legacy `WalkFiles` behaviour).
- [x] Implement streaming Git worktree enumeration in `pkg/core/util/gitwalk.go`:
  - Resolve worktree root via `git -C <dir> rev-parse --show-toplevel` (with per-walk caching).
  - Stream NUL-delimited paths via `git -c core.quotepath=false ls-files -z --cached --others --exclude-standard -- <relPath>` (when `RespectGitIgnore`) or `--cached -- <relPath>` (when `TrackedOnly`).
  - Handle deleted working-tree files (`ENOENT`), gitlink/submodule directory entries, duplicate merge-conflict index entries, and context cancellation (`exec.CommandContext`).
  - Preserve `WalkOptions.PruneDirs` filtering, original root-relative path formatting, and `RepositoryIndex` assignment.
  - Ensure explicit regular-file targets bypass `.gitignore` under `RespectGitIgnore`, and verify tracked status under `TrackedOnly`.
  - Fall back cleanly to `walkDir` for non-Git directories when `RespectGitIgnore` is true and `TrackedOnly` is false; return a typed error when `TrackedOnly` is requested outside a Git worktree.

## Phase 2 - Scan Engine Wiring (`pkg/plugin/secrets-finder/pkg`)

- [x] Add `RespectGitIgnore bool` and `TrackedOnly bool` fields to `secrets.SecretSearchOptions` (zero value `false`).
- [x] Propagate `RespectGitIgnore` and `TrackedOnly` into `util.WalkOptions` inside `pkg/plugin/secrets-finder/pkg/secretfinder_plugin.go`, `secret_scanner.go`, and `roots.go` (propagating non-Git `TrackedOnly` errors cleanly through target acquisition reporting).
- [x] Verify `TestScanEquivalence`, `TestPrefilterEquivalence`, and `testdata/golden/reference-corpus.json` remain 100% unchanged under default library options.

## Phase 3 - CLI Flags, Pre-Push Mode & Agent Discovery (`cmd/`)

- [x] Add `--no-ignore` and `--tracked-only` flags to `cmd/secretSearch.go`:
  - Default `RespectGitIgnore: !searchNoIgnore` and `TrackedOnly: searchTrackedOnly` for local path scans.
  - Validate mutual exclusion (`--no-ignore` + `--tracked-only` -> exit `2`; `--tracked-only` + `--staged` or `--stdin` -> exit `2`).
  - Ensure `--staged` and `--stdin` never consult `.gitignore`.
  - Exit `2` on `--tracked-only` outside a Git repository.
- [x] Add `--no-ignore` and `--tracked-only` flags to `cmd/hook.go` (`checkmate hook run`):
  - Keep `--staged` (default when no args and `!hookTrackedOnly`) 100% immune to `.gitignore`.
  - Support `checkmate hook run --tracked-only [paths...]` (defaulting to repo root `.` when no paths are passed) with structured envelope mode `"tracked-files"`.
  - Default explicit directory targets (`checkmate hook run src supabase`) to `RespectGitIgnore: !hookNoIgnore` while keeping explicit file targets unaffected by `.gitignore`.
- [x] Add `ignoreMode` (`"gitignore"`, `"tracked-only"`, `"none"`, `"staged"`) to the structured agent/hook JSON envelope (`pkg/precommit/format.go`).
- [x] Update `cmd/describe.go` (JSON and Markdown manifests) with `--no-ignore`, `--tracked-only`, and a pre-push hook recipe.

## Phase 4 - Unit & Real-Git Integration Tests

- [x] Add unit and real-`git` repository integration tests covering all `.gitignore`, tracked-but-ignored, force-staged, explicit file, `--no-ignore`, `--tracked-only`, non-Git fallback, mutual-exclusion, ENOENT, merge conflict, Unicode/spaces, and cancellation cases.

## Phase 5 - Documentation & Validation

- [x] Update `README.md`, `docs/features.md`, and `docs/index.html` to document `.gitignore`-aware directory scans, `--no-ignore`, and `--tracked-only` pre-push usage.
- [x] Run full validation: `go build ./...`, `go vet ./...`, `go test -race ./...`, and `go run ./tools/prosecheck`.
