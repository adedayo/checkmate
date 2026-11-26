# Design: 012-gitignore-aware-scanning

**Status:** Draft

## Architecture

```text
CLI: checkmate search [flags] <targets...>
     checkmate hook run [flags] [targets...]
         │
         ├──► Flag validation:
         │      - Reject mutually exclusive --no-ignore + --tracked-only (exit 2)
         │      - --staged / --stdin: bypass .gitignore completely (index/stdin is ground truth)
         │
         ├──► Per-target classification (in Scan / Acquisition layer):
         │      1. Remote Git URL: clone & walk as before (cloned tree only has tracked files)
         │      2. Explicit regular file (os.Stat -> !IsDir()):
         │           - RespectGitIgnore: ALWAYS scan file directly (never skip explicit file via .gitignore)
         │           - TrackedOnly: verify tracked in Git (`git ls-files --error-unmatch`) or skip
         │      3. Local directory (os.Stat -> IsDir()):
         │           - Detect Git worktree root via `git -C <dir> rev-parse --show-toplevel`
         │           - If inside Git worktree and (RespectGitIgnore || TrackedOnly):
         │               -> Stream via util.WalkGitFiles (git ls-files -z)
         │           - If outside Git worktree:
         │               -> TrackedOnly: fail closed (error -> CLI exit 2)
         │               -> RespectGitIgnore: fall back cleanly to util.WalkFiles
         │
         └──► Streaming file discovery (`pkg/core/util/gitwalk.go` + `walk.go`):
                - Spawns streaming `git -c core.quotepath=false ls-files -z ...`
                - Reads NUL-delimited paths incrementally via bufio.Reader
                - Deduplicates paths (in case a path appears in both cached/other states)
                - Applies WalkOptions.PruneDirs / ExclusionProvider path pruning
                - Skips deleted working-tree entries (ENOENT from --cached when deleted on disk)
                - Emits RepositoryIndexedFile into existing bounded worker channel
```

## Key Design Details

### 1. Streaming Git File Enumerator (`pkg/core/util/gitwalk.go`)

To uphold `scan-engine` R1 (streaming discovery), R3 (bounded memory), R10 (cancellation), and Guardrail 6 (determinism):

1. **Worktree resolution:**
   - Given a local directory target `root`, resolve its canonical filesystem path (`filepath.Abs` + `filepath.EvalSymlinks` where appropriate) and run:
     ```text
     git -C <root> rev-parse --show-toplevel
     ```
   - Cache `dir -> repoRoot` per scan invocation so scanning multiple sibling directories (`src supabase scripts .github`) incurs minimal subprocess overhead.
   - Compute `relTarget, err := filepath.Rel(repoRoot, absRoot)`:
     - When `relTarget == "."`, omit the pathspec or pass `.`.
     - Otherwise pass `-- <relTarget>` so Git scopes enumeration strictly to the requested subdirectory.

2. **Streaming `git ls-files -z` invocation:**
   - **Default Gitignore-aware mode (`RespectGitIgnore: true, TrackedOnly: false`):**
     ```text
     git -C <repoRoot> -c core.quotepath=false ls-files -z --cached --others --exclude-standard -- <relTarget>
     ```
     Why this exact command is security-optimal:
     - `--cached` includes **every file tracked in the Git index**, even if it matches `.gitignore`, `.git/info/exclude`, or global `core.excludesFile` (catches `git add -f .env` and historically committed `.env` files).
     - `--others --exclude-standard` includes every untracked file that is **not** ignored by standard Git ignore rules (nested `.gitignore`, `.git/info/exclude`, `core.excludesFile`, and `!negation` rules).
     - Untracked ignored files (local `.env.local`, `supabase/.temp/`, `dist/`, `node_modules/`, `.angular/`) are never emitted.
     - `-z` NUL-terminates every path and `-c core.quotepath=false` prevents C-style octal escaping of non-ASCII filenames.
   - **Tracked-only mode (`TrackedOnly: true`):**
     ```text
     git -C <repoRoot> -c core.quotepath=false ls-files -z --cached -- <relTarget>
     ```
     - Emits strictly files present in the Git index under `<relTarget>`.

3. **Streaming consumption & edge cases:**
   - Use `exec.CommandContext(ctx, "git", ...)` and read `stdout` incrementally with `bufio.Reader.ReadString('\x00')`.
   - Check `ctx.Done()` before sending each `RepositoryIndexedFile` so cancellation kills the `git` child process promptly (`R10`).
   - **Deleted-on-disk tracked files:** `--cached` can emit a path that was deleted in the working tree (`rm foo` without `git rm`). Call `os.Lstat(fullPath)` before emitting; skip `os.IsNotExist` entries (and skip gitlink/submodule directory entries where `info.IsDir()` is true, or optionally recurse into initialised submodules if desired — document clearly: gitlinks reported by `ls-files --cached` are directories and skipped as non-regular files unless explicitly walked).
   - **Unmerged/conflicted index entries:** During a merge conflict, `git ls-files --cached` emits a conflicted path up to 3 times (stages 1, 2, 3). Maintain a lightweight per-root deduplication check (adjacent duplicate suppression suffices because `git ls-files --cached` emits identical conflicted paths consecutively, keeping memory O(1)! If `--cached` and `--others` overlap on rare intent-to-add `git add -N` entries, track only seen intent-to-add paths or use a small `prev` check + `ls-files --deduplicate` where Git >= 2.31 supports it, falling back cleanly if older Git does not).
   - **Path preservation for `ExcludeContainer`:** Emit `fullPath` using the same relative/absolute base convention as `util.WalkFiles(root)` (i.e. `filepath.Join(originalRoot, relFromTarget)`) so `ShouldExclude`, `PerFileExcludedHashes`, `PathRegexExcludedRegex`, and diagnostic `Location` formatting behave identically to `util.WalkFiles`.
   - **Directory pruning & `ExcludeContainer`:** Before emitting each file, consult `WalkOptions.PruneDirs` on parent path segments (or let the existing exclusion filter run) so `.checkmate.yaml` path exclusions continue to take full effect on top of `.gitignore`.

### 2. Explicit File Arguments & Symlink Safety

- **Explicit file targets (`checkmate search .env.local` or `checkmate hook run .env.local`):**
  - When a positional argument is a regular file (not a directory):
    - Under `RespectGitIgnore: true` (and `TrackedOnly: false`): bypass `.gitignore` and scan the file directly. Rationale: the user or `pre-commit` framework explicitly asked CheckMate to inspect that file.
    - Under `TrackedOnly: true`: check whether the file is tracked in its Git worktree (`git ls-files --error-unmatch -- <relPath>`); skip untracked files so passing mixed paths under `--tracked-only` still honours the tracked-only contract.
- **Directory symlinks:** Match `util.WalkFiles` default (`FollowLinks: false`); `git ls-files` emits symlink entries as paths without recursing into symlinked directories.
- **Non-Git directories:**
  - If `git rev-parse --show-toplevel` returns non-zero (not inside a Git worktree) or `git` is not installed:
    - When `TrackedOnly: true`: return a clear operational error (CLI exits `2`) because a tracked-only scan cannot be satisfied without Git.
    - When `RespectGitIgnore: true` (default CLI mode): fall back silently (with verbose log if `--verbose` is set) to `util.WalkFiles`, scanning all files governed by `.checkmate.yaml`.

### 3. `SecretSearchOptions` & Engine Integration (`pkg/plugin/secrets-finder/pkg/`)

Extend `secrets.SecretSearchOptions` additively:

```go
type SecretSearchOptions struct {
    // ... existing fields ...

    // RespectGitIgnore skips untracked files matched by .gitignore (and Git's
    // standard exclude files) when scanning directory targets inside a Git
    // worktree. Git-tracked files, explicit file targets, staged blobs, and
    // non-Git directories are never skipped.
    RespectGitIgnore bool

    // TrackedOnly restricts directory and file scans inside a Git worktree to
    // files tracked in the Git index (`git ls-files --cached`). Fails closed if
    // a target is outside a Git repository.
    TrackedOnly bool
}
```

And wire into `util.WalkOptions`:

```go
type WalkOptions struct {
    PruneDirs        func(path string, name string) bool
    FollowLinks      bool
    Concurrency      int
    RespectGitIgnore bool
    TrackedOnly      bool
}
```

- Zero value of both structs keeps `RespectGitIgnore: false` and `TrackedOnly: false` (100% backwards-compatible for `pkg/sdk`, `pkg/api`, `TestScanEquivalence`, and golden-corpus tests).
- When `WalkFilesWithOptions` encounters a directory root with `RespectGitIgnore` or `TrackedOnly` enabled, it delegates that root to `walkGitRoot` (falling back to `walkDir` for non-Git roots when `!TrackedOnly`).

### 4. CLI Flags & Behaviour Matrix (`cmd/secretSearch.go`, `cmd/hook.go`, `cmd/describe.go`)

| Command & Mode | Default behaviour | `--no-ignore` | `--tracked-only` |
|---|---|---|---|
| `checkmate search <dir>` (inside Git repo) | Tracked + untracked non-ignored (`RespectGitIgnore=true`) | Scans all files on disk (incl. `.env.local`, `.temp/`) | Tracked files only (`git ls-files --cached`) |
| `checkmate search <dir>` (outside Git repo) | Scans all files on disk | Scans all files on disk | Error, exit `2` |
| `checkmate search <file>` (explicit file) | Always scans `<file>` | Always scans `<file>` | Scans `<file>` only if Git-tracked |
| `checkmate search --staged` | Staged Git index blobs (never uses `.gitignore`) | No-op (already ignores `.gitignore`) | Error or no-op (staged implies index; document explicitly) |
| `checkmate search --stdin` | Stdin stream (never uses `.gitignore`) | No-op | No-op |
| `checkmate hook run` (no args / `--staged`) | Staged Git index blobs (never uses `.gitignore`) | No-op | Scans all tracked files in repo root when passed without `--staged`? *Prefer explicit:* `checkmate hook run --tracked-only [paths...]` scans tracked files in `[paths...]` (default `.`) and switches mode to `"tracked-files"`. |
| `checkmate hook run <dir...>` | Tracked + untracked non-ignored (`RespectGitIgnore=true`) | Scans all files on disk | Tracked files only (`mode: "tracked-files"`) |
| `checkmate hook run <file...>` | Always scans explicit files | Always scans explicit files | Scans only tracked files among `<file...>` |
| `--no-ignore` + `--tracked-only` together | N/A | Error, exit `2` (mutually exclusive) | Error, exit `2` (mutually exclusive) |

#### Pre-Push Ergonomics Showcase
With this change, a repository's `.githooks/pre-push` reduces from a 20-line `git ls-files -z` bash loop to a single readable command:

```bash
checkmate hook run --tracked-only --min-confidence critical src supabase scripts .github
```

And a local workstation or container image audit stays one flag away:

```bash
checkmate search --no-ignore --format text --redact --fail-on-findings .
```

#### `checkmate describe` & Structured Output Envelope
- Add `--no-ignore` and `--tracked-only` to `cmd/describe.go` (both JSON and Markdown outputs) alongside a pre-push recipe.
- Include `"ignoreMode": "gitignore" | "tracked-only" | "none"` (or `"staged"`) in the structured `--format agent` / `--format json` envelope for `checkmate hook run` and `checkmate search --format agent` so AI agents can immediately verify whether gitignored files were skipped or included.
