# Design: 011-pre-commit-cli

**Status:** Implemented

## Architecture

```text
git commit  ──►  .git/hooks/pre-commit (or pre-commit framework)
                     │
                     ▼
        cmd/hook.go (`checkmate hook run | install | uninstall`)
        cmd/secretSearch.go (`checkmate search [flags] [paths...]`)
                     │
                     ├──► Fast path: 0 staged files -> exit 0 immediately (~3-5ms)
                     │
                     ├──► pkg/precommit/staged.go
                     │      1. Single `git rev-parse --show-toplevel`
                     │      2. Single `git diff --cached -U0 --no-color --no-ext-diff --diff-filter=ACMR`
                     │         -> staged paths + added/modified line ranges + added-file flag
                     │      3. Single `git cat-file --batch` (streaming `:path` blobs over stdin/stdout)
                     │      4. Parallel worker pool over staged blobs via ScanContext + ConfidentialCheck
                     │      5. Filter findings by added-line ranges (diff-only mode) + inline ignore + min-confidence
                     │
                     ├──► pkg/precommit/format.go
                     │      Redaction (`first4****last4`), concise terminal text formatter, JSON/SARIF
                     │
                     ├──► pkg/precommit/exclusions.go
                     │      Merges: MakeCommonExclusions + repo-root `.checkmate.yaml`
                     │              + explicit `-e` YAML + optional read-only SQLite exceptions
                     │
                     └──► pkg/plugin/secrets-finder/pkg
                            - Lazy vendor rule catalog (`sync.Once`, `syntax.Parse` + `prefilter.BuildPatterns`)
                            - Per-rule lazy `*regexp.Regexp` compilation (`sync.Once` on prefilter admission)
                            - Lazy per-extension `ScanContext` finder class construction
                            - Inline `checkmate:ignore` / `checkmate:ignore-next-line` suppression
                            - Expanded text/config extensions (`.env*`, `.tfvars`, `.toml`, `.properties`, ...)
```

## Key Design Details

### 1. Eliminating CLI Startup Latency (`pkg/plugin/secrets-finder/pkg/`)

Today, every invocation of `checkmate` spends ~50ms inside `regexes.go`'s `init()` compiling ~222 Gitleaks regexes twice (`regexp.Compile` in `loadGitleaksPatterns`, then `regexp.MustCompile` in `setupVendorSecrets`), plus ~35ms constructing all 8 `ScanContext` finder classes and building the prefilter automaton.

Optimisation strategy (100% finding-identical):

1. **Pattern-based prefilter (`prefilter.BuildPatterns`):**
   - `prefilter.Build` already only calls `rules[id].String()` and passes the pattern string to `extractSeeds` (`regexp/syntax.Parse`).
   - Add `prefilter.BuildPatterns(patterns map[string]string) *Matcher` and have `Build(rules map[string]*regexp.Regexp)` delegate to it.
2. **Lazy vendor rule catalog + per-rule lazy compilation:**
   - Replace eager `init()` compilation of Gitleaks rules with a `sync.Once`-initialised `vendorCatalog`:
     - Parses embedded `gitleaks.toml` once on first scan use.
     - Validates each Gitleaks regex with `syntax.Parse(rule.Regex, syntax.Perl)` (orders of magnitude faster than full NFA compilation, and exact because Go's `regexp.Compile` fails iff `syntax.Parse` fails for Perl syntax).
     - Builds deterministic `sortedIDs []string`, `patterns []string`, and `compiled []lazyRegex` (where each `lazyRegex` holds a `sync.Once` + `*regexp.Regexp`).
   - `vendorMatcher()` builds the Aho-Corasick automaton via `prefilter.BuildPatterns(catalog.patternMap)` — without compiling a single Gitleaks `*regexp.Regexp`.
   - `vendorRegexAt(i int) *regexp.Regexp` compiles rule `i` only when the prefilter admits it (or when prefiltering is disabled).
   - `regexSecretFinder` gains an optional lazy regex resolver (`lazyIndex int` or `func() *regexp.Regexp`) so constructing a vendor finder does not force compilation of skipped rules.
   - Preserve package-internal helper `getVendorSecrets()` for tests that inspect the full compiled rule map.
3. **Lazy per-class construction in `ScanContext`:**
   - `NewScanContext` initialises empty `providers`/`consumers` maps and builds `classJava`, `classYAML`, `classDefault`, etc. on demand inside `consumersFor(class finderClass)`.
   - On a commit touching only Go files, only `classJava` is built (1/8th the setup cost).
4. **Zero-cost fast path for empty staged commits:**
   - `checkmate hook run` runs `git diff --cached` first. When zero staged files are present, it returns `0` without ever triggering `vendorCatalog`, `vendorMatcher()`, `NewScanContext`, or SQLite.

### 2. Fast Git Staged Blob & Diff-Hunk Scanner (`pkg/precommit/`)

1. **Repo root discovery:** `git rev-parse --show-toplevel` (1 subprocess, ~2ms).
2. **Staged diff extraction:** Single subprocess:
   ```text
   git -c core.quotepath=false diff --cached -U0 --no-color --no-ext-diff --no-renames --diff-filter=ACMR
   ```
   -Wait: what about renames (`R`)? With `--no-renames`, Git reports renames as `D` + `A`, so renamed/moved files with newly staged content are cleanly included under `A`! And `--diff-filter=ACMR` handles added, copied, modified, and type-changed files while ignoring deletions.
   - Wait: what about binary staged files (like `.p12`, `.jks`, `.pfx` keystores)? `git diff --cached` prints `Binary files /dev/null and b/path/to/cert.p12 differ` (or `GIT binary patch`), which we also parse from `diff --git a/... b/...` headers + `new file mode` headers so newly added binary confidential files (`.p12`, `.jks`, `id_ed25519`, etc.) are ALWAYS caught!
   - Even cleaner and 100% immune to unusual filenames/quoting:
     - Call 1: `git diff --cached --raw -z --no-renames --diff-filter=ACMR` gives exact NUL-delimited `(status, stagedBlobSHA, path)` tuples for every staged file (including binary files, spaces/tabs/newlines in filenames, and exact blob object IDs).
     - Call 2 (only if `diffOnly` is true and at least one file has status `M`): `git diff --cached -U0 --no-color --no-ext-diff --no-renames --diff-filter=M` parses `diff --git` + `@@ -old +newStart,newCount @@` hunk headers to map each modified file to its added/changed 1-based line intervals `[newStart, newStart+newCount-1]`. Newly added (`A`) files treat all lines as added.
     - Call 3 (only for non-excluded staged files whose size <= 10MB or recognised extension): Single `git cat-file --batch` piped with the exact `<blobSHA>\n` list from Call 1. One subprocess reads all staged blobs directly from Git's object store with zero working-tree interference!
3. **Scanning staged blobs:**
   - Run through the same engine (`ScanContext.FindSecretsInFile` + confidential file content/extension checks) in parallel across workers bounded by `min(len(stagedFiles), GOMAXPROCS)`.
   - Apply inline `checkmate:ignore` / `checkmate:ignore-next-line` filtering against the staged blob's lines.
   - Apply `ExclusionProvider` (`ShouldExcludePath`, `ShouldExclude`, `ShouldExcludeHash`, `ShouldExcludeHashOnPath`).
   - In `diffOnly` mode: for modified (`M`) files, keep findings whose 1-based line range (`[Range.Start.Line+1, Range.End.Line+1]`) overlaps any added hunk interval. For newly added (`A`) files, keep all findings (including confidential-file diagnostics).

### 3. Fixing Scannable File Coverage (`pkg/core/definitions.go`, `pkg/plugin/secrets-finder/pkg/`)

1. **Extensions:** Add `.env`, `.local`, `.development`, `.production`, `.staging`, `.properties`, `.ini`, `.cfg`, `.toml`, `.tf`, `.tfvars`, `.hcl`, `.npmrc`, `.pypirc`, `.netrc`, `.tsx`, `.jsx`, `.cjs`, `.kts`, `.dockerfile`, `.htpasswd`, `.pgpass`, `.dockercfg`, `.kubeconfig` to `TextFileExtensions` (via `tfe1`).
2. **Case-insensitive lookup + `.env.*` filenames:** In `consumePathGated`, normalize `lowerExt := strings.ToLower(ext)` when checking `common.TextFileExtensions` and `recognisedFiles`, and also allow any file whose base name starts with `.env` (case-insensitive, e.g. `.env`, `.env.local`, `.env.prod`, `.env.custom`).
3. **Modern SSH keys:** Add `id_ed25519`, `id_ecdsa`, `id_ed25519_sk`, `id_ecdsa_sk` to `DangerousFileNames` and handle them (plus their `.pub` counterparts as `Info`) in `checkConfidential`.
4. **Golden baseline:** Re-record `testdata/golden/reference-corpus.json` deliberately so the two real secrets in `repo-a/.env` (`DATABASE_URL` MySQL password + `STRIPE_KEY`) are locked in.

### 4. Exclusion Correctness & Shared Suppression Parity

1. **`secrets.MergeExclusions`:** Preserve and deterministically deduplicate `GloballyExcludedHashes` and `PerFileExcludedHashes` alongside all existing fields.
2. **File-argument prefix stripping:** In `defaultExclusionProvider.ShouldExclude` and `ShouldExcludeHashOnPath`, only strip a repository prefix when it is a proper directory prefix of `pathContext` (never when `prefix == pathContext`). In `cmd/secretSearch.go`, populate `ExcludeContainer.Repositories` with directory roots (or repo root for files) rather than raw file paths.
3. **Root-relative default exclusions:** Update `MakeCommonExclusions` patterns to `(?:^|.*/)[.]git/.*`, `(?:^|.*/)(?i:package-lock|npm-shrinkwrap)[.]json`, and `(?:^|.*/)node_modules/.*`. Verify `directoryPrunePattern` still derives valid pruners for `.git` and `node_modules`.
4. **Repo `.checkmate.yaml` + optional read-only SQLite exceptions:**
   - Auto-discover `<repoRoot>/.checkmate.yaml` (or `<cwd>/.checkmate.yaml` when not in a Git repo) and merge with built-in exclusions and explicit `-e` file.
   - When `~/.checkmate/checkmate.db` exists and `--no-db` is not set, query active exceptions for matching project/global scopes in read-only mode (`?mode=ro`) without running schema migrations or creating files.
5. **Inline suppressions:**
   - Inside file scanning (`ScanContext.FindSecretsInFile` or post-aggregation over file bytes), suppress findings whose start line contains `checkmate:ignore` (case-insensitive) or whose immediately preceding line contains `checkmate:ignore-next-line` (case-insensitive).

### 5. CLI Interface, Output Formats & Exit Codes

#### Exit Codes (when `--fail-on-findings` is enabled, or in `checkmate hook run`)
- `0`: Scan succeeded, zero unexcluded findings at or above `--min-confidence`.
- `1`: Scan succeeded, one or more unexcluded findings at or above `--min-confidence`.
- `2`: Operational/configuration/git/acquisition error (invalid `--exclusion` file or YAML, invalid flag value, not a git repo when `--staged` is requested, target acquisition failure).

#### Redaction (`--redact`)
- Always compute `SHA256` on the raw secret before redacting.
- Replace raw secret in `Source` with `redactSecret(raw)`:
  - If `len(raw) <= 8`: `"****"`
  - If `len(raw) <= 12`: `raw[:2] + "****" + raw[len(raw)-2:]`
  - Otherwise: `raw[:4] + "****" + raw[len(raw)-4:]`
  - Consistent with Guardrail 3 (`first 4 + last 4 chars`).

#### Text Formatter (`--format text`)
Clean, concise, grep-friendly terminal report (no em dashes):
```text
CheckMate found 2 potential secret(s) in 3 staged file(s) (18ms):

  [CRITICAL] src/config.go:14:21  Discovered a GitHub OAuth Access Token...
             match: ghp_****0099  sha256: 9f86d081884c...
  [HIGH]     .env:2:12            Found a Stripe Access Token...
             match: sk_t****7dc   sha256: 4a1b2c3d4e5f...

Commit blocked. To suppress a false positive, add its sha256 to .checkmate.yaml or append 'checkmate:ignore' to the line.
```

#### `checkmate hook` Commands
- `checkmate hook run [files...]`:
  - Defaults: `--staged` (when no positional files passed, or explicitly `--staged`), `--diff-only=true`, `--format text`, `--redact=true`, `--fail-on-findings=true`, `--min-confidence medium`.
  - When positional files are passed (e.g., `pre-commit` framework with `pass_filenames: true`), scans those files directly unless `--staged` is explicitly set.
- `checkmate hook install [--force]`:
  - Resolves hook path via `git rev-parse --git-path hooks/pre-commit` (supports worktrees and `core.hooksPath`).
  - Writes a POSIX `#!/bin/sh` script containing a marker (`# checkmate-managed-hook`) that executes `exec checkmate hook run "$@"` with mode `0755`.
  - Refuses to overwrite an existing non-CheckMate hook unless `--force` is passed.
- `checkmate hook uninstall`:
  - Removes the hook only if it contains `# checkmate-managed-hook`.

#### `.pre-commit-hooks.yaml`
Provides two hooks at repo root:
- `checkmate-staged`: `entry: checkmate hook run --staged`, `pass_filenames: false`, `language: system`
- `checkmate-files`: `entry: checkmate hook run`, `pass_filenames: true`, `language: system`
