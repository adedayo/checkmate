# Tasks: 011-pre-commit-cli

**Status:** Implemented

## Phase 1 - Startup & Engine Performance (`pkg/plugin/secrets-finder/pkg`)

- [x] Add `prefilter.BuildPatterns(patterns map[string]string) *Matcher` in `pkg/plugin/secrets-finder/pkg/prefilter/prefilter.go` and delegate `Build` to it.
- [x] Replace eager `init()` Gitleaks compilation with lazy `vendorCatalog` (`sync.Once` + `syntax.Parse` validation + per-rule `sync.Once` `*regexp.Regexp` compilation) in `pkg/plugin/secrets-finder/pkg/regexes.go`, `gitleaks.go`, `specific_vendor_finders.go`, `secrets_util.go`, and `prefilter_gate.go`.
- [x] Make `ScanContext` lazily initialise each `finderClass` on first use in `pkg/plugin/secrets-finder/pkg/scancontext.go`.
- [x] Verify finding-equivalence via `TestPrefilterEquivalence`, `TestScanEquivalence`, and `-race`.

## Phase 2 - Coverage, Exclusion Correctness & Inline Suppression

- [x] Expand `TextFileExtensions` in `pkg/core/definitions.go` (`.env`, `.local`, `.development`, `.production`, `.staging`, `.properties`, `.ini`, `.cfg`, `.toml`, `.tf`, `.tfvars`, `.hcl`, `.npmrc`, `.pypirc`, `.netrc`, `.tsx`, `.jsx`, `.cjs`, `.kts`, `.dockerfile`, `.htpasswd`, `.pgpass`, `.dockercfg`, `.kubeconfig`) and add `id_ed25519`, `id_ecdsa`, `id_ed25519_sk`, `id_ecdsa_sk` to `DangerousFileNames` and `checkConfidential`.
- [x] Normalise extensions case-insensitively and allow `.env.*` basenames in `pkg/plugin/secrets-finder/pkg/path_processing.go`.
- [x] Deliberately re-record `pkg/plugin/secrets-finder/pkg/testdata/golden/reference-corpus.json` to include the `repo-a/.env` findings and verify diff.
- [x] Fix `secrets.MergeExclusions` in `pkg/plugin/secrets-finder/pkg/regexes.go` to preserve `GloballyExcludedHashes` and `PerFileExcludedHashes`.
- [x] Fix `MakeCommonExclusions` patterns to match root-relative paths (`(?:^|.*/)...`) while preserving directory pruning.
- [x] Fix file-path prefix stripping in `pkg/core/diagnostics/exclusion.go` (`ShouldExclude` and `ShouldExcludeHashOnPath`) and `cmd/secretSearch.go`.
- [x] Implement inline suppression (`checkmate:ignore` and `checkmate:ignore-next-line`) during file scanning.

## Phase 3 - Fast Git Staged, Stdin & Pre-Commit Engine (`pkg/precommit`)

- [x] Implement fast staged scanner (`pkg/precommit/staged.go`): single `git diff --cached --raw -z` + optional single `git diff --cached -U0` hunk parser + single `git cat-file --batch` blob reader + parallel worker pool + diff-hunk filtering.
- [x] Implement stdin blob scanning (`ScanReader`) with filename, confidential check, inline ignore, and exclusions.
- [x] Implement shared exclusion loader (`pkg/precommit/exclusions.go`): built-in common + repo-root `.checkmate.yaml` + explicit `-e` YAML + optional fast read-only SQLite exception reader (`?mode=ro`, skipped when DB absent).
- [x] Implement secret redaction, confidence threshold filtering, and clean terminal text formatter (`pkg/precommit/format.go`).
- [x] Implement hook installer/uninstaller (`pkg/precommit/install.go`) respecting `git rev-parse --git-path hooks/pre-commit`.

## Phase 4 - CLI Commands, AI-Native Discovery & Ecosystem Integration

- [x] Upgrade `cmd/secretSearch.go` with `--fail-on-findings`, `--format` (`json|text|sarif|pdf|agent`), `--redact`, `--min-confidence`, `--staged`, `--diff-only`, `--stdin`, `--filename`, `--no-auto-exclusion`, `--data-path`, `--no-db`; fix JSON empty `[]` output, `--sarif`/`--pdf` exclusivity, and strict exit `2` on invalid `-e`.
- [x] Add `cmd/hook.go` (`checkmate hook run`, `checkmate hook install`, `checkmate hook uninstall`) with agent-ready structured JSON/agent output envelopes and redacted text defaults.
- [x] Add `cmd/describe.go` (`checkmate describe`, aliases `capabilities`, `agent-info`) returning a fast JSON/Markdown AI-agent capability manifest (commands, flags, exit codes, recipes, MCP/LSP discovery, guardrails) with zero scan-engine startup cost.
- [x] Fix `cmd/root.go` to route errors to `stderr` and include agent discovery guidance in `--help`.
- [x] Add root `.pre-commit-hooks.yaml` manifest.

## Phase 5 - Tests, Benchmarks & Verification

- [x] Add unit & integration tests covering:
  - Lazy vendor compilation & `ScanContext` equivalence + startup latency benchmark
  - `.env`, `.env.local`, `.tfvars`, `.toml`, `.npmrc`, `.properties`, `.tsx`, `id_ed25519` detection
  - `MergeExclusions` hash preservation, file-path `Repositories` exclusion matching, root-relative common exclusions
  - `checkmate:ignore` and `checkmate:ignore-next-line` inline suppression
  - End-to-end real `git` repo tests: staged vs working-tree divergence (`git add -p` style), diff-only ignoring untouched legacy lines while catching newly added secrets, newly added confidential binary files (`.p12`/`id_ed25519`), clean empty commit fast path, `--stdin`, exit codes `0`/`1`/`2`, redaction, `--min-confidence`, `.checkmate.yaml` auto-discovery, and `hook install`/`uninstall`.
- [x] Update `README.md` with pre-commit hook and AI-native CLI usage.
- [x] Run full validation: `go build ./...`, `go test -race ./...`, `go run ./tools/prosecheck`, `golangci-lint run`, and cold-start timing verification.
