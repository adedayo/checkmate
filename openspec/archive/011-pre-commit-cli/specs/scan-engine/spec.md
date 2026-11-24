# Spec Delta: Scan Engine (`scan-engine`)

**Change:** 011-pre-commit-cli
**Status:** Draft

## Delta Requirements

### R7 - Lazy Rule Initialisation & Per-Class Construction (Performance, Finding-Identical)

- Package initialisation (`init()`) MUST NOT parse `gitleaks.toml` or compile vendor regular expressions eagerly.
- The literal prefilter MUST support construction directly from pattern strings (`prefilter.BuildPatterns`) so vendor rules skipped by the prefilter are never compiled into `*regexp.Regexp` automata during short-lived CLI invocations.
- Each vendor rule's `*regexp.Regexp` MUST be compiled at most once per process (lazily via per-rule `sync.Once`) when admitted by the prefilter or when prefiltering is disabled.
- `ScanContext` MUST construct each extension `finderClass` lazily on first file of that class rather than building all 8 classes up front.
- These optimisations MUST be finding-identical to eager compilation, verified by `TestPrefilterEquivalence` and `TestScanEquivalence`.

### R8 - Config/Dotfile Coverage & Exclusion Correctness (Product Decision)

- `common.TextFileExtensions` and file-scanning eligibility MUST cover modern secret-bearing configuration, IaC, and frontend text extensions: `.env`, `.local`, `.development`, `.production`, `.staging`, `.properties`, `.ini`, `.cfg`, `.toml`, `.tf`, `.tfvars`, `.hcl`, `.npmrc`, `.pypirc`, `.netrc`, `.tsx`, `.jsx`, `.cjs`, `.kts`, `.dockerfile`, `.htpasswd`, `.pgpass`, `.dockercfg`, `.kubeconfig`, plus any `.env.*` filename regardless of suffix.
- Extension lookup in `consumePathGated` MUST be case-insensitive.
- `common.DangerousFileNames` and `checkConfidential` MUST recognise `id_ed25519`, `id_ecdsa`, `id_ed25519_sk`, and `id_ecdsa_sk` (and treat their `.pub` counterparts as `Info` public keys).
- `secrets.MergeExclusions` MUST preserve and deterministically deduplicate `GloballyExcludedHashes` and `PerFileExcludedHashes`.
- `MakeCommonExclusions` path patterns MUST match both root-relative paths (for example `package-lock.json`, `node_modules/a.js`) and nested paths while preserving directory pruning.
- `ShouldExclude` and `ShouldExcludeHashOnPath` MUST NOT strip a repository prefix that equals the entire `pathContext` (preserving per-file exclusions when individual files are passed as scan targets).
- Findings whose start line contains `checkmate:ignore` or whose preceding line contains `checkmate:ignore-next-line` (case-insensitive) MUST be suppressed.
- `testdata/golden/reference-corpus.json` MUST be deliberately re-recorded to reflect the newly detected `repo-a/.env` findings.
