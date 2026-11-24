# Spec: Pre-Commit CLI & Git Hook Integration (`pre-commit-cli`)

**Change:** 011-pre-commit-cli
**Status:** Draft

## Overview

CheckMate provides fast, deterministic CLI secret scanning suitable for Git `pre-commit` hooks via both enhanced `checkmate search` flags and a dedicated `checkmate hook` subcommand (`run`, `install`, `uninstall`), plus a root `.pre-commit-hooks.yaml` manifest.

## Requirements

### R1 - Exit Code Contract

- When `--fail-on-findings` is enabled (and always in `checkmate hook run`):
  - Exit `0`: scan completed with zero unexcluded findings at or above `--min-confidence`.
  - Exit `1`: scan completed with one or more unexcluded findings at or above `--min-confidence`.
  - Exit `2`: operational, Git, acquisition, or configuration error (for example: unreadable or invalid YAML passed via `--exclusion`, invalid `--min-confidence` or `--format`, `--staged` outside a Git repository, or target acquisition failure).
- Default `checkmate search` without `--fail-on-findings` preserves backwards compatibility (exits `0` on findings, non-zero on fatal errors).

### R2 - Git Index (Staged) & Stdin Scanning

- `--staged` MUST scan content from the Git index (staged blobs), NEVER from unstaged working-tree edits.
  - A secret staged in the index MUST be detected even if removed from the working tree.
  - A secret present only in the working tree (unstaged) MUST NOT trigger a finding under `--staged`.
- Staged extraction MUST use bounded subprocesses independent of staged file count (single `git diff --cached --raw -z`, single `git cat-file --batch`, and at most one `git diff --cached -U0` for modified hunks).
- When `--diff-only` is enabled with `--staged` (default `true` in `checkmate hook run` and `checkmate search --staged`):
  - Modified files MUST only report content findings overlapping added/modified line ranges while still scanning full staged blob context for accurate detection and line numbers.
  - Newly added files MUST report all findings, including newly added confidential files (for example `.p12`, `.pem`, `id_ed25519`).
- When zero files are staged, `--staged` MUST exit `0` immediately without initialising the secret rule catalog, prefilter automaton, or SQLite database.
- `--stdin` MUST read content from standard input and scan it using `--filename` (default `"stdin"`) for extension/confidentiality/exclusion context.

### R3 - Output Formats, Redaction & Confidence Threshold

- `--format <json|text|sarif|pdf>` selects the output format cleanly without printing duplicate formats to stdout. Legacy `--json`, `--sarif`, and `--pdf` flags remain supported.
- JSON output with zero findings MUST emit `[]` (never `null`).
- `--format text` MUST emit a concise, human-readable summary containing severity/confidence, `file:line:col`, rule description, match preview (redacted when `--redact` is set), and SHA-256 checksum.
- `--redact` MUST mask secret evidence (`first4****last4` for lengths > 12, `first2****last2` for 9-12, `****` for <= 8) while computing `SHA256` on the raw secret value.
- `--min-confidence <info|low|medium|high|critical>` MUST filter emitted and blocking findings to those at or above the specified confidence level.

### R4 - Exclusion Discovery & Inline Suppression

- CLI scans MUST auto-discover `<repoRoot>/.checkmate.yaml` (or `<cwd>/.checkmate.yaml` outside a Git repo) unless `--no-auto-exclusion` is set, and merge it with built-in exclusions and any explicit `--exclusion` file.
- When `~/.checkmate/checkmate.db` (or `--data-path`) exists and `--no-db` is not set, `checkmate hook run` (and `checkmate search` when enabled) MUST load matching project and global active SQLite exceptions in read-only mode without creating a database or running write migrations.
- Inline comments containing `checkmate:ignore` on the finding's line or `checkmate:ignore-next-line` on the immediately preceding line MUST suppress that finding (case-insensitive).

### R5 - Hook Management & `pre-commit` Framework Manifest

- `checkmate hook run [files...]` defaults to `--staged` (when no files are passed), `--diff-only`, `--format text`, `--redact`, `--fail-on-findings`, and `--min-confidence medium`.
- `checkmate hook install [--force]` resolves the hook path via `git rev-parse --git-path hooks/pre-commit`, writes an executable CheckMate-managed hook script, and refuses to overwrite an unmanaged existing hook unless `--force` is specified.
- `checkmate hook uninstall` removes the hook only if it carries the CheckMate marker.
- Repository root MUST ship `.pre-commit-hooks.yaml` defining `checkmate-staged` and `checkmate-files` hooks.

### R6 - Performance Budget

- Empty staged commit (`checkmate hook run` with 0 staged files) MUST complete without loading Gitleaks regexes or building the prefilter automaton.
- Typical single-file or small-diff staged commit MUST avoid compiling vendor regexes skipped by the literal prefilter and avoid constructing unused language finder classes.

### R7 - AI-Native Agent Discovery & Structured Envelopes

- `checkmate describe` (aliases: `capabilities`, `agent-info`) MUST emit a fast, zero-scan-init self-describing manifest of CheckMate's commands, flags, exit codes (`0`, `1`, `2`), output formats, recommended agent workflows, MCP integration (`checkmate mcp serve`), and security guardrails.
  - Default format: machine-readable JSON (`--format json`); also supports `--format markdown` for direct LLM/agent prompt or `AGENTS.md` ingestion.
- `--format agent` on `checkmate search` and `checkmate hook run` (and `--format json` on `checkmate hook run`) MUST emit a structured JSON envelope containing `status` (`clean`, `findings_detected`, `error`), `exitCode`, `mode`, `filesScanned`, `durationMs`, `minConfidence`, `redacted`, `findingsCount`, `findings`, and actionable `nextSteps` (with remediation guidance and SHA-256 suppression instructions).
- Operational errors in JSON/agent formats MUST emit valid structured JSON to stdout (or stderr cleanly without corrupting stdout), and root CLI errors MUST write to `stderr` so `stdout` remains strictly machine-parseable.
- All CLI subcommands MUST remain strictly non-interactive (never block on TTY prompts) and document exit codes and agent-friendly examples in `--help`.

