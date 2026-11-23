# OpenSpec Proposal: 010-lsp-server-modernisation

**Status:** Implemented
**Capabilities:** `lsp-server` (new)
**Type:** Feature / Revival

## Goal

Revive and modernise CheckMate's Language Server Protocol server (`checkmate lspServe`, `pkg/lsp/`) from a dormant commented-out stub into a **full-fledged, production-ready in-editor secret scanner** compatible with VS Code, Neovim, Zed, Helix, Emacs, and JetBrains LSP clients.

Developers get sub-second inline diagnostics while editing, full workspace scanning on open, shared suppression awareness with CheckMate Desktop App and MCP triage (`~/.checkmate/checkmate.db` + `.checkmate.yaml`), and one-click **Quick Fix code actions** to suppress false positives without leaving their editor.

## Motivation

Inspection of `pkg/lsp/securityserver.go` and `pkg/lsp/diagnostics_conversion.go` showed that the current LSP server produces zero diagnostics:

1. **All scanning handlers are commented out.** `analyseWorkspace`, `didOpen`, and `didChange` have empty bodies; `diagnostics_conversion.go` functions carry `//nolint:unused`.
2. **Engine API drift.** The commented code references obsolete signatures for `secrets.GetFinderForFileType` and `secrets.FindSecret` that no longer compile against `pkg/plugin/secrets-finder/pkg`.
3. **Protocol defects.** `shutdown` calls `os.Exit(0)` immediately without returning a JSON-RPC response (causing editors to report a server crash); `initialize` does not advertise capabilities (`textDocumentSync`, `codeActionProvider`, `executeCommandProvider`); `didClose` never clears stale diagnostics; `Critical` confidence maps to LSP `Hint` (`4`) instead of `Error` (`1`); `analyseWorkspace` ignores `ss.ExclusionProvider` and emits bare paths instead of `file://` URIs.
4. **Disconnected from CheckMate's exception store.** `lspServe` has no awareness of SQLite exceptions created via CheckMate Desktop App, REST API, or MCP agent triage, causing editors to cry wolf on already-triaged false positives.
5. **No tests.** `pkg/lsp` has zero unit or integration tests.

## Scope

1. **Standards-Compliant LSP Lifecycle (LSP 3.17 over stdio):**
   - Clean `initialize` handshake returning `ServerCapabilities` (`textDocumentSync: Full`, `save`, `codeActionProvider`, `executeCommandProvider`, `workspace.workspaceFolders`).
   - Proper `shutdown` (returns `null` result, stops accepting requests) followed by `exit` (`0` if shutdown was received, `1` otherwise).
   - Clean `stdout` framing (`log.SetOutput(os.Stderr)` in `cmd/lspServe.go`).
2. **Real-Time Document & Workspace Secret Analysis:**
   - `initialized` -> asynchronous workspace scan of all `workspaceFolders` (or `rootUri`) using `secrets.SearchSecretsOnPaths` with the active exclusion provider, publishing diagnostics per file using properly encoded `file://` URIs and clearing resolved diagnostics on subsequent scans.
   - `textDocument/didOpen`, `textDocument/didChange` (debounced per-URI, default 150ms, cancelling superseded in-flight scans), `textDocument/didSave` (immediate scan), and `textDocument/didClose` (clear diagnostics when file is not flagged by workspace scan or on close).
   - Wire directly to the current `secrets.GetFinderForFileType(fileType, secOpts)` + `secrets.FindSecret(rif, reader, finder, false)` APIs (benefiting automatically from the literal prefilter added in `003-scan-engine-performance`).
3. **Accurate Diagnostics & Severity Mapping:**
   - Map `Critical` and `High` -> LSP `Error` (1), `Medium` -> `Warning` (2), `Low` -> `Information` (3), `Info` -> `Hint` (4).
   - Populate accurate 0-based `start`/`end` ranges, rule `code`, `source: "CheckMate"`, human-readable justification message, and structured `data` payload (`findingId`, `secretChecksum`, `ruleId`) for Code Actions.
4. **Shared Exception & Suppression Integration:**
   - Merge exclusions from:
     1. Built-in common exclusions (`secrets.MakeCommonExclusions()`).
     2. Workspace `.checkmate.yaml` (auto-discovered at workspace root, plus optional `--exclusion` CLI flag).
     3. Active SQLite exceptions from `--data-path` (default `~/.checkmate`, opt-out via `--no-db`) matching the workspace project or global scope.
   - Automatically reload exclusions when `.checkmate.yaml` changes (`workspace/didChangeWatchedFiles` or mtime check) or after a Code Action executes.
5. **In-Editor Quick Fix Code Actions (`textDocument/codeAction` + `workspace/executeCommand`):**
   - Provide quick fixes on any CheckMate diagnostic:
     - **"CheckMate: Suppress this value in this file (`pathHash`)"**
     - **"CheckMate: Suppress this value across project (`globalHash`)"**
     - **"CheckMate: Exclude this file from secret scanning (`pathRegex`)"**
   - Persist the suppression to SQLite (`exceptions` table + `audit_log`) or workspace `.checkmate.yaml` (when `--no-db` is set), refresh the exclusion provider, and immediately re-scan and re-publish cleared diagnostics for the open document.
6. **Comprehensive Test Suite:**
   - End-to-end LSP JSON-RPC (`Content-Length` framed) integration tests in `pkg/lsp/securityserver_test.go` covering `initialize`, `didOpen`, `didChange` debounce, `didSave`, `didClose`, `codeAction` + `executeCommand` suppression, `file://` URI round-tripping, and clean `shutdown`/`exit`.

## Non-Goals

- **Editor-specific extension marketplace packaging (VS Code `.vsix`, Neovim plugin).** CheckMate ships the standard `checkmate lspServe` binary; lightweight configuration snippets for VS Code, Neovim, Zed, and Helix are documented in `docs/`.
- **AI / LLM calls inside the LSP hot path.** Editor keystroke analysis MUST remain purely local, deterministic, and sub-50ms per file. AI triage remains driven by MCP (`007`/`009`) or Desktop App / API.
- **Incremental diff text sync (`TextDocumentSyncKindIncremental`).** Full-document sync (`TextDocumentSyncKindFull`) is fast, simple, and exact for CheckMate's line-indexed regex/entropy scanner.

## Guardrail Interactions

- **Guardrail 3 (No plaintext secrets stored):** Code Actions store only `secretChecksum` (`pathHash`/`globalHash`) or file paths (`pathRegex`) in SQLite / `.checkmate.yaml` — never plaintext secret strings.
- **Guardrail 4 & 6 (Stable identity & determinism):** Diagnostics emitted per file are sorted canonically and carry the same `findingID` and `secretChecksum` used by CLI, API, Desktop App, and MCP.
- **Prose check (`tools/prosecheck`):** All user-visible diagnostic messages and Code Action titles MUST contain no em dashes.

## Decisions

| # | Decision |
|---|---|
| 1 | Replace the minimal `go-lsp` wrapper or extend `pkg/lsp` with clean stdlib `Content-Length` LSP 3.17 JSON-RPC framing so we have full control over `initialize` capabilities, `shutdown`/`exit`, `codeAction`, `executeCommand`, cancellation, and concurrent writes without upstream wrapper constraints. |
| 2 | Debounce `textDocument/didChange` per document URI (150ms default, configurable via `CHECKMATE_LSP_DEBOUNCE_MS`) with per-document context cancellation so typing in large files stays lag-free. |
| 3 | Auto-discover workspace `.checkmate.yaml` and read `~/.checkmate/checkmate.db` (read/write, opt-out via `--no-db`) so IDE diagnostics stay in sync with CheckMate App and MCP suppressions. |
| 4 | Map `Critical` and `High` to LSP `Error` (1) so real credentials surface prominently in editor Problems panels. |
