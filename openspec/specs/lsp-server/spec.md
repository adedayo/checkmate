# Spec: Language Server Protocol (`lsp-server`)

**Change:** 010-lsp-server-modernisation
**Status:** Accepted

## Overview

`checkmate lspServe` runs an LSP 3.17 compliant Language Server over `stdin`/`stdout` (`Content-Length` framed JSON-RPC 2.0) providing real-time in-editor secret detection, workspace-wide scanning, shared exception awareness, and Quick Fix suppression actions.

## Requirements

### R1 — Transport & Lifecycle

- Command: `checkmate lspServe [--exclusion <yaml>] [--data-path ~/.checkmate] [--no-db] [--no-workspace-scan]`.
- Uses standard LSP `Content-Length` header framing over `stdin`/`stdout`. All logs and warnings MUST be written to `stderr`.
- `initialize` MUST return `InitializeResult` advertising:
  - `textDocumentSync`: `{ openClose: true, change: 1 (Full), save: { includeText: true } }`
  - `codeActionProvider`: `{ codeActionKinds: ["quickfix"] }`
  - `executeCommandProvider`: `{ commands: ["checkmate.suppressPathHash", "checkmate.suppressGlobalHash", "checkmate.excludeFile"] }`
- `shutdown` MUST reply with `result: null` and MUST NOT call `os.Exit` before replying.
- `exit` MUST cause `Serve` to return cleanly (`0` if `shutdown` was received, `1` otherwise).

### R2 — Real-Time Document Analysis

- `textDocument/didOpen` and `textDocument/didSave` MUST scan the document buffer immediately using `secrets.GetFinderForFileType` + `secrets.FindSecret` and publish `textDocument/publishDiagnostics` (publishing `[]` when clean).
- `textDocument/didChange` MUST debounce per document URI (`CHECKMATE_LSP_DEBOUNCE_MS`, default `150ms`) and cancel any superseded in-flight scan for the same URI.
- `textDocument/didClose` MUST cancel pending scans for the URI and clear stale in-memory diagnostics.

### R3 — Workspace Analysis & URI Correctness

- On `initialized` (unless `--no-workspace-scan`), the server MUST asynchronously scan all `workspaceFolders` (falling back to `rootUri`) using the active composite `ExclusionProvider`.
- Every published diagnostic URI MUST be a valid percent-encoded `file://` URI.
- Workspace scans MUST NOT overwrite newer in-memory diagnostics for currently open documents.

### R4 — Diagnostic Format & Severity Mapping

- Severity mapping:
  - `Critical` -> `1` (`Error`)
  - `High` -> `1` (`Error`)
  - `Medium` -> `2` (`Warning`)
  - `Low` -> `3` (`Information`)
  - `Info` -> `4` (`Hint`)
- Diagnostics MUST set `source: "CheckMate"`, 0-based `range.start` and `range.end`, `code` = rule ID, and `data` = `{ findingId, secretChecksum, ruleId }`.
- Diagnostic messages MUST contain no plaintext secret values and no em dashes (`prosecheck` compliant).

### R5 — Shared Exceptions & Quick Fix Code Actions

- Exclusions MUST merge common exclusions, `--exclusion` YAML, workspace `.checkmate.yaml`, and active SQLite exceptions (unless `--no-db`).
- `textDocument/codeAction` MUST offer Quick Fix actions (`checkmate.suppressPathHash`, `checkmate.suppressGlobalHash`, `checkmate.excludeFile`) for CheckMate diagnostics.
- `workspace/executeCommand` MUST persist the suppression (to SQLite + `audit_log`, or workspace `.checkmate.yaml` when `--no-db`), reload exclusions, and immediately re-publish updated diagnostics for open documents.
- No plaintext secret values may ever be written by Code Actions.
