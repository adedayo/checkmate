# Tasks: 010-lsp-server-modernisation

**Status:** Implemented

## Phase 1 — Transport, Protocol & URI Hygiene (`pkg/lsp`)

- [x] Implement `Content-Length` framed JSON-RPC 2.0 transport in `pkg/lsp/transport.go` with mutex-guarded writer (no `os.Exit` in handlers).
- [x] Define LSP 3.17 wire types in `pkg/lsp/protocol.go` (`InitializeParams`/`InitializeResult`, `ServerCapabilities`, `Diagnostic` with `Data`, `CodeAction`, `ExecuteCommandParams`, `DidOpen`/`DidChange`/`DidSave`/`DidClose`).
- [x] Implement cross-platform `file://` URI <-> filesystem path helpers in `pkg/lsp/uri.go` with unit tests (spaces, percent-encoding, Unix and Windows paths).
- [x] Update `pkg/lsp/diagnostics_conversion.go`: fix `Critical` -> LSP `Error` (1), set `source: "CheckMate"`, attach `findingId`/`secretChecksum`/`ruleId` in `Diagnostic.Data`, remove `//nolint:unused`.

## Phase 2 — Real-Time Document & Workspace Scanning

- [x] Implement `pkg/lsp/exclusions.go` merging `secrets.MakeCommonExclusions()`, `--exclusion` YAML, workspace `.checkmate.yaml`, and optional SQLite active exceptions.
- [x] Implement `pkg/lsp/server.go`:
  - `initialize` returning full `ServerCapabilities` + `initialized` launching async workspace scan.
  - `textDocument/didOpen`, debounced `textDocument/didChange` (per-URI cancellation, `CHECKMATE_LSP_DEBOUNCE_MS` default 150ms), `textDocument/didSave`, `textDocument/didClose`.
  - Track `publishedURIs` and clear diagnostics (`[]`) when findings are fixed or suppressed.
  - Proper `shutdown` (returns `null` result) and `exit` (returns exit code `0` or `1` from `Serve`).
- [x] Update `cmd/lspServe.go`: route logs to `os.Stderr`, add `--data-path`, `--no-db`, `--no-workspace-scan`, and propagate exit status cleanly.

## Phase 3 — Quick Fix Code Actions & Shared Exception Write-Back

- [x] Implement `textDocument/codeAction` returning Quick Fixes (`checkmate.suppressPathHash`, `checkmate.suppressGlobalHash`, `checkmate.excludeFile`) for CheckMate diagnostics.
- [x] Implement `workspace/executeCommand` persisting suppressions to SQLite (with `audit_log`) or `.checkmate.yaml` (when `--no-db`), reloading exclusions, and re-scanning open documents immediately.

## Phase 4 — Tests & Documentation

- [x] Add end-to-end `Content-Length` pipe integration tests in `pkg/lsp/securityserver_test.go`:
  - `initialize` / `initialized` workspace scan publishing `file://` diagnostics
  - `didOpen` detecting secret -> `didChange` removing secret clearing diagnostic to `[]`
  - `didChange` debounce collapsing rapid edits
  - `Critical` severity mapping to LSP `Error` (1)
  - `codeAction` + `executeCommand` suppressing a finding and clearing diagnostics on open doc
  - `shutdown` + `exit` clean termination
- [x] Remove `github.com/adedayo/go-lsp` from `go.mod` if no other packages reference it (verify via grep before removing).
- [x] Add editor configuration examples (VS Code, Neovim, Zed, Helix) to `docs/features.md` and `docs/index.html`.
