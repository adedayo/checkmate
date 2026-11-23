# Design: 010-lsp-server-modernisation

**Status:** Implemented

## Architecture

```text
Editor (VS Code / Neovim / Zed / Helix / JetBrains)
   │  LSP 3.17 over stdio (Content-Length framed JSON-RPC 2.0)
   ▼
cmd/lspServe.go (`checkmate lspServe [--exclusion file] [--data-path ~/.checkmate] [--no-db] [--no-workspace-scan]`)
   │  log.SetOutput(os.Stderr)
   ▼
pkg/lsp (Server)
   ├── transport.go         Content-Length JSON-RPC 2.0 reader/writer (mutex-guarded)
   ├── protocol.go          LSP 3.17 types (Initialize, Diagnostics, CodeAction, ExecuteCommand)
   ├── uri.go               Cross-platform file:// URI <-> filesystem path conversion
   ├── exclusions.go        Composite ExclusionProvider (common + .checkmate.yaml + SQLite exceptions)
   ├── diagnostics.go       SecurityDiagnostic -> lsp.Diagnostic conversion (Critical->Error, data payload)
   └── server.go            Lifecycle, debounced doc scanning, workspace scan, Code Actions
   │
   ├──► pkg/plugin/secrets-finder/pkg (GetFinderForFileType, FindSecret, SearchSecretsOnPaths)
   └──► pkg/store/sqlite              (optional shared exceptions + audit_log)
```

## Key Design Details

### 1. Why Replace `go-lsp`'s `DefaultServer` Wrapper

`github.com/adedayo/go-lsp` (`v0.0.9`, unchanged since 2020) lacks LSP 3.17 `codeActionProvider`, `executeCommandProvider`, `Diagnostic.Data`, per-request cancellation, and proper `shutdown`/`exit` semantics without `os.Exit` inside handlers. Writing a compact, self-contained `Content-Length` framed JSON-RPC 2.0 layer in `pkg/lsp/` (mirroring `pkg/mcp/`) is ~150 lines of stdlib Go, removes an unmaintained dependency, makes every handler trivially unit-testable over `io.Pipe` without calling `os.Exit`, and guarantees thread-safe writes when debounced scans and workspace scans publish diagnostics concurrently.

### 2. Document Lifecycle & Debouncing

Maintain a thread-safe per-URI document table:

```go
type openDocument struct {
    uri     string
    path    string
    version int
    text    string
    timer   *time.Timer
    cancel  context.CancelFunc
}
```

- **`textDocument/didOpen`**: stores document, runs immediate scan in a goroutine, publishes `textDocument/publishDiagnostics` (even if empty `[]` to clear stale diagnostics).
- **`textDocument/didChange`**: updates `text` and `version`, cancels any in-flight scan for this URI, resets a per-URI debounce timer (`150ms` default). When the timer fires, scans the latest `text` snapshot and publishes diagnostics only if `version` still matches.
- **`textDocument/didSave`**: cancels pending debounce timer and runs an immediate scan.
- **`textDocument/didClose`**: stops timer, cancels in-flight scan, removes from open table, and publishes empty `[]` diagnostics (unless the workspace scan owns diagnostics for that file, in which case we keep or clear per `clearOnClose` setting; default: keep workspace diagnostics if present, else publish `[]`).

### 3. Single-File Scanning Path

In `scanDocument(ctx, filePath, content)`:
1. Consult composite `ExclusionProvider.ShouldExcludePath(filePath)` first — skip excluded paths immediately and publish `[]`.
2. Build `secOpts := secrets.SecretSearchOptions{ ShowSource: false, CalculateChecksum: true, Exclusions: exclusions }`.
3. Resolve matcher via `finder := secrets.GetFinderForFileType(filepath.Ext(filePath), secOpts)`.
4. Construct `rif := util.RepositoryIndexedFile{ File: filePath, RepositoryIndex: 0 }` and iterate `secrets.FindSecret(rif, strings.NewReader(content), finder, false)`.
5. Sort diagnostics canonically (`diagnostics.SortDiagnosticsCanonically`), convert to `[]lsp.Diagnostic` (preserving `findingId`, `secretChecksum`, `ruleId` in `Diagnostic.Data`), and publish via `textDocument/publishDiagnostics` with `uri = pathToFileURI(filePath)`.

### 4. Workspace Scanning & Clearing Resolved Diagnostics

On `initialized` (unless `--no-workspace-scan` is passed):
- Runs `secrets.SearchSecretsOnPaths(workspacePaths, secOpts)` in a background goroutine bounded by the server context.
- Skips files currently open in the editor (which are scanned directly from in-memory buffer contents so unsaved edits aren't overwritten by stale disk contents).
- Tracks `publishedURIs map[string]struct{}`; on rescan (e.g. after reloading exclusions), any previously flagged URI that now has 0 findings receives `publishDiagnostics(uri, [])` so resolved warnings disappear cleanly from the editor Problems panel.

### 5. Shared Exclusions & Quick Fix Code Actions

`compositeExclusions` merges:
1. `secrets.MakeCommonExclusions()` (lockfiles, stylesheets, etc.)
2. Workspace `.checkmate.yaml` (discovered in each workspace root) + explicit `--exclusion` YAML file
3. Active exceptions from SQLite (`~/.checkmate/checkmate.db`) for any project whose repository matches the workspace path (plus global exceptions), when `--no-db` is false.

`textDocument/codeAction`:
- Inspects `params.Context.Diagnostics` for diagnostics with `source == "CheckMate"` and valid `data` (`findingId`, `secretChecksum`, `ruleId`).
- Returns up to 3 `CodeAction` items (`kind: "quickfix"`):
  1. `checkmate.suppressPathHash`: `CheckMate: Suppress this value in this file`
  2. `checkmate.suppressGlobalHash`: `CheckMate: Suppress this value across project`
  3. `checkmate.excludeFile`: `CheckMate: Exclude this file from secret scanning`

`workspace/executeCommand`:
- Executes the chosen command:
  - When SQLite store is attached: creates an `active` `store.Exception` (`createdBy: "lsp:editor"`, `reason: "false_positive_pattern"`, `tags: ["lsp-quickfix"]`) + `audit_log` entry, matching or creating the project for the workspace root.
  - When `--no-db` is set (or no DB available): appends the hash (`PerFileExcludedHashes` / `GloballyExcludedHashes`) or path regex (`PathExclusionRegExs`) cleanly to `<workspaceRoot>/.checkmate.yaml`.
- Recompiles `compositeExclusions` and immediately re-scans all open documents so the suppressed diagnostic vanishes in real time.

### 6. Severity & URI Correctness

- Severity mapping:
  - `Critical` -> `1` (`Error`)
  - `High` -> `1` (`Error`)
  - `Medium` -> `2` (`Warning`)
  - `Low` -> `3` (`Information`)
  - `Info` -> `4` (`Hint`)
- `file://` URI conversion (`pkg/lsp/uri.go`):
  - Properly handles URL percent-encoding (spaces, unicode), macOS/Linux `/path/to/file` -> `file:///path/to/file`, and Windows `C:\path\file` -> `file:///C:/path/file`.
