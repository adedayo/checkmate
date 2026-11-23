# Design: 009-mcp-hardening-and-remote-triage

**Status:** Implemented

## 1. Async Scans & MCP `notifications/progress`

### Synchronous with Progress Token
Per MCP 2025-03-26, a client may include `_meta.progressToken` in `tools/call` params:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "checkmate_scan",
    "arguments": { "targets": ["/large/monorepo"] },
    "_meta": { "progressToken": "scan-4" }
  }
}
```

`Server.dispatch` extracts `progressToken` and passes a `progressFn(progress, total, message)` callback into `triage.Service.Scan`. CheckMate's existing coalesced progress callback (`diagnostics.Progress` every `CHECKMATE_PROGRESS_INTERVAL`, default 250ms) forwards into:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/progress",
  "params": {
    "progressToken": "scan-4",
    "progress": 1420,
    "total": 8500,
    "message": "Scanning pkg/auth/jwt.go"
  }
}
```

- Over **stdio**: written directly to the mutex-guarded `stdout` writer.
- Over **Streamable HTTP**: pushed to the session's `GET /v1/mcp` SSE stream (if connected) or streamed inline if the `POST /v1/mcp` client sent `Accept: text/event-stream`.

### Asynchronous Mode (`async: true`)
For MCP clients that enforce strict per-call timeouts regardless of progress notifications:
- `checkmate_scan(targets=[...], async=true)` registers an active scan tracker in `triage.Service`, starts `RunScan` in a goroutine, waits up to 5 seconds for `scanID` creation, and returns `{ "scanId": "...", "projectId": "...", "status": "running" }`.
- `checkmate_get_scan_status(scanId)` returns `{ "scanId", "status": "running|complete|failed", "filesScanned", "totalFiles", "currentFile", "overview": <ScanOverview when complete>, "error": <when failed> }`.
- Also allows checking status of historical scans directly from SQLite if not in the in-memory active map.

## 2. Unbounded Paginated Findings (`checkmate_list_findings`)

- `checkmate_list_findings` accepts:
  - `scanId` (required)
  - Optional filters: `file`, `ruleId`, `secretChecksum`, `triageStatus`, `severity`, `includeSuppressed` (default `false`)
  - Pagination: `limit` (default `50`, max `200`), `offset` (default `0`)
- Returns canonical, deterministically ordered `[]WorklistLocation` (including `localFile` when a retained checkout exists) plus `{ totalCount, hasMore, nextOffset }`.
- `checkmate_get_worklist` gains `samplesPerGroup` (default `5`, max `50`), keeping default responses compact while letting agents widen a single call when needed.

## 3. Remote Git URL Triage & Safe Checkout Lifecycle

When `checkmate_scan` is called with remote Git URLs and `keepCheckout: true`:
1. `triage.Service.Scan` sets `SecretSearchOptions.KeepCheckouts = true` (from `008`) with a per-scan `CloneBaseDir` (`<data-path>/code/<projectID>/<scanID>/`, mode `0700`).
2. `AcquisitionReport.RetainedPaths` (`sanitisedRepoURL -> localDir`) is persisted in `scans.additional_info` under `"retainedCheckouts"`.
3. `ScanOverview` includes `retainedCheckouts: { "<repoURL>": "<localDir>" }` and `acquisition: <AcquisitionReport>`.
4. `WorklistLocation` resolves `localFile` by mapping the repo URL prefix of `finding.File` through `retainedCheckouts` (and verifying the path stays inside `localDir` via `filepath.Rel` to prevent path traversal).
5. `checkmate_get_finding_context(scanId, findingId, beforeLines=20, afterLines=20)` reads the line window from `localFile` (if local/retained and still on disk) or falls back to `finding.SourceContext`, returning numbered lines plus surrounding context.
   - Note: Because this also implements the currently stubbed `sqlite.DB.GetCodeContext` (`pkg/store/sqlite/db.go:579`), Desktop App and REST clients benefit as well.
6. `checkmate_cleanup_checkout(scanId)` removes `<data-path>/code/<projectID>/<scanID>/`, clears `retainedCheckouts` in `scans.additional_info`, and writes an `audit_log` entry.
7. On server shutdown in `--ephemeral` mode (or after a configurable TTL `CHECKMATE_CHECKOUT_TTL`, default 24h), retained MCP checkouts are automatically removed.

## 4. Streamable HTTP SSE (`GET /v1/mcp`)

Add a lightweight `sessionManager` inside `pkg/mcp`:
- Maps `Mcp-Session-Id` -> `{ notifyCh chan []byte, lastActive time.Time, closeOnce sync.Once }`.
- `POST /v1/mcp` creates or looks up a session and returns `Mcp-Session-Id`.
- `GET /v1/mcp` with `Accept: text/event-stream` and `Mcp-Session-Id`:
  - Sets `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`.
  - Streams JSON-RPC notifications as `event: message\ndata: <json>\n\n` with 15s `: keepalive\n\n` comments.
- `DELETE /v1/mcp` closes the session channel and removes the session (`204 No Content`).
- Background reaper evicts idle sessions after 30 minutes to prevent memory leaks.
