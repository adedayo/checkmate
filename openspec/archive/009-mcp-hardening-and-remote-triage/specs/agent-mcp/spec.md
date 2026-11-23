# Spec Delta: Agent MCP Server (`agent-mcp`)

**Change:** 009-mcp-hardening-and-remote-triage

## New & Updated Tools

### R9 — Async Scan & `checkmate_get_scan_status`

- `checkmate_scan` gains optional inputs:
  - `async` (`bool`, default `false`): starts the scan in the background and returns `{ scanId, projectId, status: "running" }` immediately.
  - `keepCheckout` (`bool`, default `false`): retains cloned remote Git repositories under `<data-path>/code/<projectID>/<scanID>/` (mode `0700`) for post-scan inspection.
- `checkmate_scan` output gains `acquisition` (`AcquisitionReport`) and `retainedCheckouts` (`map[string]string`). If all targets fail acquisition, `checkmate_scan` MUST return `isError: true` with the structured `acquisition.failures`.
- When `_meta.progressToken` is provided on a synchronous `checkmate_scan`, the server MUST emit coalesced `notifications/progress` frames (`progress`, `total`, `message`).
- New tool `checkmate_get_scan_status(scanId)` returns `{ scanId, status, filesScanned, totalFiles, currentFile, overview?, error? }`.

### R10 — `checkmate_list_findings` & Configurable `samplesPerGroup`

- `checkmate_get_worklist` gains `samplesPerGroup` (`int`, default `5`, max `50`).
- New tool `checkmate_list_findings(scanId, file?, ruleId?, secretChecksum?, triageStatus?, severity?, includeSuppressed?, limit?, offset?)` returns paginated individual findings in canonical order without the 5-sample worklist cap.

### R11 — Remote Checkout Context & Cleanup

- When a scan has retained checkouts, `WorklistLocation` and `checkmate_list_findings` items MUST include `localFile` (verified inside the checkout root).
- New tool `checkmate_get_finding_context(scanId, findingId, beforeLines?, afterLines?)` returns numbered source lines around the finding from local disk / retained checkout (falling back to stored `source_context`).
- New tool `checkmate_cleanup_checkout(scanId)` deletes the retained checkout directory for `scanId`, clears its reference in SQLite, and logs an `audit_log` event.

### R12 — Streamable HTTP SSE (`GET /v1/mcp`)

- `GET /v1/mcp` with `Accept: text/event-stream` and `Mcp-Session-Id` MUST stream server-initiated JSON-RPC notifications (including `notifications/progress`) over SSE until the client disconnects or `DELETE /v1/mcp` closes the session.
