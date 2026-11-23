# Tasks: 009-mcp-hardening-and-remote-triage

**Status:** Implemented

## Phase 1 — Async Scans & Live Progress

- [x] Add active-scan progress registry in `pkg/triage.Service` (`StartScanAsync`, `GetScanStatus`).
- [x] Plumb `progressCallback` through `triage.Service.Scan` to `sqlite.DB.RunScan`.
- [x] Extract `_meta.progressToken` in `pkg/mcp/protocol.go` and emit `notifications/progress` frames on both `ServeStdio` and HTTP SSE sessions.
- [x] Add `async` parameter to `checkmate_scan` and add `checkmate_get_scan_status` MCP tool.
- [x] Tests: verify `notifications/progress` frames arrive over stdio pipe during scan; verify `async: true` + polling `checkmate_get_scan_status` reaches `complete`.

## Phase 2 — Unbounded Finding Listing & Worklist Flexibility

- [x] Add `ListFindings(ctx, ListFindingsRequest)` to `pkg/triage.Service` with filtering (`file`, `ruleId`, `secretChecksum`, `triageStatus`, `severity`, `includeSuppressed`) and deterministic pagination.
- [x] Expose `checkmate_list_findings` tool in `pkg/mcp/server.go`.
- [x] Add `samplesPerGroup` (default `5`, max `50`) to `WorklistRequest` and `checkmate_get_worklist`.
- [x] Tests: file with 12 distinct findings is fully paginated via `checkmate_list_findings` and widened via `samplesPerGroup: 15`.

## Phase 3 — Remote Git URL Triage & Checkout Cleanup

- [x] Wire `keepCheckout: bool` on `ScanRequest` / `checkmate_scan` to `008`'s `SecretSearchOptions.KeepCheckouts` with `0700` per-scan `CloneBaseDir`.
- [x] Persist `retainedCheckouts` in `scans.additional_info` and include `acquisition` (`AcquisitionReport`) in `ScanOverview` (returning `isError: true` on total acquisition failure).
- [x] Populate `localFile` on `WorklistLocation` when a retained checkout maps to the finding's URL (with path-traversal guard).
- [x] Implement `GetFindingContext` (also filling `sqlite.DB.GetCodeContext`) and expose `checkmate_get_finding_context` MCP tool.
- [x] Implement `CleanupCheckout` and expose `checkmate_cleanup_checkout` MCP tool + automatic cleanup on ephemeral exit and TTL expiry.
- [x] Tests: remote git URL scan with `keepCheckout: true` exposes readable `localFile`, serves context via `checkmate_get_finding_context`, and removes disk files on `checkmate_cleanup_checkout`.

## Phase 4 — Streamable HTTP SSE (`GET /v1/mcp`)

- [x] Implement session manager in `pkg/mcp/sessions.go` with bounded notification queue and idle session eviction.
- [x] Add `GET /v1/mcp` (`Accept: text/event-stream`) handler in `pkg/mcp/server.go` and register `http.MethodGet` on `/v1/mcp` in `pkg/api/api.go`.
- [x] Update `openspec/specs/api-contract/openapi.yaml` with `GET /v1/mcp` and `GET /v1/findings/{findingId}/context`.
- [x] Tests: `httptest` client opens SSE stream on `GET /v1/mcp`, triggers `POST /v1/mcp` scan with `_meta.progressToken`, receives SSE progress events, and closes via `DELETE /v1/mcp`.
