# Tasks: 007-agent-mcp-triage

**Status:** Complete (Archived)

## Phase 1 — Schema & SQLite Store

- [x] Add migration `006_agent_triage.up.sql` and `006_agent_triage.down.sql`:
  - `findings`: `triage_status`, `triage_source`, `triaged_at`, `context_hash` + index `idx_findings_triage_status`
  - `scans`: `sanitised_summary`
- [x] Extend `pkg/sdk/types.go` (`TriageStatus`, `AIAnnotation` triage fields) and `pkg/store/store.go` (`SanitisedSummary`, `StoredFinding`, `TriageUpdate`, `PlatformStore` methods).
- [x] Implement store methods in `pkg/store/sqlite/`:
  - `GetScanFindings(scanID string)` (full `StoredFinding` rows with triage & suppression metadata)
  - `GetScanProjectID(scanID string)`
  - `UpdateFindingTriage(scanID, findingID string, update store.TriageUpdate)`
  - `RecomputeScanSummary(scanID string) (*store.SanitisedSummary, error)`
  - `GetSanitisedSummary(scanID string) (*store.SanitisedSummary, error)`
  - `PreviewExceptionOnScan(scanID string, exc *store.Exception)`
  - `ApplyExceptionToScan(ctx, scanID string, exc *store.Exception, triagedBy string, force bool)`
  - `RecordAuditEvent(event *store.AuditEvent, resourceType, resourceID string)`
- [x] Update `finding_writer.go` for drift-aware `context_hash` carry-forward of triage verdicts on rescan, and call `RecomputeScanSummary` at the end of `RunScan`.
- [x] Unit tests for migration, carry-forward with/without context drift, `RecomputeScanSummary`, and exception preview/apply.

## Phase 2 — Triage & Sanitisation Service (`pkg/triage`)

- [x] Implement `pkg/triage.Service`:
  - `Scan` (local paths, project IDs, optional `gitDiffBase` changed-file filtering)
  - `GetWorklist` (grouping by `checksum`, `directory`, `file`, `rule` with deterministic ordering and pagination)
  - `PreviewSuppression` (wildcard validation + blast-radius preview)
  - `RecordTriageBatch` (atomic updates, `applyToSameChecksum`, optional persisted exception, audit log, summary recomputation)
  - `ApplySuppressionRule` (wildcard guardrails, true-positive protection, retroactive scan reconciliation)
  - `ExportSanitised` (`json`, `sarif`, `csv`, `pdf`, `checkmate_yaml`)
- [x] Unit tests covering clustering, blast-radius preview, wildcard rejection, true-positive protection, and end-to-end FP suppression.

## Phase 3 — SARIF 2.1.0 Suppressions & Sanitised Reports

- [x] Extend `pkg/report/sarif.go` with `SarifSuppression`, `Properties`, `EndLine`/`EndColumn`, and `GenerateSARIFWithOptions`.
- [x] Validate suppressed and triaged SARIF output against `pkg/report/testdata/sarif-schema-2.1.0.json`.

## Phase 4 — MCP Server & CLI (`pkg/mcp`, `cmd/mcpServe.go`)

- [x] Implement transport-agnostic MCP JSON-RPC 2.0 server in `pkg/mcp`:
  - Protocol handshake (`initialize`, `notifications/initialized`, `ping`)
  - 6 tools (`checkmate_scan`, `checkmate_get_worklist`, `checkmate_preview_suppression`, `checkmate_triage_batch`, `checkmate_apply_suppression_rule`, `checkmate_export_sanitised`)
  - Resources (`checkmate://scans/{scanId}/summary`, `checkmate://scans/{scanId}/worklist`, `checkmate://scans/{scanId}/sanitised`, `checkmate://projects/{projectId}/exceptions`)
  - Prompts (`triage_scan`, `audit_changes`)
  - `ServeStdio` and `HTTPHandler`
- [x] Add `cmd/mcpServe.go` (`checkmate mcp serve [--data-path | --ephemeral]`) and fix `cmd/root.go` config notice to write to `os.Stderr`.
- [x] Integration tests driving `pkg/mcp` over both in-memory stdio pipes and `httptest` HTTP against a real fixture repo with true secrets and false positives.

## Phase 5 — REST API & OpenAPI Contract

- [x] Mount `/v1/mcp` on the `/v1` subrouter in `pkg/api/api.go`.
- [x] Add `PUT /v1/findings/{findingId}/triage`, `POST /v1/scans/{scanId}/triage/batch`, `GET /v1/scans/{scanId}/sanitised`, and `?view=sanitised` on `GET /v1/scans/{scanId}/report`.
- [x] Update `openspec/specs/api-contract/openapi.yaml` and `openspec/project.md`.
- [x] Add API integration tests for `/v1/mcp` and the new triage/sanitised endpoints.
