# Spec Delta: API Contract (`api-contract`)

**Change:** 007-agent-mcp-triage

## New & Extended `/v1` Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/mcp` | Streamable HTTP MCP JSON-RPC 2.0 endpoint (single or batch request) |
| `DELETE` | `/v1/mcp` | Terminate an HTTP MCP session (`204 No Content`) |
| `PUT` | `/v1/findings/{findingId}/triage` | Record or update an external/agent triage verdict for a finding (`scanId` required in body) |
| `POST` | `/v1/scans/{scanId}/triage/batch` | Submit a batch of external/agent triage verdicts for a scan |
| `GET` | `/v1/scans/{scanId}/sanitised` | Retrieve the scan's sanitised summary and active (non-suppressed) findings |
| `GET` | `/v1/scans/{scanId}/report` | Extended with optional `?view=sanitised` (default `raw` for backward compatibility; `sanitised` omits suppressed findings or emits SARIF `suppressions[]` when `&includeSuppressed=true`) |

All endpoints sit under `/v1` behind `AuthMiddleware`.
