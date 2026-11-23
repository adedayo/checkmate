# Spec Delta: API Contract (`api-contract`)

**Change:** 009-mcp-hardening-and-remote-triage

## New & Extended `/v1` Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/mcp` | Streamable HTTP MCP SSE notification stream (`Accept: text/event-stream`, requires `Mcp-Session-Id`) |
| `GET` | `/v1/findings/{findingId}/context` | Return surrounding source code context lines for a finding (`?scanId=...&before=20&after=20`) |
| `DELETE` | `/v1/scans/{scanId}/checkout` | Delete any retained remote Git checkout associated with `scanId` |
