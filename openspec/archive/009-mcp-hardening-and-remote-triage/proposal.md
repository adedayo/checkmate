# OpenSpec Proposal: 009-mcp-hardening-and-remote-triage

**Status:** Implemented
**Capabilities:** `agent-mcp`, `api-contract`
**Depends On:** `008-git-checkout-auth-and-reliability` (for `KeepCheckouts` and `AcquisitionReport`)
**Type:** Enhancement

## Goal

Eliminate the operational caveats discovered in the initial `007-agent-mcp-triage` release so CheckMate's MCP server scales smoothly to **large monorepos**, **remote Git URL scans**, **high-density single-file findings**, and **streaming Streamable HTTP clients**.

## Motivation

Live verification of `checkmate mcp serve` (v1.6.0) confirmed the core triage loop works end-to-end on local repositories, while surfacing four concrete caveats:

1. **Synchronous scans risk client timeouts on large repositories.** `checkmate_scan` currently blocks until `RunScan` completes and emits no MCP `notifications/progress` frames. Scanning a 50,000-file repository can exceed an MCP client's per-tool timeout (often 60–120s).
2. **Worklist groups cap `sampleLocations` at 5.** `checkmate_get_worklist` returns at most 5 sample locations per group. While ideal for `groupBy: "checksum"` or `groupBy: "directory"`, a file with 15 distinct findings forces multiple round-trips or lacks a direct paginated finding list tool (`checkmate_list_findings`).
3. **Remote Git URL scans delete the checkout before the agent can inspect code.** When an agent runs `checkmate_scan(targets=["https://github.com/org/repo"])`, CheckMate clones the repository, scans it, deletes the temporary checkout, and rewrites locations to `https://github.com/org/repo/path/file.go`. The agent has no local file to open unless it independently clones the repo or fetches files over the network.
4. **Streamable HTTP `GET /v1/mcp` returns `405 Method Not Allowed`.** Clients that open the optional MCP Streamable HTTP SSE stream (`GET /v1/mcp` with `Accept: text/event-stream`) cannot receive server-initiated progress notifications or scan-completion updates.
5. **Silent clone failures.** Without `008-git-checkout-auth-and-reliability` wired into `ScanOverview`, a failed remote clone returns `rawFindings: 0` with no warning to the agent.

## Scope

1. **Async Scans & Live MCP Progress (`notifications/progress`):**
   - Add `async: bool` parameter on `checkmate_scan` (returns immediately with `{ scanId, status: "running" }`) and a new `checkmate_get_scan_status` tool returning live progress (`filesScanned`, `currentFile`, `status`, and final `ScanOverview` once complete).
   - When the MCP client includes `_meta.progressToken` on a synchronous `checkmate_scan` call, emit coalesced MCP `notifications/progress` JSON-RPC notifications over stdio or SSE using CheckMate's existing `CHECKMATE_PROGRESS_INTERVAL` progress monitor.
2. **Unbounded Finding Access (`checkmate_list_findings` + `samplesPerGroup`):**
   - Add `checkmate_list_findings(scanId, file, ruleId, secretChecksum, triageStatus, includeSuppressed, limit, offset)` for direct paginated access to individual findings.
   - Add optional `samplesPerGroup` (default `5`, max `50`) to `checkmate_get_worklist`.
3. **Remote Git URL Triage (`keepCheckout`, `checkmate_get_finding_context`, `checkmate_cleanup_checkout`):**
   - Add `keepCheckout: bool` (default `false`; auto-enabled when caller sets `keepCheckout: true` on a remote Git URL) on `checkmate_scan`, backed by `008`'s `SecretSearchOptions.KeepCheckouts` (`0700` directory under `<data-path>/code/<projectID>/`).
   - Return `localCheckoutPath` in `ScanOverview` and `localFile` alongside `file` in worklist/finding locations whenever a retained checkout exists so local agents can read the file directly.
   - Add `checkmate_get_finding_context(scanId, findingId, beforeLines, afterLines)` so even **remote HTTP MCP agents** (without local filesystem access) can inspect surrounding code lines directly from the retained checkout or stored `source_context`.
   - Add `checkmate_cleanup_checkout(scanId)` (plus automatic cleanup on `--ephemeral` server exit) so retained checkouts containing plaintext secrets do not linger on disk after triage completes.
4. **Streamable HTTP SSE (`GET /v1/mcp`):**
   - Track active MCP HTTP sessions (`Mcp-Session-Id`) with an SSE subscription channel on `GET /v1/mcp` (`Accept: text/event-stream`), pushing `notifications/progress` and scan lifecycle notifications to connected HTTP MCP clients, and cleaning up on `DELETE /v1/mcp` or idle timeout.
5. **Surface Acquisition Failures in `ScanOverview`:**
   - Include `acquisition` (`attempted`, `succeeded`, `failed`, `failures[]`) from `008` in `checkmate_scan` output; return `isError: true` with structured failure details when all targets fail to acquire.

## Non-Goals

- **Desktop App (`checkmate-app`) frontend UI for `sanitised_summary`.** Tracked separately under `checkmate-app` modernisation (`002-app-modernisation`).
- **Replacing the sanctioned-LLM workflow.** Local agents continue to read local workspace files directly; `checkmate_get_finding_context` is an optional convenience for remote URL / remote HTTP MCP workflows.

## Decisions

| # | Decision |
|---|---|
| 1 | Support both `_meta.progressToken` streaming on synchronous `checkmate_scan` AND explicit `async: true` + `checkmate_get_scan_status` so both progress-capable and short-timeout MCP clients work reliably on large repos. |
| 2 | Keep `keepCheckout: false` as default for security (no lingering plaintext secrets on disk); when enabled, scope checkouts to `0700` per-scan directories and provide `checkmate_cleanup_checkout` plus TTL/exit cleanup. |
| 3 | Add `checkmate_list_findings` and `samplesPerGroup` rather than making `checkmate_get_worklist` unbounded, keeping default responses compact and token-efficient. |
| 4 | Implement session-scoped SSE on `GET /v1/mcp` using the same pure-Go stdlib stack (`net/http.Flusher`) with bounded per-session queues and idle eviction. |
