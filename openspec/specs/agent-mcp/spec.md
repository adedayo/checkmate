# Spec: Agent MCP Server (`agent-mcp`)

**Change:** 007-agent-mcp-triage
**Status:** Accepted

## Overview

CheckMate exposes a Model Context Protocol (MCP) server enabling AI coding agents and automated LLM tools to run secret scans, retrieve clustered worklists pointing directly to flagged code coordinates, preview and apply false-positive suppressions, record triage verdicts, and export sanitised reports.

## Transports

### R1 — Local Stdio Transport (`checkmate mcp serve`)

- Command: `checkmate mcp serve [--data-path ~/.checkmate | --ephemeral]`.
- Uses newline-delimited JSON-RPC 2.0 over `stdin`/`stdout`.
- `stdout` MUST contain ONLY valid JSON-RPC 2.0 frames. All diagnostic logs and config notices MUST go to `stderr`.
- When `--ephemeral` is set, uses a temporary SQLite database cleaned up on exit (suitable for stateless CI/PR runs). Otherwise shares CheckMate's persistent SQLite store so results are immediately visible to `checkmate-app` and the REST API.

### R2 — Remote Streamable HTTP Transport (`/v1/mcp`)

- Mounted on the `/v1` router behind `AuthMiddleware`.
- `POST /v1/mcp` accepts a single JSON-RPC 2.0 request (or batch) and returns `application/json` (or `202 Accepted` for notifications).
- `DELETE /v1/mcp` cleanly acknowledges session termination (`204 No Content`).

## Protocol Capabilities

- Negotiates MCP protocol versions `2025-03-26` and `2024-11-05`.
- Declares capabilities: `tools`, `resources`, `prompts`.
- Handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, and `prompts/get`.

## Tools

### R3 — `checkmate_scan`

Runs a deterministic secret scan and returns a compact overview (never a raw finding dump).

- **Inputs:** `targets` (`string[]`, optional if `projectId` provided), `projectId` (`string`, optional), `gitDiffBase` (`string`, optional — restricts scan to files changed relative to the git ref), `excludeTests` (`bool`), `exclusionFile` (`string`).
- **Output:** `scanId`, `projectId`, `filesScanned`, `rawFindings`, `alreadySuppressed`, `carriedForwardTriaged`, `untriagedFindings`, and cluster counts (`uniqueChecksums`, `uniqueFiles`, `uniqueDirectories`, `byRule`).

### R4 — `checkmate_get_worklist`

Returns clustered pointers telling the agent where to look.

- **Inputs:** `scanId` (required), `groupBy` (`"checksum"` | `"directory"` | `"file"` | `"rule"`, default `"checksum"`), `onlyUntriaged` (`bool`, default `true`), `includeSuppressed` (`bool`, default `false`), `severity` (`string`, optional), `limit` (`int`, default 25, max 100), `offset` (`int`, default 0).
- **Output:** Deterministic ordered list of groups containing `groupKey`, `ruleId`, `secretType`, `highestSeverity`, `occurrenceCount`, `distinctFiles`, and sample locations (`findingId`, `file`, `line`, `column`, `endLine`, `endColumn`, `secretChecksum`).

### R5 — `checkmate_preview_suppression`

Dry-runs an exception rule against an existing scan without mutating state.

- **Inputs:** `scanId` (required), `ruleId` (`string`, default `"*"`), `scope` (`ExceptionScopeDetail`, required).
- **Output:** `matchedCount`, `untriagedMatchedCount`, `alreadySuppressedCount`, `wouldSuppressTruePositives`, `conflictingFindingIds`, `matchedByRule`, and `sampleMatchedLocations`.

### R6 — `checkmate_triage_batch`

Records agent triage verdicts for one or more findings and updates the scan result.

- **Inputs:** `scanId` (required), `triagedBy` (`string`, optional default `"agent:mcp"`), `decisions` (array of `{ findingId, applyToSameChecksum, verdict, reason, justification, remediationHint, contextClues, fpLikelihood, persistException, exceptionScope, stringMatch }`).
- **Behaviour:**
  - `verdict` MUST be one of `true_positive`, `false_positive`, `needs_review`.
  - Updates findings atomically without modifying deterministic `severity` or `confidence`.
  - Marks `false_positive` findings `suppressed = 1`; when `persistException` is true, creates an active scoped exception (`globalHash`, `pathHash`, or `pathString`) and links `exception_id`.
  - Appends an `audit_log` entry per decision and recomputes `scans.sanitised_summary`.
- **Output:** Count of updated findings, created exception IDs, and the updated `sanitisedSummary`.

### R7 — `checkmate_apply_suppression_rule`

Persists a pattern-level suppression rule and retroactively reconciles the scan.

- **Inputs:** `scanId` (required), `ruleId` (`string`, default `"*"`), `scope` (`ExceptionScopeDetail`, required), `reason` (`string`, required), `justification` (`string`, required), `triagedBy` (`string`), `force` (`bool`, default `false`).
- **Guardrails:**
  - MUST reject overly broad wildcard regexes (`.*`, `.+`, `^.*$`, `^.+$`, empty).
  - MUST refuse to suppress findings already marked `true_positive` unless `force: true`.
  - Reconciles matching findings in `scanId`, logs an audit event, and recomputes `scans.sanitised_summary`.

### R8 — `checkmate_export_sanitised`

Exports the triaged and sanitised scan result.

- **Inputs:** `scanId` (required), `format` (`"json"` | `"sarif"` | `"csv"` | `"pdf"` | `"checkmate_yaml"`, default `"json"`), `includeSuppressed` (`bool`, default `false`), `outputPath` (`string`, optional).
- **Output:** `sanitisedSummary`, `format`, `findingCount`, and either `content` (text formats) or `outputPath` (when written to disk / PDF).

## Resources & Prompts

- **Resources:**
  - `checkmate://scans/{scanId}/summary` — JSON raw vs. sanitised summary.
  - `checkmate://scans/{scanId}/worklist` — JSON default untriaged checksum-grouped worklist.
  - `checkmate://scans/{scanId}/sanitised` — JSON sanitised active findings.
  - `checkmate://projects/{projectId}/exceptions` — JSON active exceptions for the project.
- **Prompts:**
  - `triage_scan(scanId, target)` — Coarse-to-fine FP triage workflow (directory → checksum → singletons → preview → apply → export).
  - `audit_changes(target, baseRef)` — Git-diff focused secret audit workflow for PRs and local changes.

## Hardening, Async Scans, Remote Checkout Triage & SSE

Merged from change 009-mcp-hardening-and-remote-triage.

### R9 — Async Scan, Live Progress & `checkmate_get_scan_status`

- `checkmate_scan` supports `async` (`bool`, default `false`) and `keepCheckout` (`bool`, default `false`).
- `checkmate_scan` returns `acquisition` (`AcquisitionReport`), `retainedCheckouts`, and `localCheckoutPath`. When all targets fail acquisition, `checkmate_scan` returns `isError: true` with the structured failure overview.
- When `_meta.progressToken` is supplied on a synchronous `checkmate_scan`, the server emits coalesced `notifications/progress` JSON-RPC notifications over stdio or the session's HTTP SSE stream.
- `checkmate_get_scan_status(scanId)` returns live progress (`filesScanned`, `totalFiles`, `currentFile`, `status`) and final `overview` or `error`.

### R10 — `checkmate_list_findings` & Configurable `samplesPerGroup`

- `checkmate_get_worklist` accepts `samplesPerGroup` (`int`, default `5`, max `50`).
- `checkmate_list_findings(scanId, file?, ruleId?, secretChecksum?, triageStatus?, severity?, includeSuppressed?, limit?, offset?)` returns canonically ordered paginated findings without the 5-sample worklist cap.

### R11 — Remote Checkout Context & Cleanup

- Worklist and finding-list locations include `localFile` (verified inside the retained checkout directory) when a scan retains remote checkouts.
- `checkmate_get_finding_context(scanId, findingId, beforeLines?, afterLines?)` returns numbered source lines around the finding from local disk or a retained checkout (falling back to stored `source_context`).
- `checkmate_cleanup_checkout(scanId)` deletes retained checkout files, clears `retainedCheckouts` in SQLite, and logs an `audit_log` entry. Retained checkouts are also cleaned up automatically on `--ephemeral` exit and after `CHECKMATE_CHECKOUT_TTL` (default 24h).

### R12 — Streamable HTTP SSE (`GET /v1/mcp`)

- `GET /v1/mcp` with `Accept: text/event-stream` and `Mcp-Session-Id` streams server-initiated JSON-RPC notifications (including `notifications/progress`) over SSE until client disconnect or `DELETE /v1/mcp`.

