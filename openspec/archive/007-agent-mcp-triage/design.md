# Design: 007-agent-mcp-triage

**Status:** Accepted (Archived)

## Architecture Overview

```text
AI Coding Agent / CI Agent (Copilot, Claude Code, Cursor, custom)
   │  Native workspace tools (read file, grep, git) for contextual investigation
   │  MCP protocol (JSON-RPC 2.0) for CheckMate control & state mutation
   ├─────────────────────────────┬─────────────────────────────┐
   │ stdio (`checkmate mcp serve`)│ Streamable HTTP (`/v1/mcp`) │
   ▼                             ▼                             │
pkg/mcp (Protocol, Tools, Resources, Prompts)                  │
   │                                                           │ REST (`/v1/...`)
   ▼                                                           ▼
pkg/triage (Service: Scan, Worklist, Preview, Triage, Suppress, Export)
   │                             │                             │
   ▼                             ▼                             ▼
pkg/sdk & secrets-finder   pkg/store/sqlite              pkg/report / reports
(deterministic scanner)    (SQLite + migrations)         (JSON, SARIF, CSV, PDF, YAML)
```

## Key Seams

### 1. `pkg/triage` — Single Source of Truth for Agent Triage

All triage business logic lives in `pkg/triage.Service`, shared by `pkg/mcp` and `pkg/api`:

- **`Scan(ctx, ScanRequest) (*ScanOverview, error)`**:
  - Supports scanning local directories/files (`targets`) or an existing `projectId`.
  - Optional `gitDiffBase` resolves changed files via `git diff --name-only <base>` (plus untracked files when scanning working tree) so PR/pre-commit agents scan only modified files.
  - Persists the scan into SQLite via a dedicated ad-hoc or matched project so every scan gets a durable `scanId`, findings rows, exception matching, and audit trail.
  - Returns a compact `ScanOverview` (raw counts, already-suppressed counts, carried-forward triaged counts, untriaged counts, and cluster counts)—never a full finding dump.
- **`GetWorklist(ctx, WorklistRequest) (*WorklistResult, error)`**:
  - Queries findings for `scanId` and groups them by `checksum` (default), `directory`, `file`, or `rule`.
  - Sorts groups deterministically (highest occurrence count first, then severity, then canonical key) and paginates via opaque cursor / offset.
  - Returns exact file coordinates (`file`, `line`, `column`, `endLine`, `endColumn`, `ruleId`, `secretType`, `severity`, `secretChecksum`) so the agent can jump directly to the code.
- **`PreviewSuppression(ctx, PreviewSuppressionRequest) (*SuppressionPreview, error)`**:
  - Constructs a temporary `store.Exception` and runs it through `sqlite.MatchExceptionPreview` (sharing `newExceptionMatcher` in `pkg/store/sqlite/exception_matcher.go`).
  - Reports total matched findings, how many are untriaged vs. already suppressed vs. already marked `true_positive`, breakdown by rule, and sample matched locations.
  - Validates regexes and rejects overly broad wildcard scopes before anything is written.
- **`RecordTriageBatch(ctx, TriageBatchRequest) (*TriageBatchResult, error)`**:
  - Applies a list of per-finding decisions atomically.
  - When `applyToSameChecksum` is true, fans out the verdict across all findings in `scanId` sharing that `secret_checksum`.
  - For `false_positive` verdicts: sets `triage_status = 'false_positive'`, `suppressed = 1`, records `ai_annotation` with justification/reason/clues, and when `persistException` is true creates a scoped active exception (`globalHash`, `pathHash`, or `pathString`) linked via `exception_id`.
  - For `true_positive` verdicts: sets `triage_status = 'true_positive'`, `suppressed = 0` (clears any non-explicit suppression if previously untriaged), and stores `remediationHint` in `ai_annotation`.
  - For `needs_review` verdicts: sets `triage_status = 'needs_review'` without suppressing.
  - Writes `audit_log` entries and calls `RecomputeScanSummary(scanId)`.
- **`ApplySuppressionRule(ctx, ApplySuppressionRuleRequest) (*ApplySuppressionRuleResult, error)`**:
  - Validates the suppression rule against wildcard guardrails.
  - Refuses to suppress findings explicitly marked `true_positive` unless `force: true`.
  - Persists the exception in `exceptions` with `status = 'active'`, reconciles matching findings in `scanId` (`suppressed = 1`, `exception_id`, `triage_status = 'false_positive'` for untriaged matches), logs to `audit_log`, and calls `RecomputeScanSummary(scanId)`.
- **`ExportSanitised(ctx, ExportRequest) (*ExportResult, error)`**:
  - Supports `json`, `sarif`, `csv`, `pdf`, and `checkmate_yaml` (active exceptions exported as `.checkmate.yaml`).
  - Defaults to `includeSuppressed: false` for clean actionable output; for SARIF, can either omit false positives or emit them with SARIF 2.1.0 `suppressions[]` (`includeSuppressed: true`).
  - Optionally writes output directly to `outputPath` and always returns the before/after noise-reduction summary.

### 2. Wildcard & Safety Guardrails on Agent Suppressions

To prevent a miscalibrated agent from wiping out real findings with a catch-all regex:

1. **Rejected wildcard patterns:** Any regex whose trimmed pattern is `.*`, `.+`, `^.*$`, `^.+`, `.*$`, or empty string is rejected on `pathRegex`, `globalRegex`, and `pathRegexRegex`.
2. **Rule wildcard restriction:** `ruleId: "*"` is only allowed for hash-scoped (`globalHash`, `pathHash`) or narrow path-specific rules, never combined with a broad `globalRegex`.
3. **True-positive protection:** `ApplySuppressionRule` checks whether the rule matches any finding in `scanId` already marked `triage_status = 'true_positive'`; if so, it rejects the call with the conflicting finding IDs unless `force: true` is explicitly set.
4. **Auditability:** Every triage batch and suppression rule writes an `audit_log` entry recording `actor` (`triagedBy`), `action`, `resource_type`, `resource_id`, and JSON diff.

### 3. Scan Summary Re-computation & Drift-Aware Carry-Forward

In `pkg/store/sqlite/db.go`, `RunScan` writes `total_findings`, `findings_by_severity`, and `score` once from raw `allFindings`. Adding `sanitised_summary` on `scans` keeps those deterministic columns untouched while giving every consumer an always-up-to-date post-triage view:

```go
type SanitisedSummary struct {
    RawFindings              int            `json:"rawFindings"`
    ActiveFindings           int            `json:"activeFindings"`
    SuppressedFindings       int            `json:"suppressedFindings"`
    TriagedTruePositives     int            `json:"triagedTruePositives"`
    TriagedFalsePositives    int            `json:"triagedFalsePositives"`
    NeedsReview              int            `json:"needsReview"`
    Untriaged                int            `json:"untriaged"`
    ActiveFindingsBySeverity map[string]int `json:"activeFindingsBySeverity"`
    SanitisedScore           float64        `json:"sanitisedScore"`
    NoiseReductionPercent    float64        `json:"noiseReductionPercent"`
    LastTriagedAt            *time.Time     `json:"lastTriagedAt,omitempty"`
    LastTriagedBy            string         `json:"lastTriagedBy,omitempty"`
}
```

`RecomputeScanSummary(scanID)` computes this directly from SQL over `findings WHERE scan_id = ?` and persists it to `scans.sanitised_summary`. It is invoked at the end of `RunScan` (after `reconcileSuppressions`) and after every triage or suppression mutation.

For rescan carry-forward (`pkg/store/sqlite/finding_writer.go`):
- `context_hash` is computed as `sha256(normalised source_context)`.
- When inserting a finding in a new scan, previous `triage_status`, `triage_source`, `triaged_at`, and `ai_annotation` are carried forward **only if** the previous row has the same `finding_id` AND (`prev.context_hash == ""` or `prev.context_hash == current.context_hash`). If surrounding code changed, `triage_status` resets to `untriaged` so the agent re-evaluates it.

### 4. MCP Server Transport & Framing (`pkg/mcp`)

- Implements JSON-RPC 2.0 per MCP specification (`2025-03-26`, backward-compatible with `2024-11-05`):
  - `initialize`, `notifications/initialized`, `ping`
  - `tools/list`, `tools/call`
  - `resources/list`, `resources/templates/list`, `resources/read`
  - `prompts/list`, `prompts/get`
- **Stdio transport (`ServeStdio`):** reads newline-delimited JSON-RPC messages from `io.Reader` (`os.Stdin`) and writes single-line JSON responses to `io.Writer` (`os.Stdout`) under a write mutex.
- **Clean `stdout` invariant:** `cmd/root.go`'s `initConfig` prints `"Using config file: ..."` to `os.Stderr` (not `os.Stdout`) so neither `checkmate mcp serve` nor `checkmate lspServe` ever emits non-JSON-RPC bytes on `stdout`.
- **Streamable HTTP transport (`HTTPHandler`):** handles `POST /v1/mcp` (single or batch JSON-RPC requests returning `application/json`, notifications returning `202 Accepted`) and `DELETE /v1/mcp` (session close) behind `AuthMiddleware`.

### 5. SARIF 2.1.0 Suppressions (`pkg/report/sarif.go`)

Extend `SarifResult` with standard SARIF 2.1.0 optional fields:
- `Suppressions []SarifSuppression` (`kind: "external"`, `status: "accepted" | "underReview"`, `justification: string`)
- `Properties map[string]interface{}` (carrying `checkmateTriage` for triaged findings)
- `EndLine` / `EndColumn` on `SarifRegion` when present on `Range.End`.

Keep `GenerateSARIF(writer, diags)` backward-compatible and add `GenerateSARIFWithOptions(writer, findings, opts)` supporting `IncludeSuppressed bool`. Validate output against `pkg/report/testdata/sarif-schema-2.1.0.json` in tests.
