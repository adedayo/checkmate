# OpenSpec Proposal: 007-agent-mcp-triage

**Status:** Accepted (Archived)
**Capabilities:** `agent-mcp` (new), `ai-triage`, `data-store`, `sarif-export`, `api-contract`
**Type:** Feature

## Goal

Enable AI coding agents and LLM-powered tools (VS Code Copilot, Claude Code, Cursor, CI agents, and custom orchestrators) to drive CheckMate via the **Model Context Protocol (MCP)** and matching REST APIs, turning CheckMate's high-recall deterministic secret detection into a **triaged, false-positive-suppressed, sanitised scan result**.

CheckMate acts as the fast, deterministic sensor and suppression/reporting engine—telling the agent *where* to look and clustering duplicate noise—while the AI agent inspects the repository in full context using its native code-reading tools, rules out false positives, writes structured verdicts and suppression rules back into CheckMate, and exports sanitised reports.

## Motivation

CheckMate's detection engine (`pkg/plugin/secrets-finder`) combines regex rules, structural heuristics, and Shannon entropy. To avoid missing real leaks, it deliberately favours recall, which produces substantial false-positive noise in real repositories (test fixtures, example configs, SRI integrity digests, UUIDs, build hashes, public keys, documentation snippets).

CheckMate's existing BYOK AI triage (`pkg/ai/client.go`) calls a single-turn `/chat/completions` endpoint with only a narrow snippet of `source_context`. That single-turn design cannot inspect surrounding functions, callers, test harnesses, `.env.example`, or directory layout—the exact evidence required to separate real credentials from false positives with high confidence.

Conversely, modern AI coding agents already have direct access to the codebase under sanctioned enterprise agreements (ZDR/DPA) and excel at contextual code investigation, but lack a fast, deterministic, full-repo secret sensor and structured exception/reporting store. Exposing CheckMate over MCP connects the two:

1. CheckMate finds every candidate secret deterministically and groups findings by checksum, directory, file, and rule.
2. The AI agent navigates straight to those coordinates, evaluates each candidate in full codebase context, previews the blast radius of proposed suppression rules, and records structured verdicts (`true_positive`, `false_positive`, `needs_review`).
3. CheckMate updates the scan record, applies scoped suppressions (`globalHash`, `pathHash`, `pathString`, `pathRegex`, `pathRegexRegex`, etc.), recomputes the scan's sanitised summary and score, and exports clean JSON, SARIF 2.1.0, CSV, PDF, or `.checkmate.yaml` outputs.

## Scope

1. **Shared Triage & Sanitisation Service (`pkg/triage`):**
   - Scan execution (local paths, projects, and optional git-diff scoping) backed by `sqlite.DB`.
   - Clustered worklist generation (`groupBy`: `checksum`, `directory`, `file`, `rule`) so agents eliminate repeated false positives in bulk.
   - Dry-run suppression preview (`PreviewSuppression`) using CheckMate's exact `exceptionMatcher` semantics to report blast radius before committing rules.
   - Atomic batch triage write-back (`RecordTriageBatch`) supporting `applyToSameChecksum`, structured reason taxonomy, and optional exception persistence.
   - Pattern-level suppression application (`ApplySuppressionRule`) with wildcard guardrails and retroactive scan reconciliation.
   - Sanitised report export (`json`, `sarif`, `csv`, `pdf`, `checkmate_yaml`).
2. **Persistence & Scan Re-summarisation (`pkg/store/sqlite`):**
   - Migration `006_agent_triage`: `triage_status`, `triage_source`, `triaged_at`, `context_hash` on `findings`; `sanitised_summary` on `scans`.
   - `RecomputeScanSummary(scanID)` so suppressing or triaging findings updates the scan's active/sanitised counts and score immediately while keeping deterministic raw totals intact.
   - Drift-aware carry-forward of triage verdicts across rescans when `finding_id` and `context_hash` match.
3. **MCP Server (`pkg/mcp`) & CLI (`cmd/mcpServe.go`):**
   - Transport-agnostic MCP JSON-RPC 2.0 server exposing 6 tools, read-only resources, and built-in triage workflow prompts (`triage_scan`, `audit_changes`).
   - `checkmate mcp serve` over `stdio` (persistent SQLite DB or `--ephemeral` mode) with clean `stdout` framing.
   - Streamable HTTP MCP mounted at `/v1/mcp` behind `AuthMiddleware`.
4. **REST Write-Back & Sanitised SARIF (`pkg/api`, `pkg/report`):**
   - `PUT /v1/findings/{findingId}/triage` and `POST /v1/scans/{scanId}/triage/batch` for external agent write-back.
   - `GET /v1/scans/{scanId}/sanitised` and `GET /v1/scans/{scanId}/report?view=sanitised`.
   - SARIF 2.1.0 `suppressions[]` and `properties.checkmateTriage` support in `pkg/report/sarif.go`.

## Non-Goals

- **No changes to deterministic detection rules.** Detection coverage and determinism (Guardrails 5 and 6) are untouched.
- **No replacement of existing BYOK AI triage.** `POST /v1/findings/{findingId}/triage` continues to work for standalone Ollama/OpenAI deployments.
- **No custom code-browsing proxy inside MCP.** Under the sanctioned-LLM assumption, the agent uses its native file, grep, and git tools to inspect the coordinates CheckMate provides.
- **No desktop UI frontend changes in this change.** Because `checkmate-app` shares the same SQLite database, updated suppressions, annotations, and metrics persist cleanly for subsequent UI work.

## Guardrail Interactions

- **Guardrail 1 (AI output never overwrites deterministic fields):** `Finding.Severity`, `Finding.Confidence`, and `scans.total_findings` / `scans.findings_by_severity` / `scans.score` remain strictly deterministic. Agent verdicts live in `triage_status`, `triage_source`, `ai_annotation`, `suppressed`/`exception_id`, and `scans.sanitised_summary`.
- **Guardrail 3 (No plaintext secrets stored):** Neither MCP responses nor triage records persist raw secret values in SQLite—only `secret_checksum`, location coordinates, and redacted/existing context.
- **Guardrail 4 (Stable finding identity):** Triage carry-forward and `applyToSameChecksum` build directly on `finding_id` and `secret_checksum`.
- **Guardrail 6 (Determinism):** Worklist clusters and exported reports are sorted canonically so agent runs see stable ordering regardless of parallel scan arrival order.

## Decisions

| # | Decision |
|---|---|
| 1 | Sanctioned LLM assumption (ZDR/DPA): the agent reads workspace files natively; CheckMate provides exact coordinates, clustering, preview, suppression, and sanitisation rather than acting as a file-read proxy. |
| 2 | Primary goal is aggressive, auditable false-positive suppression with safety guardrails (dry-run preview, wildcard rejection, refusal to silently suppress already-confirmed true positives). |
| 3 | Dual transport: `checkmate mcp serve` (stdio) for local coding agents/CI and `/v1/mcp` (Streamable HTTP) on the API server, sharing one `pkg/mcp` core. |
| 4 | Zero new third-party dependencies for MCP protocol framing (pure Go JSON-RPC 2.0 over stdlib `bufio` + `net/http`) to preserve CGO-free, minimal supply-chain footprint. |
| 5 | Keep deterministic raw scan columns untouched; store post-triage active counts and sanitised score in `scans.sanitised_summary`. |
