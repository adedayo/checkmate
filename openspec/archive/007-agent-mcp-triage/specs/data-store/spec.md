# Spec Delta: Data Store (`data-store`)

**Change:** 007-agent-mcp-triage

## Migration `006_agent_triage`

### `findings` Table Additions

```sql
ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'untriaged';
ALTER TABLE findings ADD COLUMN triage_source TEXT;
ALTER TABLE findings ADD COLUMN triaged_at TEXT;
ALTER TABLE findings ADD COLUMN context_hash TEXT;
ALTER TABLE findings ADD COLUMN end_line INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN end_column INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_findings_triage_status ON findings(scan_id, triage_status);
```

- `triage_status` values: `untriaged`, `true_positive`, `false_positive`, `needs_review`.
- `triage_source` identifies the actor (e.g. `agent:copilot/claude-sonnet`, `byok:ollama/llama3`, `human:dayo`).
- `context_hash` stores the SHA-256 hex digest of normalised `source_context` for drift detection.

### `scans` Table Additions

```sql
ALTER TABLE scans ADD COLUMN sanitised_summary TEXT NOT NULL DEFAULT '{}';
```

Stores JSON-serialised `store.SanitisedSummary` computed over the scan's findings after suppression reconciliation and triage updates. Deterministic raw columns (`total_findings`, `findings_by_severity`, `score`) remain unchanged.

## Behavioural Requirements

1. **Drift-aware carry-forward:** During `persistFindingBatch`, prior `triage_status`, `triage_source`, `triaged_at`, and `ai_annotation` for the same `(project_id, finding_id)` MUST be carried forward if and only if the prior `context_hash` is empty or matches the new finding's `context_hash`. When `context_hash` differs, `triage_status` resets to `untriaged`.
2. **Summary recomputation:** `RecomputeScanSummary(scanID)` MUST recompute `sanitised_summary` from the `findings` table, counting active (non-suppressed) findings, suppressed findings, each `triage_status`, active severity distribution, `sanitisedScore`, and `noiseReductionPercent`.
3. **Store-side exception preview & reconciliation:** `PreviewExceptionOnScan` and `ApplyExceptionToScan` MUST reuse `newExceptionMatcher` so preview, mid-scan reconciliation, and future scans agree identically on matched findings.
