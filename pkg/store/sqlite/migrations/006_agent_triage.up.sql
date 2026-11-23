-- Migration: 006_agent_triage
-- Direction: UP
--
-- Adds agent triage tracking columns to findings and a sanitised_summary JSON
-- column to scans so external AI agents (via MCP or REST) can record verdicts,
-- suppress false positives, detect context drift across rescans, and keep
-- post-triage scan metrics updated without overwriting deterministic fields.

ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'untriaged';
ALTER TABLE findings ADD COLUMN triage_source TEXT;
ALTER TABLE findings ADD COLUMN triaged_at TEXT;
ALTER TABLE findings ADD COLUMN context_hash TEXT;
ALTER TABLE findings ADD COLUMN end_line INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN end_column INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_findings_triage_status ON findings(scan_id, triage_status);

ALTER TABLE scans ADD COLUMN sanitised_summary TEXT NOT NULL DEFAULT '{}';
