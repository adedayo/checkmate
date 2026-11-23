-- Migration: 006_agent_triage
-- Direction: DOWN

DROP INDEX IF EXISTS idx_findings_triage_status;
ALTER TABLE findings DROP COLUMN end_column;
ALTER TABLE findings DROP COLUMN end_line;
ALTER TABLE findings DROP COLUMN context_hash;
ALTER TABLE findings DROP COLUMN triaged_at;
ALTER TABLE findings DROP COLUMN triage_source;
ALTER TABLE findings DROP COLUMN triage_status;

ALTER TABLE scans DROP COLUMN sanitised_summary;
