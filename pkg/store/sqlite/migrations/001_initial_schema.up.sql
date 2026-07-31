-- Migration: 001_initial_schema
-- Direction: UP
--
-- Creates the initial CheckMate schema.
-- All JSON columns store marshalled Go structs for complex nested types.
-- The schema is intentionally denormalised in places (e.g. findings stores
-- project_id directly) to avoid expensive joins on hot read paths.



-- ─── Projects ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    workspace    TEXT NOT NULL DEFAULT 'default',
    name         TEXT NOT NULL,
    -- Full project struct (repositories, scan policy, etc.) serialised as JSON
    data         TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace);

-- ─── Scans ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    id             TEXT PRIMARY KEY,
    project_id     TEXT REFERENCES projects(id) ON DELETE CASCADE,
    -- queued | running | complete | failed | cancelled
    status         TEXT NOT NULL DEFAULT 'queued',
    targets        TEXT NOT NULL DEFAULT '[]',  -- JSON array of paths/URLs
    started_at     TEXT,
    completed_at   TEXT,
    duration_ms    INTEGER,
    file_count     INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    -- JSON object: { "CRITICAL": 0, "HIGH": 3, ... }
    findings_by_severity TEXT NOT NULL DEFAULT '{}',
    score          REAL,
    -- Arbitrary additional metadata (show_source flag, etc.)
    additional_info TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_project    ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

-- ─── Findings ────────────────────────────────────────────────────────────────
--
-- finding_id is the stable deterministic identity:
--   sha256(rule_id + repo_url + file_path + line_number + column_number + secret_checksum)
-- Same physical finding in different scans always has the same finding_id.

CREATE TABLE IF NOT EXISTS findings (
    finding_id           TEXT NOT NULL,
    scan_id              TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id           TEXT REFERENCES projects(id) ON DELETE CASCADE,
    rule_id              TEXT NOT NULL,
    -- Structured type: e.g. "aws.access_key", "generic.high_entropy"
    secret_type          TEXT NOT NULL DEFAULT 'generic.high_entropy',
    severity             TEXT NOT NULL,  -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence           TEXT NOT NULL,  -- CONFIRMED|HIGH|MEDIUM|LOW
    repo_url             TEXT,
    commit_sha           TEXT,
    branch               TEXT,
    file_path            TEXT NOT NULL,
    line_number          INTEGER NOT NULL,
    column_number        INTEGER NOT NULL,
    -- Redacted value: first 4 + last 4 chars only. Never raw value.
    evidence_redacted    TEXT,
    secret_checksum      TEXT NOT NULL,
    -- Source context with secret replaced by ████
    source_context       TEXT,
    suppressed           INTEGER NOT NULL DEFAULT 0,
    exception_id         TEXT,
    verification_status  TEXT NOT NULL DEFAULT 'NOT_CHECKED',
    verified_at          TEXT,
    -- JSON-serialised AIAnnotation or NULL
    ai_annotation        TEXT,
    detected_at          TEXT NOT NULL,
    -- Composite PK: one row per (finding, scan). Same finding can appear
    -- in multiple scans but we track each occurrence.
    PRIMARY KEY (finding_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan        ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_project     ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_secret_type ON findings(secret_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_suppressed  ON findings(suppressed);
CREATE INDEX IF NOT EXISTS idx_findings_checksum    ON findings(secret_checksum);

-- ─── Exceptions ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS exceptions (
    id             TEXT PRIMARY KEY,
    -- Rule ID this exception applies to, or "*" for all rules at this scope
    rule_id        TEXT NOT NULL,
    -- value|line|file|directory|project|global
    scope_type     TEXT NOT NULL,
    -- JSON: { "repoUrl": "...", "path": "...", "lineStart": N, ... }
    scope_json     TEXT NOT NULL DEFAULT '{}',
    -- Structured reason enum
    reason         TEXT NOT NULL,
    justification  TEXT,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    -- NULL = permanent (never expires)
    expires_at     TEXT,
    -- active|expired|revoked
    status         TEXT NOT NULL DEFAULT 'active',
    -- JSON: { "fileHash": "sha256:...", "commitSha": "..." }
    evidence_json  TEXT NOT NULL DEFAULT '{}',
    -- JSON array of strings
    tags           TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_exceptions_status     ON exceptions(status);
CREATE INDEX IF NOT EXISTS idx_exceptions_expires    ON exceptions(expires_at);
CREATE INDEX IF NOT EXISTS idx_exceptions_scope_type ON exceptions(scope_type);
CREATE INDEX IF NOT EXISTS idx_exceptions_rule_id    ON exceptions(rule_id);

-- ─── Audit Log ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,  -- e.g. scan.triggered, exception.created, exception.revoked
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    -- JSON diff or additional context
    diff          TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_time     ON audit_log(created_at DESC);

-- ─── API Keys ─────────────────────────────────────────────────────────────────
--
-- Plaintext key is NEVER stored. Only the bcrypt hash and a display prefix.

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    -- bcrypt hash of the full key
    key_hash     TEXT NOT NULL,
    -- First 8 chars for identification in the UI ("cm_a1b2c3d4...")
    key_prefix   TEXT NOT NULL,
    -- JSON array of scope strings
    scopes       TEXT NOT NULL DEFAULT '[]',
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    last_used_at TEXT,
    -- JSON array of CIDR strings, or NULL for no restriction
    ip_allowlist TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- ─── Git Config ───────────────────────────────────────────────────────────────
--
-- Stores the serialised GitServiceConfig. Single row — upserted on save.

CREATE TABLE IF NOT EXISTS git_config (
    id   TEXT PRIMARY KEY DEFAULT 'singleton',
    data TEXT NOT NULL DEFAULT '{}'
);

-- ─── Workspaces ───────────────────────────────────────────────────────────────
--
-- Derived / cache view of workspace → project summaries.
-- Kept in sync whenever a project is created, updated, scanned, or deleted.

CREATE TABLE IF NOT EXISTS workspaces (
    name TEXT PRIMARY KEY
);

-- ─── Webhooks ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhooks (
    id              TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    -- JSON array of event strings
    events          TEXT NOT NULL DEFAULT '[]',
    -- Plaintext secret used for HMAC signing
    secret          TEXT,
    created_at      TEXT NOT NULL,
    last_delivered_at TEXT
);
