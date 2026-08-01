ALTER TABLE exceptions ADD COLUMN project_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_exceptions_project_id ON exceptions(project_id);
