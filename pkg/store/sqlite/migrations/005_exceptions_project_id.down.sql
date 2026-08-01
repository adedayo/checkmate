DROP INDEX IF EXISTS idx_exceptions_project_id;
ALTER TABLE exceptions DROP COLUMN project_id;
