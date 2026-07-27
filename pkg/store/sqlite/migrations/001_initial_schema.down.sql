-- Migration: 001_initial_schema
-- Direction: DOWN

DROP TABLE IF EXISTS webhooks;
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS git_config;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS exceptions;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS projects;
