CREATE TABLE IF NOT EXISTS ai_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Ensure only one row exists
    enabled BOOLEAN NOT NULL DEFAULT 0,
    provider TEXT NOT NULL DEFAULT 'ollama',
    model TEXT NOT NULL DEFAULT 'llama3',
    base_url TEXT NOT NULL DEFAULT 'http://localhost:11434/v1',
    api_key TEXT,
    default_prompt_mode TEXT NOT NULL DEFAULT 'REDACTED'
);

INSERT OR IGNORE INTO ai_settings (id) VALUES (1);
