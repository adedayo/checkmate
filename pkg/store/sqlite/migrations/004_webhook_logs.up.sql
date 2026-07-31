CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id              TEXT PRIMARY KEY,
    webhook_id      TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    attempt_number  INTEGER NOT NULL,
    response_code   INTEGER,
    latency_ms      INTEGER,
    error_message   TEXT,
    created_at      TEXT NOT NULL
);
