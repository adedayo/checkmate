package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
)

// CreateWebhook inserts a new webhook into the database.
func (d *DB) CreateWebhook(webhook *store.Webhook) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	eventsJSON, err := json.Marshal(webhook.Events)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook events: %w", err)
	}

	var secret *string
	if webhook.Secret != "" {
		secret = &webhook.Secret
	}

	_, err = d.db.Exec(`
		INSERT INTO webhooks (id, url, events, created_at, secret)
		VALUES (?, ?, ?, ?, ?)
	`, webhook.ID, webhook.URL, string(eventsJSON), webhook.CreatedAt.Format(time.RFC3339), secret)

	return err
}

// GetWebhooks retrieves all webhooks.
func (d *DB) GetWebhooks() ([]*store.Webhook, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, url, events, created_at, secret
		FROM webhooks
	`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var webhooks []*store.Webhook
	for rows.Next() {
		var w store.Webhook
		var eventsJSON string
		var createdAt, secret sql.NullString
		if err := rows.Scan(&w.ID, &w.URL, &eventsJSON, &createdAt, &secret); err != nil {
			return nil, err
		}
		if secret.Valid {
			w.Secret = secret.String
		}
		if createdAt.Valid {
			w.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
		}
		if err := json.Unmarshal([]byte(eventsJSON), &w.Events); err != nil {
			return nil, fmt.Errorf("failed to unmarshal webhook events: %w", err)
		}
		webhooks = append(webhooks, &w)
	}

	return webhooks, rows.Err()
}

// DeleteWebhook deletes a webhook by ID.
func (d *DB) DeleteWebhook(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM webhooks WHERE id = ?`, id)
	return err
}

// RecordWebhookDelivery records a delivery attempt.
func (d *DB) RecordWebhookDelivery(log *store.WebhookDeliveryLog) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO webhook_delivery_logs (id, webhook_id, event_type, attempt_number, response_code, latency_ms, error_message, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, log.ID, log.WebhookID, log.EventType, log.AttemptNumber, log.ResponseCode, log.LatencyMs, log.ErrorMessage, log.CreatedAt.Format(time.RFC3339))
	
	return err
}
