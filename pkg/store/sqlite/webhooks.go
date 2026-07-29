package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"golang.org/x/crypto/bcrypt"
)

// CreateWebhook inserts a new webhook into the database.
func (d *DB) CreateWebhook(webhook *store.Webhook) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	eventsJSON, err := json.Marshal(webhook.Events)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook events: %w", err)
	}

	var secretHash *string
	if webhook.Secret != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(webhook.Secret), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hashStr := string(hash)
		secretHash = &hashStr
	}

	_, err = d.db.Exec(`
		INSERT INTO webhooks (id, url, events, created_at, secret_hash)
		VALUES (?, ?, ?, ?, ?)
	`, webhook.ID, webhook.URL, string(eventsJSON), webhook.CreatedAt.Format(time.RFC3339), secretHash)

	return err
}

// GetWebhooks retrieves all webhooks.
func (d *DB) GetWebhooks() ([]*store.Webhook, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, url, events, created_at
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
		var createdAt sql.NullString
		if err := rows.Scan(&w.ID, &w.URL, &eventsJSON, &createdAt); err != nil {
			return nil, err
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
