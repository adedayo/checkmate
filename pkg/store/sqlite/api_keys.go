package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/auth"
)

// CreateAPIKey persists a new API key metadata and its hash.
func (d *DB) CreateAPIKey(key *auth.APIKey, hash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	scopesJSON, err := json.Marshal(key.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	ipAllowlistJSON, err := json.Marshal(key.IPAllowlist)
	if err != nil {
		return fmt.Errorf("marshal ip_allowlist: %w", err)
	}

	var expiresAt, lastUsedAt *string
	if key.ExpiresAt != nil {
		str := key.ExpiresAt.Format(time.RFC3339)
		expiresAt = &str
	}
	if key.LastUsedAt != nil {
		str := key.LastUsedAt.Format(time.RFC3339)
		lastUsedAt = &str
	}

	_, err = d.db.ExecContext(context.Background(), `
		INSERT INTO api_keys(id, name, key_hash, key_prefix, scopes, created_by, created_at, expires_at, last_used_at, ip_allowlist)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, hash, key.KeyPrefix, string(scopesJSON), key.CreatedBy, key.CreatedAt.Format(time.RFC3339),
		expiresAt, lastUsedAt, string(ipAllowlistJSON))
	if err != nil {
		return fmt.Errorf("insert api_key: %w", err)
	}
	return nil
}

// ListAPIKeys retrieves all API keys without their hashes.
func (d *DB) ListAPIKeys() ([]*auth.APIKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.QueryContext(context.Background(), `
		SELECT id, name, key_prefix, scopes, created_by, created_at, expires_at, last_used_at, ip_allowlist
		FROM api_keys
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query api_keys: %w", err)
	}
	defer rows.Close()

	var keys []*auth.APIKey
	for rows.Next() {
		var key auth.APIKey
		var scopesStr, ipAllowlistStr string
		var expAt, lastUsed *string
		var createdAtStr string

		if err := rows.Scan(&key.ID, &key.Name, &key.KeyPrefix, &scopesStr, &key.CreatedBy, &createdAtStr, &expAt, &lastUsed, &ipAllowlistStr); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}

		if err := json.Unmarshal([]byte(scopesStr), &key.Scopes); err != nil {
			return nil, fmt.Errorf("unmarshal scopes: %w", err)
		}
		if err := json.Unmarshal([]byte(ipAllowlistStr), &key.IPAllowlist); err != nil {
			return nil, fmt.Errorf("unmarshal ipAllowlist: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			key.CreatedAt = t
		}
		if expAt != nil {
			if t, err := time.Parse(time.RFC3339, *expAt); err == nil {
				key.ExpiresAt = &t
			}
		}
		if lastUsed != nil {
			if t, err := time.Parse(time.RFC3339, *lastUsed); err == nil {
				key.LastUsedAt = &t
			}
		}

		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

// GetAPIKeyByPrefix retrieves the API key and its hash by the key prefix for authentication.
func (d *DB) GetAPIKeyByPrefix(prefix string) (*auth.APIKey, string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRowContext(context.Background(), `
		SELECT id, name, key_hash, key_prefix, scopes, created_by, created_at, expires_at, last_used_at, ip_allowlist
		FROM api_keys WHERE key_prefix = ?`, prefix)

	var key auth.APIKey
	var keyHash, scopesStr, ipAllowlistStr, createdAtStr string
	var expAt, lastUsed *string

	err := row.Scan(&key.ID, &key.Name, &keyHash, &key.KeyPrefix, &scopesStr, &key.CreatedBy, &createdAtStr, &expAt, &lastUsed, &ipAllowlistStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", fmt.Errorf("api key not found")
		}
		return nil, "", fmt.Errorf("scan api_key_by_prefix: %w", err)
	}

	if err := json.Unmarshal([]byte(scopesStr), &key.Scopes); err != nil {
		return nil, "", fmt.Errorf("unmarshal scopes: %w", err)
	}
	if err := json.Unmarshal([]byte(ipAllowlistStr), &key.IPAllowlist); err != nil {
		return nil, "", fmt.Errorf("unmarshal ipAllowlist: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		key.CreatedAt = t
	}
	if expAt != nil {
		if t, err := time.Parse(time.RFC3339, *expAt); err == nil {
			key.ExpiresAt = &t
		}
	}
	if lastUsed != nil {
		if t, err := time.Parse(time.RFC3339, *lastUsed); err == nil {
			key.LastUsedAt = &t
		}
	}

	return &key, keyHash, nil
}

// DeleteAPIKey removes an API key from the database.
func (d *DB) DeleteAPIKey(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.db.ExecContext(context.Background(), `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete api_key: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}
