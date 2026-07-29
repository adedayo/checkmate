package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// StoreRefreshToken saves a new refresh token hash to the database.
func (d *DB) StoreRefreshToken(tokenHash, username string, expiresAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.ExecContext(context.Background(), `
		INSERT INTO refresh_tokens(token_hash, username, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		tokenHash, username, expiresAt.Format(time.RFC3339), time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("insert refresh_token: %w", err)
	}
	return nil
}

// ValidateRefreshToken checks if a token exists and is not expired, returning the username if valid.
func (d *DB) ValidateRefreshToken(tokenHash string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRowContext(context.Background(), `
		SELECT username, expires_at FROM refresh_tokens WHERE token_hash = ?`, tokenHash)

	var username, expiresAtStr string
	if err := row.Scan(&username, &expiresAtStr); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("refresh token not found")
		}
		return "", fmt.Errorf("scan refresh_token: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return "", fmt.Errorf("parse expires_at: %w", err)
	}

	if time.Now().After(expiresAt) {
		// Clean up expired token asynchronously
		go func() {
			_ = d.RevokeRefreshToken(tokenHash)
		}()
		return "", fmt.Errorf("refresh token expired")
	}

	return username, nil
}

// RevokeRefreshToken deletes a refresh token from the database.
func (d *DB) RevokeRefreshToken(tokenHash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.ExecContext(context.Background(), `DELETE FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("delete refresh_token: %w", err)
	}
	return nil
}
