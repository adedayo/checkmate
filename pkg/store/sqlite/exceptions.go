package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
)

// CreateException inserts a new exception into the database.
func (d *DB) CreateException(exc *store.Exception) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	scopeType := ""
	if exc.Scope != nil {
		scopeType = exc.Scope.Type
	}
	scopeJSON, _ := json.Marshal(exc.Scope)
	evidenceJSON, _ := json.Marshal(exc.Evidence)
	tagsJSON, _ := json.Marshal(exc.Tags)

	_, err := d.db.Exec(`
		INSERT INTO exceptions (
			id, rule_id, scope_type, scope_json, reason, justification, created_by,
			created_at, expires_at, status, evidence_json, tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, exc.ID, exc.RuleID, scopeType, string(scopeJSON), exc.Reason, exc.Justification, exc.CreatedBy,
		exc.CreatedAt.Format(time.RFC3339), timePtrToStr(exc.ExpiresAt), exc.Status, string(evidenceJSON), string(tagsJSON))

	if err == nil && len(exc.AuditTrail) > 0 {
		for _, audit := range exc.AuditTrail {
			d.insertAuditLogTx(d.db, audit, "exception", exc.ID)
		}
	}

	return err
}

func timePtrToStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func parseTimeStr(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return nil
	}
	return &t
}

// GetException retrieves an exception by ID.
func (d *DB) GetException(id string) (*store.Exception, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRow(`
		SELECT id, rule_id, scope_json, reason, justification, created_by,
		       created_at, expires_at, status, evidence_json, tags
		FROM exceptions
		WHERE id = ?
	`, id)

	var exc store.Exception
	var scopeJSON, evidenceJSON, tagsJSON string
	var justification, expiresAt, createdAt sql.NullString

	err := row.Scan(
		&exc.ID, &exc.RuleID, &scopeJSON, &exc.Reason, &justification, &exc.CreatedBy,
		&createdAt, &expiresAt, &exc.Status, &evidenceJSON, &tagsJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("exception not found")
		}
		return nil, err
	}

	exc.Justification = justification.String
	exc.ExpiresAt = parseTimeStr(expiresAt)
	if createdAt.Valid {
		exc.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
	}

	json.Unmarshal([]byte(scopeJSON), &exc.Scope)
	json.Unmarshal([]byte(evidenceJSON), &exc.Evidence)
	json.Unmarshal([]byte(tagsJSON), &exc.Tags)

	exc.AuditTrail = d.getAuditLogsTx(d.db, "exception", id)

	return &exc, nil
}

// ListExceptions retrieves all exceptions.
func (d *DB) ListExceptions() ([]*store.Exception, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, rule_id, scope_json, reason, justification, created_by,
		       created_at, expires_at, status, evidence_json, tags
		FROM exceptions
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []*store.Exception
	for rows.Next() {
		var exc store.Exception
		var scopeJSON, evidenceJSON, tagsJSON string
		var justification, expiresAt, createdAt sql.NullString

		if err := rows.Scan(
			&exc.ID, &exc.RuleID, &scopeJSON, &exc.Reason, &justification, &exc.CreatedBy,
			&createdAt, &expiresAt, &exc.Status, &evidenceJSON, &tagsJSON,
		); err != nil {
			return nil, err
		}

		exc.Justification = justification.String
		exc.ExpiresAt = parseTimeStr(expiresAt)
		if createdAt.Valid {
			exc.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
		}

		json.Unmarshal([]byte(scopeJSON), &exc.Scope)
		json.Unmarshal([]byte(evidenceJSON), &exc.Evidence)
		json.Unmarshal([]byte(tagsJSON), &exc.Tags)

		exceptions = append(exceptions, &exc)
	}
	rows.Close() // Close rows to release the connection

	// Fetch audit logs for all exceptions
	for _, exc := range exceptions {
		exc.AuditTrail = d.getAuditLogsTx(d.db, "exception", exc.ID)
	}

	return exceptions, nil
}

// UpdateException updates mutable fields and appends to the audit trail.
func (d *DB) UpdateException(id string, updates store.ExceptionUpdate) (*store.Exception, error) {
	exc, err := d.GetException(id)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if updates.ExpiresAt != nil {
		exc.ExpiresAt = updates.ExpiresAt
	}
	if updates.Justification != nil {
		exc.Justification = *updates.Justification
	}
	if updates.Tags != nil {
		exc.Tags = updates.Tags
	}

	audit := &store.AuditEvent{
		Action:    "exception.updated",
		Timestamp: time.Now(),
		User:      "system",
		Details:   "Exception updated via API",
	}
	exc.AuditTrail = append(exc.AuditTrail, audit)
	d.insertAuditLogTx(d.db, audit, "exception", id)

	tagsJSON, _ := json.Marshal(exc.Tags)

	_, err = d.db.Exec(`
		UPDATE exceptions 
		SET expires_at = ?, justification = ?, tags = ?
		WHERE id = ?
	`, timePtrToStr(exc.ExpiresAt), exc.Justification, string(tagsJSON), id)

	if err != nil {
		return nil, err
	}

	return exc, nil
}

// DeleteException performs a soft delete by marking status as revoked.
func (d *DB) DeleteException(id string) error {
	exc, err := d.GetException(id)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	exc.Status = "revoked"
	audit := &store.AuditEvent{
		Action:    "exception.revoked",
		Timestamp: time.Now(),
		User:      "system",
		Details:   "Exception revoked via API",
	}
	exc.AuditTrail = append(exc.AuditTrail, audit)
	d.insertAuditLogTx(d.db, audit, "exception", id)

	_, err = d.db.Exec(`
		UPDATE exceptions
		SET status = ?
		WHERE id = ?
	`, exc.Status, id)

	return err
}

func (d *DB) insertAuditLogTx(db *sql.DB, audit *store.AuditEvent, resourceType, resourceID string) {
	db.Exec(`
		INSERT INTO audit_log (id, actor, action, resource_type, resource_id, diff, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "aud_"+uuid.New().String()[:12], audit.User, audit.Action, resourceType, resourceID, audit.Details, audit.Timestamp.Format(time.RFC3339))
}

func (d *DB) getAuditLogsTx(db *sql.DB, resourceType, resourceID string) []*store.AuditEvent {
	rows, err := db.Query(`
		SELECT actor, action, created_at, diff
		FROM audit_log
		WHERE resource_type = ? AND resource_id = ?
		ORDER BY created_at ASC
	`, resourceType, resourceID)
	
	if err != nil {
		return nil
	}
	defer rows.Close()

	var audits []*store.AuditEvent
	for rows.Next() {
		var a store.AuditEvent
		var createdAt sql.NullString
		var details sql.NullString
		rows.Scan(&a.User, &a.Action, &createdAt, &details)
		if createdAt.Valid {
			a.Timestamp, _ = time.Parse(time.RFC3339, createdAt.String)
		}
		a.Details = details.String
		audits = append(audits, &a)
	}
	return audits
}
