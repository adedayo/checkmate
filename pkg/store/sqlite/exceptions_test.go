package sqlite

import (
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_Exceptions(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()

	exc := &store.Exception{
		ID:        "exc_123",
		RuleID:    "TEST_RULE",
		Scope:     &store.ExceptionScopeDetail{Type: "repository", RepoURL: "https://github.com/test/repo"},
		Reason:    "false_positive",
		CreatedBy: "alice",
		CreatedAt: time.Now(),
		Status:    "active",
		Tags:      []string{"test", "ignore"},
	}

	err = db.CreateException(exc)
	require.NoError(t, err)

	fetched, err := db.GetException("exc_123")
	require.NoError(t, err)
	assert.Equal(t, "exc_123", fetched.ID)
	assert.Equal(t, "TEST_RULE", fetched.RuleID)
	assert.Equal(t, "repository", fetched.Scope.Type)
	assert.Equal(t, []string{"test", "ignore"}, fetched.Tags)

	// Test Update
	justification := "updated justification"
	expiresAt := time.Now().Add(24 * time.Hour)
	updates := store.ExceptionUpdate{
		Justification: &justification,
		ExpiresAt:     &expiresAt,
		Tags:          []string{"updated"},
	}

	updated, err := db.UpdateException("exc_123", updates)
	require.NoError(t, err)
	assert.Equal(t, justification, updated.Justification)
	assert.Equal(t, []string{"updated"}, updated.Tags)
	assert.Len(t, updated.AuditTrail, 1)
	assert.Equal(t, "exception.updated", updated.AuditTrail[0].Action)

	// Test List
	list, err := db.ListExceptions()
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// Test Delete
	err = db.DeleteException("exc_123")
	require.NoError(t, err)

	deleted, err := db.GetException("exc_123")
	require.NoError(t, err)
	assert.Equal(t, "revoked", deleted.Status)
	assert.Len(t, deleted.AuditTrail, 2)
	assert.Equal(t, "exception.revoked", deleted.AuditTrail[1].Action)
}
