package sqlite

import (
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) (*DB, func()) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	return db, func() { db.Close() }
}

func TestDB_APIKeys(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// 1. Create an API Key
	expiresAt := time.Now().Add(24 * time.Hour)
	key := &auth.APIKey{
		ID:        "ak_12345678",
		Name:      "Test Key",
		KeyPrefix: "cm_a1b2c",
		Scopes:    []auth.APIKeyScope{auth.ScopeScanRead},
		CreatedBy: "testuser",
		CreatedAt: time.Now(),
		ExpiresAt: &expiresAt,
	}

	hash := "fake_bcrypt_hash"

	err := db.CreateAPIKey(key, hash)
	require.NoError(t, err, "should create API key without error")

	// 2. List API Keys
	keys, err := db.ListAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "Test Key", keys[0].Name)
	assert.Equal(t, "cm_a1b2c", keys[0].KeyPrefix)
	assert.Equal(t, []auth.APIKeyScope{auth.ScopeScanRead}, keys[0].Scopes)

	// 3. Get API Key By Prefix
	fetchedKey, fetchedHash, err := db.GetAPIKeyByPrefix("cm_a1b2c")
	require.NoError(t, err)
	assert.Equal(t, "ak_12345678", fetchedKey.ID)
	assert.Equal(t, "fake_bcrypt_hash", fetchedHash)

	// 4. Get Non-Existent API Key
	_, _, err = db.GetAPIKeyByPrefix("cm_invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api key not found")

	// 5. Delete API Key
	err = db.DeleteAPIKey("ak_12345678")
	require.NoError(t, err)

	// 6. Verify Deletion
	keys, err = db.ListAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 0)
}

func TestDB_RefreshTokens(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	tokenHash := "sha256_hash_here"
	username := "test_user"
	expiresAt := time.Now().Add(1 * time.Hour)

	// 1. Store Token
	err := db.StoreRefreshToken(tokenHash, username, expiresAt)
	require.NoError(t, err)

	// 2. Validate Token (Valid)
	fetchedUsername, err := db.ValidateRefreshToken(tokenHash)
	require.NoError(t, err)
	assert.Equal(t, "test_user", fetchedUsername)

	// 3. Validate Token (Expired)
	expiredHash := "sha256_expired"
	err = db.StoreRefreshToken(expiredHash, username, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	_, err = db.ValidateRefreshToken(expiredHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token expired")

	// Wait a moment for the async cleanup routine to run
	time.Sleep(50 * time.Millisecond)

	// Verify the expired token was actually deleted asynchronously
	_, err = db.ValidateRefreshToken(expiredHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token not found")

	// 4. Revoke Token
	err = db.RevokeRefreshToken(tokenHash)
	require.NoError(t, err)

	// 5. Validate Token (Revoked)
	_, err = db.ValidateRefreshToken(tokenHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token not found")
}
