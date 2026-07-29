package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/auth"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuthTest(t *testing.T) (*sqlite.DB, func()) {
	tempDir := t.TempDir()
	db, err := sqlite.New(tempDir)
	require.NoError(t, err)

	pm = db

	return db, func() { _ = db.Close() }
}

func TestAPI_AuthLogin(t *testing.T) {
	_, cleanup := setupAuthTest(t)
	defer cleanup()

	// 1. Valid Login
	body := `{"username": "testuser", "password": "password123"}`
	req, _ := http.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(body))
	w := httptest.NewRecorder()

	authLogin(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["accessToken"])
	assert.NotEmpty(t, resp["refreshToken"])
	assert.Equal(t, float64(900), resp["expiresIn"])

	// 2. Invalid Login (Missing username)
	body = `{"password": "password123"}`
	req, _ = http.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(body))
	w = httptest.NewRecorder()

	authLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_APIKeys(t *testing.T) {
	_, cleanup := setupAuthTest(t)
	defer cleanup()

	// 1. Create API Key
	createReq := auth.APIKey{
		Name: "CI Key",
		Scopes: []auth.APIKeyScope{auth.ScopeScanWrite},
	}
	body, _ := json.Marshal(createReq)
	req, _ := http.NewRequest(http.MethodPost, "/v1/auth/api-keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createAPIKey(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var created auth.APIKeyCreated
	err := json.NewDecoder(w.Body).Decode(&created)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, created.Key)
	assert.True(t, strings.HasPrefix(created.Key, "cm_"))
	assert.Equal(t, "CI Key", created.Name)

	// 2. Validate API Key (Middleware logic via validateAPIKey helper)
	isValid := validateAPIKey(created.Key)
	assert.True(t, isValid, "The generated plaintext key should pass bcrypt validation against the DB")

	isValid = validateAPIKey("cm_invalidkey")
	assert.False(t, isValid)
}
