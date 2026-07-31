package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_WebhooksIntegration(t *testing.T) {
	_, cleanup := setupAuthTest(t)
	defer cleanup()

	// Setting up router so mux.Vars works
	router := mux.NewRouter()
	router.HandleFunc("/v1/webhooks", createWebhook).Methods(http.MethodPost)
	router.HandleFunc("/v1/webhooks", listWebhooks).Methods(http.MethodGet)
	router.HandleFunc("/v1/webhooks/{webhookId}", deleteWebhook).Methods(http.MethodDelete)

	// Create Webhook
	body := `{"url": "https://example.com", "events": ["scan.completed"]}`
	req, _ := http.NewRequest(http.MethodPost, "/v1/webhooks", strings.NewReader(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp store.Webhook
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.NotEmpty(t, resp.Secret)
	assert.Equal(t, "https://example.com", resp.URL)

	webhookID := resp.ID

	// List Webhooks
	req, _ = http.NewRequest(http.MethodGet, "/v1/webhooks", nil)
	w = httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	require.Equal(t, http.StatusOK, w.Code)
	var listResp []store.Webhook
	err = json.NewDecoder(w.Body).Decode(&listResp)
	require.NoError(t, err)
	assert.Len(t, listResp, 1)
	assert.Empty(t, listResp[0].Secret) // Secret must be redacted on GET

	// Delete Webhook
	req, _ = http.NewRequest(http.MethodDelete, "/v1/webhooks/"+webhookID, nil)
	w = httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestAPI_AISettingsIntegration(t *testing.T) {
	_, cleanup := setupAuthTest(t)
	defer cleanup()

	router := mux.NewRouter()
	router.HandleFunc("/v1/settings/ai", updateAISettings).Methods(http.MethodPut)
	router.HandleFunc("/v1/settings/ai", getAISettings).Methods(http.MethodGet)

	// Update AI Settings
	settings := store.AISettings{
		Enabled:           true,
		Provider:          "openai",
		Model:             "gpt-4",
		BaseURL:           "https://api.openai.com",
		APIKey:            "sk-test",
		DefaultPromptMode: "REDACTED",
	}
	body, _ := json.Marshal(settings)
	req, _ := http.NewRequest(http.MethodPut, "/v1/settings/ai", bytes.NewReader(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Get AI Settings
	req, _ = http.NewRequest(http.MethodGet, "/v1/settings/ai", nil)
	w = httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp store.AISettings
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "gpt-4", resp.Model)
}
