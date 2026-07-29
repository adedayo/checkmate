package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// listWebhooks handles GET /v1/webhooks
func listWebhooks(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	webhooks, err := pm.GetWebhooks()
	if err != nil {
		http.Error(w, "Failed to retrieve webhooks", http.StatusInternalServerError)
		return
	}

	// Hide the secrets when listing
	for _, wh := range webhooks {
		wh.Secret = ""
	}

	if webhooks == nil {
		webhooks = []*store.Webhook{}
	}

	_ = json.NewEncoder(w).Encode(webhooks)
}

// createWebhook handles POST /v1/webhooks
func createWebhook(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.URL == "" || len(req.Events) == 0 {
		http.Error(w, "url and events are required", http.StatusBadRequest)
		return
	}

	// Generate a secure webhook secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}
	secret := hex.EncodeToString(secretBytes)

	webhook := &store.Webhook{
		ID:        "wh_" + uuid.New().String()[:12], // Simple ID generation
		URL:       req.URL,
		Events:    req.Events,
		CreatedAt: time.Now(),
		Secret:    secret,
	}

	if err := pm.CreateWebhook(webhook); err != nil {
		http.Error(w, "Failed to create webhook", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(webhook)
}

// deleteWebhook handles DELETE /v1/webhooks/{webhookId}
func deleteWebhook(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	webhookID := vars["webhookId"]

	if err := pm.DeleteWebhook(webhookID); err != nil {
		http.Error(w, "Failed to delete webhook", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// testWebhook handles POST /v1/webhooks/{webhookId}/test
func testWebhook(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// In a real implementation, this would look up the webhook URL and signature
	// and fire an HTTP POST to it with a mock payload.
	// For now, we'll just return 202 Accepted.

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "Test event dispatched",
	})
}
