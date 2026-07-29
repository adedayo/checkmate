package api

import (
	"encoding/json"
	"net/http"

	"github.com/adedayo/checkmate/pkg/store"
)

func getAISettings(w http.ResponseWriter, r *http.Request) {
	settings, err := pm.GetAISettings()
	if err != nil {
		http.Error(w, "Failed to retrieve AI settings", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(settings)
}

func updateAISettings(w http.ResponseWriter, r *http.Request) {
	var settings store.AISettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := pm.UpdateAISettings(&settings); err != nil {
		http.Error(w, "Failed to update AI settings", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(settings)
}
