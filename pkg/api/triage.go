package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/adedayo/checkmate/pkg/ai"
)

type triageResponse struct {
	Status    string `json:"status"`
	FindingID string `json:"findingId"`
}

func triageFinding(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	findingID := vars["findingId"]

	// Return 202 Accepted immediately
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(triageResponse{
		Status:    "queued",
		FindingID: findingID,
	})

	// Process AI triage in background
	go processTriage(findingID)
}

func processTriage(findingID string) {
	// 1. Load finding
	finding, err := pm.GetFinding(findingID)
	if err != nil {
		return // log error in production
	}

	// 2. Load settings
	settings, err := pm.GetAISettings()
	if err != nil || !settings.Enabled {
		return
	}

	// 3. Request AI evaluation
	ann, err := ai.TriageFinding(settings, finding)
	if err != nil {
		return // log error
	}

	// 4. Update finding in DB
	_ = pm.UpdateFindingAIAnnotation(findingID, ann)
}
