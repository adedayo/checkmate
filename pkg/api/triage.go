package api

import (
	"encoding/json"
	"net/http"
	"time"

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

func batchTriageFindings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanId"]

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "batch_queued",
		"scanId": scanID,
	})

	go processBatchTriage(scanID)
}

func processBatchTriage(scanID string) {
	findingIDs, err := pm.GetUnannotatedFindings(scanID)
	if err != nil || len(findingIDs) == 0 {
		return
	}

	for _, id := range findingIDs {
		processTriage(id)
		time.Sleep(200 * time.Millisecond)
	}
}
