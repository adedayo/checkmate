package api

import (
	"encoding/json"
	"net/http"

	"github.com/adedayo/checkmate/pkg/mcp"
	"github.com/adedayo/checkmate/pkg/triage"
	"github.com/gorilla/mux"
)

// handleMCP serves the Streamable HTTP Model Context Protocol endpoint at /v1/mcp.
func handleMCP(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	mcp.NewServer(pm, apiVersion).HTTPHandler().ServeHTTP(w, r)
}

type singleFindingTriageRequest struct {
	ScanID              string   `json:"scanId"`
	TriagedBy           string   `json:"triagedBy,omitempty"`
	ApplyToSameChecksum bool     `json:"applyToSameChecksum,omitempty"`
	Verdict             string   `json:"verdict"`
	Reason              string   `json:"reason,omitempty"`
	Justification       string   `json:"justification,omitempty"`
	RemediationHint     string   `json:"remediationHint,omitempty"`
	ContextClues        []string `json:"contextClues,omitempty"`
	FPLikelihood        *float64 `json:"fpLikelihood,omitempty"`
	PersistException    bool     `json:"persistException,omitempty"`
	ExceptionScope      string   `json:"exceptionScope,omitempty"`
	StringMatch         string   `json:"stringMatch,omitempty"`
}

// recordFindingTriage handles PUT /v1/findings/{findingId}/triage to write back
// an external AI agent or human triage verdict for a finding.
func recordFindingTriage(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	findingID := mux.Vars(r)["findingId"]
	var req singleFindingTriageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ScanID == "" {
		http.Error(w, "scanId is required", http.StatusBadRequest)
		return
	}

	svc := triage.NewService(pm)
	res, err := svc.RecordTriageBatch(r.Context(), triage.TriageBatchRequest{
		ScanID:    req.ScanID,
		TriagedBy: req.TriagedBy,
		Decisions: []triage.TriageDecision{
			{
				FindingID:           findingID,
				ApplyToSameChecksum: req.ApplyToSameChecksum,
				Verdict:             req.Verdict,
				Reason:              req.Reason,
				Justification:       req.Justification,
				RemediationHint:     req.RemediationHint,
				ContextClues:        req.ContextClues,
				FPLikelihood:        req.FPLikelihood,
				PersistException:    req.PersistException,
				ExceptionScope:      req.ExceptionScope,
				StringMatch:         req.StringMatch,
			},
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// submitBatchTriage handles POST /v1/scans/{scanId}/triage/batch for external
// agent batch triage write-back.
func submitBatchTriage(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	scanID := mux.Vars(r)["scanId"]
	var req triage.TriageBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ScanID = scanID

	svc := triage.NewService(pm)
	res, err := svc.RecordTriageBatch(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// getSanitisedScan handles GET /v1/scans/{scanId}/sanitised and returns the
// scan's sanitised summary together with its active (non-suppressed) findings.
func getSanitisedScan(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	scanID := mux.Vars(r)["scanId"]
	includeSuppressed := r.URL.Query().Get("includeSuppressed") == "true"

	svc := triage.NewService(pm)
	exp, err := svc.ExportSanitised(r.Context(), triage.ExportRequest{
		ScanID:            scanID,
		Format:            "json",
		IncludeSuppressed: includeSuppressed,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(exp.Content))
}
