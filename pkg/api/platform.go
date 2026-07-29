package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/gorilla/mux"
)

// systemHealth returns the basic health of the API
func systemHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// systemReady checks if dependencies (like the DB) are ready
func systemReady(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, `{"status": "unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	if err := pm.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "unavailable",
			"error":  err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

// searchFindings handles searching findings across projects
func searchFindings(w http.ResponseWriter, r *http.Request) {
	var req store.FindingSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Apply defaults
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Page <= 0 {
		req.Page = 1
	}

	result, err := pm.SearchFindings(req)
	if err != nil {
		http.Error(w, "Failed to search findings", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(result)
}

// listProjectScans retrieves paginated scans for a project
func listProjectScans(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID := vars["projectId"]

	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	scans, err := pm.ListProjectScans(projectID, limit, offset)
	if err != nil {
		http.Error(w, "Failed to list scans", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(scans)
}

// scanSSEHandler streams scan events to the client using Server-Sent Events
func scanSSEHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanId"]

	// Set required SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	broker := pm.GetBroker()
	if broker == nil {
		http.Error(w, "Event broker unavailable", http.StatusInternalServerError)
		return
	}

	eventsCh, cleanup := broker.Subscribe(scanID)
	defer cleanup()

	// Keep connection alive with periodic pings
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Ensure immediate flush of headers
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			// Client disconnected
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case event, open := <-eventsCh:
			if !open {
				// Channel closed, scan completed or broker shutdown
				return
			}
			
			dataBytes, err := json.Marshal(event.Data)
			if err != nil {
				continue
			}
			
			// SSE format:
			// event: <type>
			// data: <json>
			_, _ = fmt.Fprintf(w, "event: %s\n", event.Type)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(dataBytes))
			flusher.Flush()
			
			if event.Type == store.EventComplete {
				return
			}
		}
	}
}

// startProjectScan initiates a new scan asynchronously and returns the scan ID
func startProjectScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID := vars["projectId"]

	// Get project to ensure it exists
	proj, err := pm.GetProject(projectID)
	if err != nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	// We use a channel to capture the scanID synchronously before returning to client
	scanIDCh := make(chan string, 1)

	go func() {
		// RunScan will block, so it must be run in a goroutine
		pm.RunScan(
			r.Context(),
			projectID,
			proj.ScanPolicy, // use project's defined policy
			nil,             // default scanner
			func(id string) { scanIDCh <- id },
			nil,             // default repo checker
			nil,             // progress monitor (broker handles events now)
			nil,             // default summariser
			nil,             // default ws summariser
		)
	}()

	// Wait for the scan ID to be created
	var scanID string
	select {
	case scanID = <-scanIDCh:
	case <-time.After(5 * time.Second):
		http.Error(w, "Timeout starting scan", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"scanId": scanID,
		"status": "starting",
	})
}
