package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// listExceptions handles GET /v1/exceptions
func listExceptions(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	projectID := vars["projectId"]

	exceptions, err := pm.ListExceptions(projectID)
	if err != nil {
		http.Error(w, "Failed to list exceptions", http.StatusInternalServerError)
		return
	}

	if exceptions == nil {
		exceptions = []*store.Exception{}
	}

	_ = json.NewEncoder(w).Encode(exceptions)
}

// createException handles POST /v1/exceptions
func createException(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	var req store.Exception
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.RuleID == "" || req.Scope == nil || req.Reason == "" {
		http.Error(w, "ruleId, scope, and reason are required", http.StatusBadRequest)
		return
	}

	req.ID = "exc_" + uuid.New().String()[:12]
	req.CreatedAt = time.Now()
	req.Status = "active"

	// Default createdBy since auth context is mocked/basic right now
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}

	req.AuditTrail = append(req.AuditTrail, &store.AuditEvent{
		Action:    "exception.created",
		Timestamp: time.Now(),
		User:      req.CreatedBy,
	})

	if err := pm.CreateException(&req); err != nil {
		http.Error(w, "Failed to create exception", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}

// getException handles GET /v1/exceptions/{exceptionId}
func getException(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	excID := vars["exceptionId"]

	exc, err := pm.GetException(excID)
	if err != nil {
		http.Error(w, "Exception not found", http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(exc)
}

// updateException handles PATCH /v1/exceptions/{exceptionId}
func updateException(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	excID := vars["exceptionId"]

	var updates store.ExceptionUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exc, err := pm.UpdateException(excID, updates)
	if err != nil {
		http.Error(w, "Failed to update exception", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(exc)
}

// revokeException handles DELETE /v1/exceptions/{exceptionId}
func revokeException(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	excID := vars["exceptionId"]

	if err := pm.DeleteException(excID); err != nil {
		http.Error(w, "Failed to revoke exception", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// exportExceptions handles GET /v1/exceptions/export
func exportExceptions(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	projectID := vars["projectId"]

	exceptions, err := pm.ListExceptions(projectID)
	if err != nil {
		http.Error(w, "Failed to export exceptions", http.StatusInternalServerError)
		return
	}

	activeExceptions := []*store.Exception{}
	for _, exc := range exceptions {
		if exc.Status != "revoked" {
			activeExceptions = append(activeExceptions, exc)
		}
	}

	w.Header().Set("Content-Disposition", "attachment; filename=checkmate.json")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(activeExceptions)
}

// importExceptions handles POST /v1/exceptions/import
func importExceptions(w http.ResponseWriter, r *http.Request) {
	if pm == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	var exceptions []*store.Exception
	if err := json.NewDecoder(r.Body).Decode(&exceptions); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	imported := 0
	skipped := 0
	var errors []string

	for _, exc := range exceptions {
		// Ensure ID is new or managed properly, here we just insert
		if exc.ID == "" {
			exc.ID = "exc_" + uuid.New().String()[:12]
		}

		if err := pm.CreateException(exc); err != nil {
			skipped++
			errors = append(errors, err.Error())
		} else {
			imported++
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errors,
	})
}

// validateExceptions handles POST /v1/exceptions/validate
func validateExceptions(w http.ResponseWriter, r *http.Request) {
	// Simple validation: just verify it parses as JSON array of exceptions
	var exceptions []*store.Exception
	if err := json.NewDecoder(r.Body).Decode(&exceptions); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":  true,
		"errors": []string{},
	})
}
