package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/triage"
)

func TestV1FindingContextAndCheckoutCleanupEndpoints(t *testing.T) {
	db, cleanup := setupAuthTest(t)
	defer cleanup()

	targetDir := t.TempDir()
	filePath := filepath.Join(targetDir, "creds.py")
	if err := os.WriteFile(filePath, []byte("# header\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n# footer\n"), 0600); err != nil {
		t.Fatal(err)
	}

	svc := triage.NewService(db)
	ov, err := svc.Scan(t.Context(), triage.ScanRequest{Targets: []string{targetDir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	findings, err := db.GetScanFindings(ov.ScanID)
	if err != nil || len(findings) == 0 {
		t.Fatalf("expected findings: %v", err)
	}

	// 1. GET /v1/findings/{findingId}/context
	ctxURL := "http://localhost/v1/findings/" + findings[0].FindingID + "/context?scanId=" + ov.ScanID + "&before=5&after=5"
	req := httptest.NewRequest(http.MethodGet, ctxURL, nil)
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET context expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var ctxRes triage.FindingContextResult
	if err := json.Unmarshal(rec.Body.Bytes(), &ctxRes); err != nil {
		t.Fatalf("unmarshal context: %v", err)
	}
	if ctxRes.Source != "local_file" || len(ctxRes.Lines) < 2 {
		t.Fatalf("unexpected finding context: %+v", ctxRes)
	}

	// 2. DELETE /v1/scans/{scanId}/checkout
	delReq := httptest.NewRequest(http.MethodDelete, "http://localhost/v1/scans/"+ov.ScanID+"/checkout", nil)
	delRec := httptest.NewRecorder()
	routes.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE checkout expected 200, got %d: %s", delRec.Code, delRec.Body.String())
	}
}
