package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunSearchCommand_FailsOnUnauthenticatedRepo(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	// Reset flags cleanly for test
	gitToken = ""
	gitTokenEnv = ""
	sshKeyPath = ""
	gitDepth = 1
	insecureSkipTLS = false
	asJSON = true
	asSARIF = false
	asPDF = false
	sensitiveFiles = false
	generateSampleExclusion = false

	code := runSearchCommand(searchCmd, []string{srv.URL + "/org/private.git"})
	if code == 0 {
		t.Fatalf("expected non-zero exit code when all targets fail acquisition, got 0")
	}
}
