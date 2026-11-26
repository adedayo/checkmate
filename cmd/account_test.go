package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/gitservice/account"
)

func resetAccountFlags() {
	accountServiceID = ""
	accountGitToken = ""
	accountGitTokenEnv = ""
	accountAnonymous = true
	accountIncludeForks = false
	accountIncludeArchived = false
	accountIncludeDisabled = false
	accountIncludeNames = nil
	accountExcludeNames = nil
	accountMaxRepos = 0
	accountFormat = "text"
	accountGitDepth = 1
	accountFullHistory = false
	accountRetainCode = false
	accountCloneDir = ""
	accountRedact = true
	accountFailOnFindings = false
	accountMinConfidence = "medium"
	accountExclusion = ""
	accountNoDB = true
	accountDataPath = "~/.checkmate"
	accountExcludeTests = false
	accountQuiet = false
	accountVerbose = false
	accountInsecureTLS = false
	accountTestRESTBaseURL = ""
	accountTestGraphQLEndpoint = ""
}

func TestAccountResolveCommand_TextAndJSONAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "59")
		switch r.URL.Path {
		case "/users/octocat":
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "User"})
		case "/users/octocat/repos":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "zebra", "clone_url": "https://github.com/octocat/zebra.git", "size": 100, "default_branch": "main"},
				{"name": "forked", "clone_url": "https://github.com/octocat/forked.git", "fork": true, "size": 50},
				{"name": "alpha", "clone_url": "https://github.com/octocat/alpha.git", "size": 25, "default_branch": "main"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 1. Text mode shows anonymous incompleteness warning and sorted repositories.
	resetAccountFlags()
	accountTestRESTBaseURL = srv.URL
	var out, errOut bytes.Buffer
	code := runAccountResolveCommand("https://github.com/octocat", &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, errOut.String())
	}
	text := out.String()
	if !strings.Contains(text, "WARNING: Result is potentially incomplete") {
		t.Fatalf("expected visible incompleteness warning in anonymous text output:\n%s", text)
	}
	idxAlpha := strings.Index(text, "alpha")
	idxZebra := strings.Index(text, "zebra")
	if idxAlpha < 0 || idxZebra < 0 || idxAlpha > idxZebra {
		t.Fatalf("expected sorted repositories alpha before zebra:\n%s", text)
	}
	if strings.Contains(text, "forked") {
		t.Fatalf("forks should be excluded by default:\n%s", text)
	}

	// 2. JSON mode returns structured AccountResolution with PotentiallyIncomplete: true.
	resetAccountFlags()
	accountTestRESTBaseURL = srv.URL
	accountFormat = "json"
	out.Reset()
	errOut.Reset()
	code = runAccountResolveCommand("github:octocat", &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 in json mode, got %d (stderr: %s)", code, errOut.String())
	}
	var res account.AccountResolution
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("invalid json output: %v\n%s", err, out.String())
	}
	if !res.PotentiallyIncomplete || res.Authenticated || len(res.Repositories) != 2 {
		t.Fatalf("unexpected AccountResolution: %+v", res)
	}

	// 3. Repository URL rejected with exit 2.
	resetAccountFlags()
	accountTestRESTBaseURL = srv.URL
	out.Reset()
	errOut.Reset()
	code = runAccountResolveCommand("https://github.com/octocat/alpha", &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for repository URL, got %d", code)
	}

	// 4. Empty account scan succeeds cleanly with incompleteness notice.
	emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/users/empty" {
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "User"})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer emptySrv.Close()

	resetAccountFlags()
	accountTestRESTBaseURL = emptySrv.URL
	accountFormat = "agent"
	out.Reset()
	errOut.Reset()
	code = runAccountScanCommand(accountScanCmd, "github:empty", &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 on empty account scan, got %d (err=%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "potentially incomplete") {
		t.Fatalf("expected incompleteness warning on stderr, got: %s", errOut.String())
	}
}
