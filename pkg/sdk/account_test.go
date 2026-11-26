package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adedayo/checkmate/pkg/gitservice/account"
)

func TestDefaultAccountFilterDistinctFromZeroValue(t *testing.T) {
	var zero AccountFilter
	def := DefaultAccountFilter()
	if zero.IncludePrivate == def.IncludePrivate {
		t.Fatalf("expected DefaultAccountFilter().IncludePrivate (%v) to differ from zero value (%v)",
			def.IncludePrivate, zero.IncludePrivate)
	}
	if !def.IncludePrivate || def.IncludeForks || def.IncludeArchived || def.IncludeDisabled {
		t.Fatalf("unexpected DefaultAccountFilter(): %+v", def)
	}
}

func TestSDKParseAccountRefAndTypedErrors(t *testing.T) {
	ref, err := ParseAccountRef("https://github.com/adedayo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Provider != "github" || ref.Login != "adedayo" {
		t.Fatalf("unexpected ref: %+v", ref)
	}

	_, err = ParseAccountRef("https://github.com/adedayo/checkmate")
	if !errors.Is(err, ErrNotAnAccount) {
		t.Fatalf("expected ErrNotAnAccount for repo URL, got %v", err)
	}
}

func TestSDKResolveAccount_AnonymousZeroConfig(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CHECKMATE_GIT_TOKEN", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/users/octo":
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "User"})
		case "/users/octo/repos":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "zebra", "clone_url": "https://github.com/octo/zebra.git", "size": 10, "default_branch": "main"},
				{"name": "alpha", "clone_url": "https://github.com/octo/alpha.git", "size": 20, "default_branch": "main"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ref, err := ParseAccountRef("github:octo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolveAccountWithOptions(context.Background(), ref, DefaultAccountFilter(), account.ResolveOptions{
		GitHubRESTBaseURL: srv.URL,
		AnonymousOnly:     true,
	})
	if err != nil {
		t.Fatalf("anonymous ResolveAccount failed: %v", err)
	}
	if res.Authenticated || !res.PotentiallyIncomplete {
		t.Fatalf("expected anonymous result to be marked potentially incomplete: %+v", res)
	}
	if len(res.Repositories) != 2 || res.Repositories[0].Name != "alpha" || res.Repositories[1].Name != "zebra" {
		t.Fatalf("expected sorted repositories [alpha, zebra], got %+v", res.Repositories)
	}
}
