package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
)

func TestParseAccountRef(t *testing.T) {
	valid := []struct {
		in   string
		want AccountRef
	}{
		{"https://github.com/adedayo", AccountRef{Provider: "github", Login: "adedayo"}},
		{"https://github.com/adedayo/", AccountRef{Provider: "github", Login: "adedayo"}},
		{"github:adedayo", AccountRef{Provider: "github", Login: "adedayo"}},
		{"GitHub:acme-org", AccountRef{Provider: "github", Login: "acme-org"}},
		{"adedayo", AccountRef{Provider: "github", Login: "adedayo"}},
	}
	for _, tc := range valid {
		got, err := ParseAccountRef(tc.in)
		if err != nil {
			t.Errorf("ParseAccountRef(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAccountRef(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	notAccount := []string{
		"",
		"https://github.com/adedayo/checkmate",
		"https://github.com/adedayo/checkmate.git",
		"git@github.com:adedayo/checkmate.git",
		"github:adedayo/checkmate",
		"adedayo/checkmate",
		"https://github.com/",
	}
	for _, raw := range notAccount {
		_, err := ParseAccountRef(raw)
		if !errors.Is(err, ErrNotAnAccount) {
			t.Errorf("ParseAccountRef(%q) error = %v, want ErrNotAnAccount", raw, err)
		}
	}
}

func TestTransportConformanceAndDeterminism(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CHECKMATE_GIT_TOKEN", "")

	// Fixture account with public repos (returned in intentionally unsorted order across 2 pages),
	// plus fork, archived, disabled, and (on GraphQL only) private repos.
	type fixtureRepo struct {
		Name     string
		Private  bool
		Fork     bool
		Archived bool
		Disabled bool
		SizeKB   int64
		Branch   string
	}
	page1Public := []fixtureRepo{
		{Name: "zeta", SizeKB: 120, Branch: "main"},
		{Name: "archived-repo", Archived: true, SizeKB: 10, Branch: "main"},
		{Name: "fork-repo", Fork: true, SizeKB: 50, Branch: "main"},
	}
	page2Public := []fixtureRepo{
		{Name: "alpha", SizeKB: 42, Branch: "develop"},
		{Name: "disabled-repo", Disabled: true, SizeKB: 5, Branch: "main"},
		{Name: "beta-internal", SizeKB: 80, Branch: "main"},
	}
	privateRepo := fixtureRepo{Name: "secret-core", Private: true, SizeKB: 200, Branch: "main"}

	// REST server serving page 1 and page 2 (with shuffled order).
	var restSrv *httptest.Server
	restSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "58")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()))

		switch r.URL.Path {
		case "/users/acme":
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "Organization"})
		case "/users/acme/repos":
			page := r.URL.Query().Get("page")
			var items []fixtureRepo
			if page == "" || page == "1" {
				items = page1Public
				w.Header().Set("Link", fmt.Sprintf(`<%s/users/acme/repos?per_page=100&type=owner&page=2>; rel="next"`, restSrv.URL))
			} else {
				items = page2Public
			}
			out := make([]map[string]any, 0, len(items))
			for _, it := range items {
				out = append(out, map[string]any{
					"name":           it.Name,
					"clone_url":      fmt.Sprintf("https://github.com/acme/%s.git", it.Name),
					"html_url":       fmt.Sprintf("https://github.com/acme/%s", it.Name),
					"private":        it.Private,
					"fork":           it.Fork,
					"archived":       it.Archived,
					"disabled":       it.Disabled,
					"size":           it.SizeKB,
					"default_branch": it.Branch,
				})
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer restSrv.Close()

	// GraphQL server returning the SAME public repos in REVERSE page order plus privateRepo.
	gqlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer good-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		rl := map[string]any{
			"limit":     5000,
			"remaining": 4998,
			"resetAt":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}

		if !strings.Contains(req.Query, "repositories(") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"repositoryOwner": map[string]any{"__typename": "Organization"},
					"rateLimit":       rl,
				},
			})
			return
		}

		cursor, _ := req.Variables["cursor"].(string)
		var items []fixtureRepo
		var nextCursor string
		var hasNext bool
		if cursor == "" {
			// Reverse page order vs REST to verify determinism!
			items = append([]fixtureRepo{privateRepo}, page2Public...)
			nextCursor = "cursor-p2"
			hasNext = true
		} else {
			items = page1Public
			nextCursor = ""
			hasNext = false
		}
		nodes := make([]map[string]any, 0, len(items))
		for _, it := range items {
			nodes = append(nodes, map[string]any{
				"name":             it.Name,
				"url":              fmt.Sprintf("https://github.com/acme/%s", it.Name),
				"isPrivate":        it.Private,
				"isFork":           it.Fork,
				"isArchived":       it.Archived,
				"isDisabled":       it.Disabled,
				"diskUsage":        it.SizeKB,
				"defaultBranchRef": map[string]any{"name": it.Branch},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"repositoryOwner": map[string]any{
					"__typename": "Organization",
					"repositories": map[string]any{
						"nodes": nodes,
						"pageInfo": map[string]any{
							"endCursor":   nextCursor,
							"hasNextPage": hasNext,
						},
					},
				},
				"rateLimit": rl,
			},
		})
	}))
	defer gqlSrv.Close()

	ref, err := ParseAccountRef("https://github.com/acme")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Anonymous REST resolution.
	anonRes, err := NewResolver(ResolveOptions{
		GitHubRESTBaseURL: restSrv.URL,
		AnonymousOnly:     true,
	}).Resolve(context.Background(), ref, DefaultAccountFilter())
	if err != nil {
		t.Fatalf("anonymous resolution failed: %v", err)
	}
	if anonRes.Authenticated || !anonRes.PotentiallyIncomplete || anonRes.AccountType != "organization" {
		t.Fatalf("unexpected anonymous metadata: %+v", anonRes)
	}
	if anonRes.ExcludedCounts["private"] != 0 {
		t.Fatalf("anonymous resolution must not count private exclusions; got %v", anonRes.ExcludedCounts)
	}

	// 2. Authenticated GraphQL resolution with IncludePrivate: false -> MUST match REST field-for-field!
	filterPublicOnly := DefaultAccountFilter()
	filterPublicOnly.IncludePrivate = false
	authPublicRes, err := NewResolver(ResolveOptions{
		GitHubGraphQLEndpoint: gqlSrv.URL,
		Token:                 "good-token",
	}).Resolve(context.Background(), ref, filterPublicOnly)
	if err != nil {
		t.Fatalf("authenticated public-only resolution failed: %v", err)
	}
	if !authPublicRes.Authenticated || authPublicRes.PotentiallyIncomplete {
		t.Fatalf("unexpected authenticated metadata: %+v", authPublicRes)
	}
	if !reflect.DeepEqual(anonRes.Repositories, authPublicRes.Repositories) {
		t.Fatalf("REST and GraphQL diverged on commonly-visible repos:\nREST:    %+v\nGraphQL: %+v",
			anonRes.Repositories, authPublicRes.Repositories)
	}

	// Verify canonical ascending sort by Location.
	wantOrder := []string{
		"https://github.com/acme/alpha.git",
		"https://github.com/acme/beta-internal.git",
		"https://github.com/acme/zeta.git",
	}
	gotOrder := make([]string, len(anonRes.Repositories))
	for i, r := range anonRes.Repositories {
		gotOrder[i] = r.Location
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("expected canonical sorted locations %v, got %v", wantOrder, gotOrder)
	}

	// 3. Authenticated GraphQL resolution with DefaultAccountFilter() includes private repo.
	authFullRes, err := NewResolver(ResolveOptions{
		GitHubGraphQLEndpoint: gqlSrv.URL,
		Token:                 "good-token",
	}).Resolve(context.Background(), ref, DefaultAccountFilter())
	if err != nil {
		t.Fatalf("authenticated full resolution failed: %v", err)
	}
	if len(authFullRes.Repositories) != 4 {
		t.Fatalf("expected 4 repos (3 public + 1 private), got %d: %+v", len(authFullRes.Repositories), authFullRes.Repositories)
	}

	// 4. Glob filtering: ExcludeNames takes precedence over IncludeNames.
	globFilter := DefaultAccountFilter()
	globFilter.IncludeNames = []string{"*-*"}
	globFilter.ExcludeNames = []string{"beta-*"}
	globRes, err := NewResolver(ResolveOptions{
		GitHubGraphQLEndpoint: gqlSrv.URL,
		Token:                 "good-token",
	}).Resolve(context.Background(), ref, globFilter)
	if err != nil {
		t.Fatalf("glob resolution failed: %v", err)
	}
	if len(globRes.Repositories) != 1 || globRes.Repositories[0].Name != "secret-core" {
		t.Fatalf("expected only secret-core after include/exclude globs, got %+v", globRes.Repositories)
	}
	if globRes.ExcludedCounts["excludeNames"] != 1 {
		t.Fatalf("expected excludeNames count=1, got %v", globRes.ExcludedCounts)
	}

	// 5. Invalid explicit token -> ErrInvalidCredential (never silent fallback).
	_, err = NewResolver(ResolveOptions{
		GitHubGraphQLEndpoint: gqlSrv.URL,
		GitHubRESTBaseURL:     restSrv.URL,
		Token:                 "bad-token",
	}).Resolve(context.Background(), ref, DefaultAccountFilter())
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential on 401, got %v", err)
	}
}

func TestCapRateLimitAndNonAdvancingErrors(t *testing.T) {
	// 1. Cap exceeded -> ErrTooManyRepositories (never truncates).
	capSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/users/bigorg" {
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "Organization"})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "r1", "clone_url": "https://github.com/bigorg/r1.git"},
			{"name": "r2", "clone_url": "https://github.com/bigorg/r2.git"},
			{"name": "r3", "clone_url": "https://github.com/bigorg/r3.git"},
		})
	}))
	defer capSrv.Close()

	_, err := NewResolver(ResolveOptions{
		GitHubRESTBaseURL: capSrv.URL,
		AnonymousOnly:     true,
		MaxRepos:          2,
	}).Resolve(context.Background(), AccountRef{Provider: "github", Login: "bigorg"}, DefaultAccountFilter())
	if !errors.Is(err, ErrTooManyRepositories) {
		t.Fatalf("expected ErrTooManyRepositories, got %v", err)
	}

	// 2. Anonymous rate limit -> ErrRateLimited recommending authentication.
	rlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(30*time.Minute).Unix()))
		http.Error(w, "API rate limit exceeded", http.StatusForbidden)
	}))
	defer rlSrv.Close()

	_, err = NewResolver(ResolveOptions{
		GitHubRESTBaseURL: rlSrv.URL,
		AnonymousOnly:     true,
	}).Resolve(context.Background(), AccountRef{Provider: "github", Login: "any"}, DefaultAccountFilter())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if !strings.Contains(err.Error(), "60/hour") || !strings.Contains(err.Error(), "token") {
		t.Fatalf("anonymous rate-limit error must recommend authentication, got: %v", err)
	}

	// 3. Non-advancing pagination link -> ErrNonAdvancingProgress (terminates).
	var loopSrv *httptest.Server
	loopSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/users/loopy" {
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "User"})
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/users/loopy/repos?page=2>; rel="next"`, loopSrv.URL))
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "r1", "clone_url": "https://github.com/loopy/r1.git"},
		})
	}))
	defer loopSrv.Close()

	_, err = NewResolver(ResolveOptions{
		GitHubRESTBaseURL: loopSrv.URL,
		AnonymousOnly:     true,
	}).Resolve(context.Background(), AccountRef{Provider: "github", Login: "loopy"}, DefaultAccountFilter())
	if !errors.Is(err, ErrNonAdvancingProgress) {
		t.Fatalf("expected ErrNonAdvancingProgress, got %v", err)
	}
}

type stubConfigManager struct {
	cfg *gitutils.GitServiceConfig
}

func (m stubConfigManager) GetConfig() (*gitutils.GitServiceConfig, error) { return m.cfg, nil }
func (m stubConfigManager) SaveConfig(*gitutils.GitServiceConfig) error    { return nil }

func TestCredentialLookupErrors(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CHECKMATE_GIT_TOKEN", "")

	// Missing explicit ServiceID -> ErrInvalidCredential (never anonymous fallback).
	emptyCfg := &gitutils.GitServiceConfig{
		GitServices: map[gitutils.GitServiceType]map[string]*gitutils.GitService{},
	}
	_, err := NewResolver(ResolveOptions{
		ConfigManager: stubConfigManager{cfg: emptyCfg},
	}).Resolve(context.Background(), AccountRef{Provider: "github", Login: "acme", ServiceID: "missing-id"}, DefaultAccountFilter())
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected ErrInvalidCredential for missing ServiceID, got %v", err)
	}

	// Multiple GitHub services without explicit ServiceID -> ErrAmbiguousService.
	ambiguousCfg := &gitutils.GitServiceConfig{
		GitServices: map[gitutils.GitServiceType]map[string]*gitutils.GitService{
			gitutils.GitHub: {
				"svc-1": {ID: "svc-1", Type: gitutils.GitHub, API_Key: "tok-1"},
				"svc-2": {ID: "svc-2", Type: gitutils.GitHub, API_Key: "tok-2"},
			},
		},
	}
	_, err = NewResolver(ResolveOptions{
		ConfigManager: stubConfigManager{cfg: ambiguousCfg},
	}).Resolve(context.Background(), AccountRef{Provider: "github", Login: "acme"}, DefaultAccountFilter())
	if !errors.Is(err, ErrAmbiguousService) {
		t.Fatalf("expected ErrAmbiguousService when multiple GitHub services match, got %v", err)
	}
}
