package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
)

func TestGetRepositories_PropagatesMidPaginationError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"user": map[string]any{
						"repositories": map[string]any{
							"nodes": []map[string]any{
								{"name": "repo-a", "id": "1", "url": "https://github.com/alice/repo-a"},
							},
							"totalCount": 2,
							"pageInfo": map[string]any{
								"endCursor":   "cursor-1",
								"hasNextPage": true,
							},
						},
					},
				},
			})
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := &gitutils.GitService{
		GraphQLEndPoint: srv.URL,
		API_Key:         "test-token",
		AccountName:     "alice",
		AccountType:     "User",
	}

	projs, _, err := GetRepositories(context.Background(), svc, &GitHubPagedSearch{
		PageSize: 10,
		First:    1,
	})
	if err == nil {
		t.Fatalf("expected mid-pagination error to propagate, got nil (projects=%v)", projs)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 requests before failing, got %d", calls.Load())
	}
}
