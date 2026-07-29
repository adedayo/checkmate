package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
)

func TestQueryProjects(t *testing.T) {

	// Create a context
	ctx := context.Background()

	// Create a mock GitService with the mock server URL and API key
	gitService := &gitutils.GitService{
		GraphQLEndPoint: "https://gitlab.com/api/graphql",
		API_Key:         "",
	}

	repo := &projects.Repository{
		Location:     "https://gitlab.com/WilbertX/conference-go-docker.git",
		LocationType: "git",
	}

	// Call the function under test
	query := fmt.Sprintf(singleProjectQuery, getRepositoryName(repo.Location))

	log.Printf("Query: %s", query)

	projects, err := queryProjects(ctx, query, gitService)
	if err != nil {
		t.Errorf("Error in queryProjects: %s", err)
	}

	log.Printf("Projects: %v", projects)

	// Verify the result
	expectedResult := projectsQueryResult{
		Nodes: []GitLabProject{},
	}
	if !equal(projects, expectedResult) {
		t.Errorf("Expected projects %v, got %v", expectedResult, projects)
	}
}

// Helper function to compare the projectsQueryResult
func equal(a, b projectsQueryResult) bool {
	aJSON, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bJSON, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return strings.Compare(string(aJSON), string(bJSON)) == 0
}
