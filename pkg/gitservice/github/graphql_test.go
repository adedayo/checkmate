package github

import (
	"context"
	"fmt"
	"log"
	"testing"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
)

func TestQueryProjects(t *testing.T) {

	// Create a context
	ctx := context.Background()

	// Create a mock GitService with the mock server URL and API key
	gitService := &gitutils.GitService{
		GraphQLEndPoint: "https://api.github.com/graphql",
		API_Key:         "",
	}

	repo := &projects.Repository{
		Location:     "https://github.com/adedayo/checkmate.git",
		LocationType: "git",
	}

	owner, name := getRepositoryOwnerAndName(repo.Location)

	// Call the function under test
	query := fmt.Sprintf(singleProjectQuery, owner, name)

	log.Printf("Query: %s", query)

	projects, err := searchProject(ctx, query, gitService)
	if err != nil {
		log.Printf("Error in queryProjects: %s", err)
		t.Errorf("Error in queryProjects: %s", err)
	}

	log.Printf("Projects: %v", projects)

	// Verify the result
	// expectedResult := projectsQueryResultGH{
	// 	Nodes: []GitHubProject{},
	// }
	// if !equal(projects, expectedResult) {
	// 	t.Errorf("Expected projects %v, got %v", expectedResult, projects)
	// }
}

// Helper function to compare the projectsQueryResultGH
// func equal(a, b projectsQueryResultGH) bool {
// 	aJSON, err := json.Marshal(a)
// 	if err != nil {
// 		return false
// 	}
// 	bJSON, err := json.Marshal(b)
// 	if err != nil {
// 		return false
// 	}
// 	return strings.Compare(string(aJSON), string(bJSON)) == 0
// }
