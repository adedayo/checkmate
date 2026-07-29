package github

import (
	"context"
	"fmt"
	"log"
	"strings"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
)

func GetRepositories(ctx context.Context, gHub *gitutils.GitService, pagedSearch *GitHubPagedSearch) (projects []GitHubProject, loc GitHubCursorLocation, err error) {

	if pagedSearch.First < 1 {
		pagedSearch.First = 7 //conservatively push up the number of projects retrieved if they forgot to set First parameter
	}

	accountType := "user"

	if gHub.AccountType == "Organization" {
		accountType = "organization"
	}

	for len(projects) < pagedSearch.PageSize {
		query := fmt.Sprintf(projectsQuery, accountType, gHub.AccountName, pagedSearch.First, formatCursor(pagedSearch.NextCursor))
		projs, err := queryProjects(ctx, query, gHub)
		if err != nil {
			log.Printf("Error: %v\n", err)
			break
		} else {
			loc.EndCursor = projs.PageInfo.EndCursor
			loc.HasNextPage = projs.PageInfo.HasNextPage
			loc.TotalCount = projs.TotalCount
			projects = append(projects, projs.Nodes...)
			if !loc.HasNextPage {
				break
			}
			pagedSearch.NextCursor = loc.EndCursor
		}
	}

	return
}

func formatCursor(cursor string) string {
	if cursor == "" {
		return ""
	}
	return fmt.Sprintf(`, after: "%s"`, cursor)
}

type GitHubPagedSearch struct {
	ServiceID  string
	PageSize   int
	First      int //(first: n, ...) in the query
	NextCursor string
}

type GitHubCursorLocation struct {
	EndCursor   string
	HasNextPage bool
	TotalCount  int64
}

func GetGitHubRepositoryStatus(ctx context.Context, gHub *gitutils.GitService, repo *projects.Repository) (project GitHubProject, err error) {

	owner, name := getRepositoryOwnerAndName(repo.Location)
	query := fmt.Sprintf(singleProjectQuery, owner, name)
	projs, err := searchProject(ctx, query, gHub)

	if err != nil {
		return
	}

	for _, ghp := range projs.Nodes {
		url := ghp.Url
		o, n := getRepositoryOwnerAndName(url)
		if o == owner && n == name {
			return ghp, nil
		}
	}

	return project, fmt.Errorf("cannot find GitHub project %s", repo.Location)
}

func getRepositoryOwnerAndName(repo string) (string, string) {

	owner, name := "", ""

	tokens := strings.Split(repo, "/")

	if len(tokens) > 1 {
		name = strings.TrimSuffix(tokens[len(tokens)-1], ".git")
		owner = tokens[len(tokens)-2]
	}

	return owner, name

}
