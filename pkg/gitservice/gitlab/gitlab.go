package gitlab

import (
	"context"
	"fmt"
	"log"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
)

func GetRepositories(ctx context.Context, gLab *gitutils.GitService, pagedSearch *GitLabPagedSearch) (projects []GitLabProject, loc GitLabCursorLocation, err error) {

	if pagedSearch.First < 1 {
		pagedSearch.First = 7 //conservatively push up the number of projects retrieved if they forgot to set First parameter
	}
	for len(projects) < pagedSearch.PageSize {
		query := fmt.Sprintf(projectsQuery, pagedSearch.First, pagedSearch.NextCursor)
		projs, err := queryProjects(ctx, query, gLab)
		if err != nil {
			log.Printf("Error: %v\n", err)
			break
		} else {
			loc.EndCursor = projs.PageInfo.EndCursor
			loc.HasNextPage = projs.PageInfo.HasNextPage
			projects = append(projects, projs.Nodes...)
			if !loc.HasNextPage {
				break
			}
			pagedSearch.NextCursor = loc.EndCursor
		}
	}

	return
}

func GetGitLabRepositoryStatus(ctx context.Context, gLab *gitutils.GitService, repo *projects.Repository) (project GitLabProject, err error) {

	query := fmt.Sprintf(singleProjectQuery, getRepositoryName(repo.Location))
	projs, err := queryProjects(ctx, query, gLab)

	for _, glp := range projs.Nodes {
		if glp.HttpUrlToRepo == repo.Location {
			project = glp
			return
		}
	}

	return
}

type GitLabPagedSearch struct {
	ServiceID  string
	PageSize   int
	First      int //(first: n, ...) in the query
	NextCursor string
}

type GitLabCursorLocation struct {
	EndCursor   string
	HasNextPage bool
}
