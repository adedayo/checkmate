package utils

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/gitservice/github"
	"github.com/adedayo/checkmate/pkg/gitservice/gitlab"
)

func GitRepositoryStatusChecker(ctx context.Context, pm projects.ProjectManager, repo *projects.Repository) (*projects.Repository, error) {

	if repo != nil {
		cm, err := pm.GetGitConfigManager()
		if err != nil {
			return repo, err
		}
		configService, err := cm.GetConfig()
		if err != nil {
			return repo, err
		}
		gitService, err := configService.FindService(repo.GitServiceID)
		if err != nil {
			return repo, err
		}
		loc := repo.Location

		if strings.Contains(strings.ToLower(loc), "gitlab") {
			//process GitLab repository attributes
			proj, err := gitlab.GetGitLabRepositoryStatus(ctx, gitService, repo)
			if err != nil {
				return repo, err
			}
			if repo.Attributes == nil {
				repo.Attributes = &map[string]interface{}{"archived": proj.Archived}
			} else {
				(*repo.Attributes)["archived"] = proj.Archived
			}

		} else if strings.Contains(strings.ToLower(loc), "github") {
			//process GitHub repository attributes
			proj, err := github.GetGitHubRepositoryStatus(ctx, gitService, repo)
			if err != nil {
				return repo, err
			}
			if repo.Attributes == nil {
				repo.Attributes = &map[string]interface{}{"archived": proj.IsArchived, "disabled": proj.IsDisabled}
			} else {
				(*repo.Attributes)["archived"] = proj.IsArchived
				(*repo.Attributes)["disabled"] = proj.IsDisabled
			}
		} else {
			log.Printf("trying to read repository property of a git repository that I can't determine whether it is GitHub or GitLab")
			return repo, errors.New("only github and gitlab currently supported")
		}

	} else {
		return repo, errors.New("nil repository")
	}

	return repo, nil
}
