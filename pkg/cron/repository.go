package scheduler

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	gitutils "github.com/adedayo/checkmate-core/pkg/git"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

//Track monitored projects, check for new commits, if any, run a scan of all projects that have that repository
func updateCommitDBs(ctx context.Context, pm projects.ProjectManager, callback func(projID string, data interface{}), config Config) {

	if cm, err := pm.GetGitConfigManager(); err == nil {
		if gsc, err := cm.GetConfig(); err == nil {
			for _, ps := range pm.ListProjectSummaries() {
				if !ps.IsBeingScanned { //skip currently-being-scanned-projects
					processProjectSummary(ctx, ps, pm, gsc, callback, config)
				}
			}
		}
	}
}

func processProjectSummary(ctx context.Context, ps *projects.ProjectSummary, pm projects.ProjectManager,
	gsc *gitutils.GitServiceConfig, callback func(projID string, data interface{}), config Config) {
	/*
		For each monitored git repo
		1. check commits across brances
		2. scan latest head branch, if not previously scanned
	*/

	hasChanged := false
	for _, repo := range ps.Repositories {
		if repo.Monitor && repo.IsGit() {
			var auth *gitutils.GitAuth
			if gitService, err := gsc.FindService(repo.GitServiceID); err == nil {
				auth = gitService.MakeAuth()
			}

			//checkout commits newer than those already noted
			if commits := CheckLatestCommits(ctx, gitutils.RepositoryCloneSpec{
				Repository: repo.Location,
				ServiceID:  repo.GitServiceID,
				Options: gitutils.GitCloneOptions{
					BaseDir: pm.GetCodeBaseDir(),
					Auth:    auth,
				},
			}, ps.GetLastCommitByBranch(repo.Location)); len(commits) > 0 {
				// if there are newer commits across any branch
				//update the commit histories across branches in the project summary
				if ps.ScanAndCommitHistories == nil {
					ps.ScanAndCommitHistories = make(map[string]map[string]projects.RepositoryHistory)
				}
				for branch, c := range commits {
					if hist, exists := ps.ScanAndCommitHistories[repo.Location]; exists {
						if old, exists := hist[branch]; exists {
							old.CommitHistories = append(old.CommitHistories, c...)
							hist[branch] = old
						} else {
							hist[branch] = projects.RepositoryHistory{
								ScanHistories:   []projects.ScanHistory{},
								CommitHistories: c,
								Repository:      repo,
							}
						}
						ps.ScanAndCommitHistories[repo.Location] = hist
					} else {
						ps.ScanAndCommitHistories[repo.Location] = map[string]projects.RepositoryHistory{
							branch: {
								ScanHistories:   []projects.ScanHistory{},
								CommitHistories: c,
								Repository:      repo,
							},
						}
					}
				}
				hasChanged = true
			}
		}

		if hasChanged {
			// save project summary
			pm.SaveProjectSummary(ps)
			//determine which commits to auto-scan, and launch scan job
			scanNextUnscannedBranch(ctx, ps, pm, callback, config)
		}
	}
}

func scanNextUnscannedBranch(ctx context.Context, ps *projects.ProjectSummary,
	pm projects.ProjectManager, callback func(projID string, data interface{}), config Config) {

	configManager := &gitutils.GitServiceConfig{
		GitServices: make(map[gitutils.GitServiceType]map[string]*gitutils.GitService),
	}
	if g, err := pm.GetGitConfigManager(); err == nil {
		if gcm, err := g.GetConfig(); err == nil {
			configManager = gcm
		}
	}

	for _, repo := range ps.Repositories {
		if repo.IsGit() && repo.Monitor {
			var hashToScan string
			scansByBranch := ps.GetScansByBranch(repo.Location)
			commits := ps.GetLastCommitByBranch(repo.Location)
			out := make(map[string][]gitutils.Commit)
			for branch, com := range commits {
				if scannedCommits, exist := scansByBranch[branch]; exist && len(com) > 0 {
					commit := com[0]
					commitHasBeenScanned := false
					for _, c := range scannedCommits {
						if c.Hash == commit.Hash {
							//we've scanned this commit
							commitHasBeenScanned = true
							break
						}
					}
					if !commitHasBeenScanned {
						if cc, exist := out[branch]; exist {
							out[branch] = append(cc, commit)
						} else {
							out[branch] = []gitutils.Commit{commit}
						}
					}
				}
			}

			//we have unscanned branches for this repo.
			//if one of the branches is the head, scan that, else, pick the most recent non-head branch for scanning
			headCommits := []gitutils.Commit{}
			otherCommits := []gitutils.Commit{}
			for _, v := range out {
				for _, c := range v {
					if c.IsHead {
						headCommits = append(headCommits, c)
					} else {
						otherCommits = append(otherCommits, c)
					}
				}
			}

			if len(headCommits) > 0 {
				//we've got some unscanned head commits
				sort.SliceStable(headCommits, func(i, j int) bool {
					a := headCommits[i].Time
					b := headCommits[j].Time
					return a.After(b) || a.Equal(b)
				})
				hashToScan = headCommits[0].Hash
			} else {
				//scan any other commits
				if len(otherCommits) > 0 && config.ScanOlderCommits {
					sort.SliceStable(otherCommits, func(i, j int) bool {
						a := otherCommits[i].Time
						b := otherCommits[j].Time
						return a.After(b) || a.Equal(b)
					})
					hashToScan = otherCommits[0].Hash
				}
			}

			//do not scan if no specific hash is identified
			if hashToScan == "" {
				return
			}

			auth := &gitutils.GitAuth{}
			if gitService, err := configManager.FindService(repo.GitServiceID); err == nil {
				auth = gitService.MakeAuth()
			}
			//clone the commit of interest
			gitutils.Clone(ctx, repo.Location, &gitutils.GitCloneOptions{
				BaseDir:    pm.GetCodeBaseDir(),
				CommitHash: hashToScan,
				Auth:       auth,
			})

			runScan(ctx, ps, pm, callback)
		}
	}
}

func runScan(ctx context.Context, ps *projects.ProjectSummary, pm projects.ProjectManager, callback func(projID string, data interface{})) {

	//scanID consumer <- scanID is generated by the scanner
	scanIDC := func(sID string) {
		//not needed
	}

	paths := []string{}
	progressMon := func(progress diagnostics.Progress) {
		paths = append(paths, progress.CurrentFile)
		callback(ps.ID, progress)
	}

	secOptions := secrets.SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        diagnostics.MakeEmptyExcludes(),
	}

	project, err := pm.GetProject(ps.ID)
	if err != nil {
		return
	}

	if options, ok := project.ScanPolicy.Config["secret-search-options"]; ok {
		if scanOpts, good := options.(secrets.SecretSearchOptions); good {
			secOptions = scanOpts
			excludes := secrets.MergeExclusions(project.ScanPolicy.Policy, secrets.MakeCommonExclusions())
			container := diagnostics.ExcludeContainer{
				ExcludeDef: &excludes,
			}
			for _, loc := range project.Repositories {
				container.Repositories = append(container.Repositories, loc.Location)
			}
			if excl, err := diagnostics.CompileExcludes(container); err == nil {
				secOptions.Exclusions = excl
			}
		}
	}

	summariser := func(projID, sID string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {
		model := projects.GenerateModel(len(paths), secOptions.ShowSource, issues)
		summary := model.Summarise()
		project, err := pm.GetProject(projID) //reloading project as policies might have been manually changed during scanning
		if err != nil {
			return summary
		}
		callback(projID, project)
		callback(projID, summary)
		return summary
	}

	pm.RunScan(ctx, ps.ID, project.ScanPolicy, secrets.MakeSecretScanner(secOptions), scanIDC,
		progressMon, summariser, projects.SimpleWorkspaceSummariser, noopConsumer{})

}

type noopConsumer struct {
}

func (n noopConsumer) ReceiveDiagnostic(*diagnostics.SecurityDiagnostic) {

}

//Checkout latest commits and return commits newer than provided list of commits per branch
func CheckLatestCommits(ctx context.Context, repo gitutils.RepositoryCloneSpec, branchCommits map[string][]gitutils.Commit) map[string][]gitutils.Commit {

	out := make(map[string][]gitutils.Commit)

	/*
		1. First clone the repository
		2. If all goes well, open the repository and retrieve all commits across branches
		3. return the list of commits newer than the provided per-branch list
	*/
	if dir, err := gitutils.Clone(ctx, gitToHTTPS(repo.Repository), &gitutils.GitCloneOptions{
		BaseDir: repo.Options.BaseDir,
		Auth:    repo.Options.Auth,
	}); err == nil {
		if gitRepo, err := git.PlainOpen(dir); err == nil {
			var head, headBranch string
			if h, err := gitRepo.Head(); err == nil {
				head = h.Hash().String()
				headBranch = h.Name().Short()
			}
			if refs, err := gitRepo.References(); err == nil {
				refs.ForEach(func(ref *plumbing.Reference) error {
					if ref.Name().IsRemote() {
						if cIter, err := gitRepo.Log(&git.LogOptions{
							From:  ref.Hash(), //branch indicator
							Order: git.LogOrderCommitterTime,
						}); err == nil {
							branch := strings.TrimPrefix(ref.Name().Short(), "origin/")
							commitsExist := hasCommitInBranch(branch, branchCommits)
							cIter.ForEach(func(c *object.Commit) error {
								if !commitsExist || c.Author.When.After(branchCommits[branch][0].Time) {
									hash := c.Hash.String()
									commit := gitutils.Commit{
										Hash:   hash,
										Branch: branch,
										Author: gitutils.Author{
											Name:  c.Author.Name,
											Email: c.Author.Email,
										},
										Time:   c.Author.When,
										IsHead: head == hash && headBranch == branch,
									}
									if cs, exists := out[branch]; exists {
										out[branch] = append(cs, commit)
									} else {
										out[branch] = []gitutils.Commit{commit}
									}
								}

								if commitsExist && c.Author.When.Before(branchCommits[branch][0].Time) {
									//since we ordered by commit time, short-circuit once we hit an older commit
									return errors.New("")
								}
								//next commit
								return nil
							})
						}
					}
					//next branch
					return nil
				})
			}
		}
	}
	return out
}

func hasCommitInBranch(branch string, branchCommits map[string][]gitutils.Commit) bool {
	if commits, exists := branchCommits[branch]; exists && len(commits) > 0 {
		return true
	}
	return false
}

func gitToHTTPS(repo string) string {
	repo = strings.TrimSpace(repo)
	if strings.HasPrefix(repo, "git@") {
		return strings.ReplaceAll(strings.ReplaceAll(repo, ":", "/"), "git@", "https://")
	}

	return repo
}
