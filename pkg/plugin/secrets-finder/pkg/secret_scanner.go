package secrets

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/core/util"
)

type SecretScanner struct {
	options SecretSearchOptions
}

func (scanner SecretScanner) Scan(ctx context.Context, projectID string, scanID string, pm projects.ProjectManager, repoStatusChecker projects.RepositoryStatusChecker,
	progressCallback func(diagnostics.Progress), consumers ...diagnostics.SecurityDiagnosticsConsumer) {

	//ensure project and scan config exist
	proj, err := pm.GetProject(projectID)
	if err != nil {
		return // no such project
	}

	scanConfig, err := pm.GetScanConfig(projectID, scanID)
	if err != nil {
		return //no such scan configuration
	}

	container := diagnostics.ExcludeContainer{
		ExcludeDef: &scanConfig.Policy,
	}

	for _, loc := range proj.Repositories {
		container.Repositories = append(container.Repositories, loc.Location)
	}

	if excl, err := diagnostics.CompileExcludes(container); err == nil {
		scanner.options.Exclusions = excl
	}

	if o, present := scanConfig.Config["secret-search-options"]; present {
		if opts, ok := o.(SecretSearchOptions); ok {
			scanner.options = opts
		}
	}

	//get paths and check out repositories as may be necessary
	repositories, local := cloneRepositories(ctx, &proj, scanID, pm,
		repoStatusChecker, progressCallback)

	paths, locID := toPathsandLocationIDs(local, repositories)

	//reverse map local (temporary code checkout) paths to git URLs
	// repoMapper := make(map[string]string)
	// for repo, path := range repositories {
	// 	paths = append(paths, path)
	// 	repoMapper[path] = repo
	// }

	transposePath := locationTransposer(paths, locID)

	//a diagnostics collect function that fixes location for git repositories
	//and multiplexes the diagnostic to all provided diagnostic consumers
	transposePathsToRepoBaseDiagnosticConsumer := func(diagnostic *diagnostics.SecurityDiagnostic) {
		location, branch, cloneDetail := transposePath(util.RepositoryIndexedFile{
			RepositoryIndex: diagnostic.RepositoryIndex,
			File:            *diagnostic.Location})
		diagnostic.Location = &location

		//add branch as a tag, if it exists
		if branch != "" {
			diagnostic.AddTag(fmt.Sprintf("branch=%s", branch))
		}

		//add other tags from attributes found about the repository
		if cloneDetail != nil && cloneDetail.Repository != nil && cloneDetail.Repository.Attributes != nil {
			attrs := *cloneDetail.Repository.Attributes
			for k, v := range attrs {
				diagnostic.AddTag(fmt.Sprintf("%s=%v", k, v))
			}
		}

		for _, consumer := range consumers {
			consumer.ReceiveDiagnostic(diagnostic)
		}
	}

	//set up secret finders as path consumers
	size := 1
	if !scanner.options.ConfidentialFilesOnly {
		size = 2
	}

	pathConsumers := make([]util.PathConsumer, 0, size)

	//we always do confidential files search
	pathConsumers = append(pathConsumers, &confidentialFilesFinder{
		ExclusionProvider: scanner.options.Exclusions,
		options:           scanner.options,
	})

	if !scanner.options.ConfidentialFilesOnly {
		pathConsumers = append(pathConsumers, &pathBasedSourceSecretFinder{
			showSource:        scanner.options.ShowSource,
			ExclusionProvider: scanner.options.Exclusions,
			options:           scanner.options,
		})
	}
	//multiplex the path consumers
	mux := util.NewPathMultiplexer(pathConsumers...)

	//these path consumers are security diagnostic providers
	diagnosticProviders := []diagnostics.SecurityDiagnosticsProvider{}
	for _, c := range pathConsumers {
		diagnosticProviders = append(diagnosticProviders, c.(diagnostics.SecurityDiagnosticsProvider))
	}

	//next call connects the diagnostic output of the providers to the
	//diagnostic consumers provided to this function
	common.RegisterDiagnosticsConsumer(transposePathsToRepoBaseDiagnosticConsumer, diagnosticProviders...)

	//we are now ready to scan for secrets

	//1. search for files to scan
	// log.Printf("Searching for files")
	allFiles := util.FindFiles(paths)
	fileCount := len(allFiles)

	//2. scan them (mux.ConsumePath), sending progress indicators
	for index, rif := range allFiles {
		f, _, _ := transposePath(rif)
		progress := diagnostics.Progress{
			ProjectID:   projectID,
			ScanID:      scanID,
			CurrentFile: f,
			Position:    int64(index + 1),
			Total:       int64(fileCount),
		}
		progressCallback(progress)
		mux.ConsumePath(rif)
	}

	//3. cleanup: delete checked out repositories if required
	if proj.DeleteCheckedOutCode {
		for _, r := range repositories {
			os.RemoveAll(r.CloneDetail.Location)
		}
	}
}

// create a location ID for each repository/local path
// align paths[id] to the corresponding loc[id] map
func toPathsandLocationIDs(local []string, repositories map[string]repoCloneAndDetail) ([]string, map[int]repoCloneAndDetail) {
	paths := make([]string, len(local)+len(repositories))

	locID := make(map[int]repoCloneAndDetail)
	id := 0
	for _, p := range local {
		locID[id] = repoCloneAndDetail{
			CloneDetail: gitutils.CloneDetail{
				Location:   p,
				Repository: p,
			},
		}
		paths[id] = p
		id++
	}
	for _, detail := range repositories {
		locID[id] = detail
		paths[id] = detail.CloneDetail.Location
		id++
	}
	return paths, locID
}

func locationTransposer(paths []string, locID map[int]repoCloneAndDetail) func(util.RepositoryIndexedFile) (transposedLocation, branch string, cloneDetail *repoCloneAndDetail) {

	return func(location util.RepositoryIndexedFile) (string, string, *repoCloneAndDetail) {
		transposedLocation := location.File
		branch := ""
		var cd *repoCloneAndDetail
		if repo, exists := locID[location.RepositoryIndex]; exists {
			cd = &repo
			if location.RepositoryIndex < len(paths) {
				localPath := paths[location.RepositoryIndex]
				if repo.CloneDetail.Branch != nil {
					branch = *repo.CloneDetail.Branch
				}
				transposedLocation = strings.Replace(transposedLocation, localPath, repo.CloneDetail.Repository, 1)
			}
		}
		return transposedLocation, branch, cd
	}
}

func MakeSecretScanner(config SecretSearchOptions) SecretScanner {
	return SecretScanner{
		options: config,
	}
}

// cloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
// and the second argument are non-git local paths
func cloneRepositories(ctx context.Context, project *projects.Project, scanID string, pm projects.ProjectManager,
	statusChecker projects.RepositoryStatusChecker, progressMonitor func(diagnostics.Progress)) (map[string]repoCloneAndDetail, []string) {

	repoMap := make(map[string]repoCloneAndDetail)
	local := []string{}
	repositories := project.Repositories
	gitConfig := &gitutils.GitServiceConfig{
		GitServices: make(map[gitutils.GitServiceType]map[string]*gitutils.GitService),
	}

	confManager, err := pm.GetGitConfigManager()
	if err == nil {
		if conf, err := confManager.GetConfig(); err == nil {
			gitConfig = conf
		} else {
			log.Printf("Error getting Config service: %v", err)

		}
	} else {
		log.Printf("Error getting DB Config manager: %v", err)
	}

	repoCount := int64(len(repositories))
	for i, p := range repositories {
		switch p.LocationType {
		case "filesystem":
			local = append(local, p.Location)
		case "git":
			if _, present := repoMap[p.Location]; !present {
				options := &gitutils.GitCloneOptions{
					BaseDir: path.Join(pm.GetCodeBaseDir(), project.ID),
					Depth:   1, //shallow
				}
				if service, err := gitConfig.FindService(p.GitServiceID); err == nil {
					options.Auth = service.MakeAuth()
				} else {
					log.Printf("Error finding Git service: %v, Project: %#v", err, p)
				}
				progressMonitor(diagnostics.Progress{
					ProjectID:   project.ID,
					ScanID:      scanID,
					Position:    int64(i),
					Total:       repoCount,
					CurrentFile: fmt.Sprintf("cloning repository %s", p.Location),
				})
				//make a call to the git server API to check the status of this repo, e.g. archived, disabled etc.
				rp, err := statusChecker(ctx, pm, &p)
				if err != nil {
					rp = &p
				}
				if repo, err := gitutils.Clone(ctx, p.Location, options); err == nil {
					repoMap[p.Location] = repoCloneAndDetail{
						Repository:  rp,
						CloneDetail: repo,
					}
				} else {
					repoMap[p.Location] = repoCloneAndDetail{
						Repository:  rp,
						CloneDetail: repo,
					}
					log.Printf("%v", err)
				}
			}
		default:
			//ignore any other types of repos
		}
	}
	return repoMap, local
}

type repoCloneAndDetail struct {
	CloneDetail gitutils.CloneDetail
	Repository  *projects.Repository
}
