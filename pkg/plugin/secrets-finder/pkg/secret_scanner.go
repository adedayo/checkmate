package secrets

import (
	"context"
	"os"

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

	//Progress is coalesced onto a ticker rather than emitted per file — see
	//progress.go. The callback contract is unchanged, so the API, WebSocket,
	//SSE and desktop-app consumers are untouched.
	reporter := newProgressReporter(projectID, scanID,
		resolveProgressInterval(scanner.options), progressCallback)
	defer reporter.Close()

	//Repositories are acquired concurrently and enter the pipeline one by one
	//as each clone lands, so scanning overlaps cloning instead of following
	//it. Indices are fixed before any clone starts, so what a finding says
	//about its repository does not depend on which clone won the race.
	registry, roots := acquireRepositories(ctx, &proj, pm, repoStatusChecker,
		scanner.options, reporter)

	//a diagnostics collect function that fixes location for git repositories
	//and multiplexes the diagnostic to all provided diagnostic consumers.
	//
	//Called only from the pipeline's sink goroutine, so the downstream
	//consumers keep the single-producer contract they were written against.
	tag := repoTagger(registry)
	transposePathsToRepoBaseDiagnosticConsumer := func(diagnostic *diagnostics.SecurityDiagnostic) {
		tag(diagnostic)
		for _, consumer := range consumers {
			consumer.ReceiveDiagnostic(diagnostic)
		}
	}

	//we are now ready to scan for secrets

	//1. stream the files to scan, rather than materialising the whole list
	//first. On a large estate that list was the single largest allocation in
	//the scan, and nothing could be scanned until the last directory had been
	//read.
	files, walkStats := util.WalkRoots(ctx, roots, util.WalkOptions{
		//Prune subtrees the operator's own exclusions have provably removed
		//from the scan, so an excluded tree costs one predicate call rather
		//than one rejection per file inside it. Nothing is pruned unless the
		//exclusion provider can prove every file beneath is excluded.
		PruneDirs: exclusionPruneDirs(scanner.options.Exclusions),
	})

	//The total is not known until the walk finishes, so it is the running
	//discovered count and becomes exact when it does. The reporter clamps it
	//up to the position so progress can never exceed 100%, and its final event
	//is exact regardless.
	reporter.Reset()
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		for s := range walkStats {
			reporter.SetTotal(s.DiscoveredSoFar)
		}
	}()

	//2. scan them across the worker pool.
	runScanPipeline(ctx, scanner.options, files, func(result fileScanResult) {
		f, _, _ := registry.transpose(result.File)
		reporter.FileDone(f)

		for _, d := range result.Diagnostics {
			transposePathsToRepoBaseDiagnosticConsumer(d)
		}
	})

	<-statsDone

	//The deferred reporter.Close emits the final, exact completion event.

	//3. cleanup: delete checked out repositories if required
	if proj.DeleteCheckedOutCode {
		for _, location := range registry.cloneLocations() {
			_ = os.RemoveAll(location)
		}
	}
}

func MakeSecretScanner(config SecretSearchOptions) SecretScanner {
	return SecretScanner{
		options: config,
	}
}

type repoCloneAndDetail struct {
	CloneDetail gitutils.CloneDetail
	Repository  *projects.Repository
	//isClone marks a root CheckMate checked out itself and may therefore
	//delete afterwards. A local filesystem root is the user's own directory,
	//and deleting it would be catastrophic.
	isClone bool
}
