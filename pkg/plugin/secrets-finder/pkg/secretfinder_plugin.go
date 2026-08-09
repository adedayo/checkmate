package secrets

import (
	"context"
	"os"
	"sort"

	diagnostics "github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// FinderPlugin is the plugin interface to the CheckMate Secret Finder module
// type FinderPlugin struct {
// 	model.CheckMatePluginInterface
// }

//GetPluginMetadata returns the plugin metadata
// func (sfp *FinderPlugin) GetPluginMetadata() (*pb.PluginMetadata, error) {
// 	var path string
// 	if exe, err := os.Executable(); err == nil {
// 		path = exe
// 	}
// 	return &pb.PluginMetadata{
// 		Description: "CheckMate's secrets-in-code detection plugin",
// 		Name:        "Secrets Finder",
// 		Id:          "secrets-finder",
// 		Path:        path,
// 	}, nil
// }

// //Scan runs the static analysis scan to find secrets in code and configuration files
// func (sfp *FinderPlugin) Scan(req *pb.ScanRequest, stream pb.PluginService_ScanServer) error {

// 	container := diagnostics.ExcludeContainer{
// 		ExcludeDef: model.ConvertExcludeDefinition(req.Excludes),
// 		Repositories:/**empty repository locations*/ []string{},
// 	}
// 	wl, err := diagnostics.CompileExcludes(container)
// 	if err != nil {
// 		return err
// 	}
// 	diags, paths := SearchSecretsOnPaths(req.PathsToScan, SecretSearchOptions{
// 		ShowSource:            req.ShowSource,
// 		Exclusions:            wl,
// 		ConfidentialFilesOnly: req.ConfidentialFilesOnly,
// 		CalculateChecksum:     req.CalculateChecksum,
// 	})
// 	for diagnostic := range diags {
// 		if err := stream.Send(model.ConvertSecurityDiagnostic(diagnostic)); err != nil {
// 			return err
// 		}
// 	}
// 	<-paths
// 	return nil
// }

// SearchSecretsOnPaths searches for secrets on indicated paths (may include local paths and git repositories)
// Streams back security diagnostics and paths
func SearchSecretsOnPaths(paths []string, options SecretSearchOptions) (chan *diagnostics.SecurityDiagnostic, chan []util.RepositoryIndexedFile) {
	return SearchSecretsOnPathsWithProgress(paths, options, "", "", nil)
}

// SearchSecretsOnPathsWithProgress is SearchSecretsOnPaths with progress
// reporting.
//
// It exists because callers that drive a scan directly through this function
// rather than through SecretScanner.Scan — the SQLite store, most importantly —
// had no way to report progress at all, and so reported none. A nil callback
// makes this exactly equivalent to SearchSecretsOnPaths, which is what the CLI
// and SDK paths pass.
//
// Progress is coalesced onto the same ticker used everywhere else (see
// progress.go); it is deliberately not emitted per file, because on a large
// corpus that is a callback storm fanning out to WebSocket and database writes.
func SearchSecretsOnPathsWithProgress(paths []string, options SecretSearchOptions,
	projectID, scanID string,
	progressCallback func(diagnostics.Progress)) (chan *diagnostics.SecurityDiagnostic, chan []util.RepositoryIndexedFile) {
	out := make(chan *diagnostics.SecurityDiagnostic)
	pathsOut := make(chan []util.RepositoryIndexedFile)

	//Git URLs are cloned concurrently and each root is scanned as soon as it
	//is available; local paths need no acquisition and go first. Indices come
	//from the caller's argument order, so a finding's repository no longer
	//depends on which of two independently-randomised map iterations happened
	//to agree — which is what decided it before.
	ctx := context.Background()
	registry, roots := acquirePaths(ctx, paths, options)

	//transpose rewrites a diagnostic's location from the local checkout back
	//to the repository it came from, and tags it with whatever the clone told
	//us about that repository.
	//
	//It used to be registered as the finders' diagnostic consumer, which meant
	//it ran on whichever goroutine happened to be broadcasting and had to
	//stash its output in a mutex-guarded map keyed by location, to be picked
	//up again once the file finished. The pool already returns findings
	//grouped by file, so the map, the mutex and the possibility of a
	//diagnostic whose location never matched its file's — and which therefore
	//stayed in that map until the process exited — all go away together.
	transpose := repoTagger(registry)

	//Coalesced onto a ticker rather than emitted per file. A nil callback
	//yields a reporter that counts but emits nothing, so the non-progress
	//callers pay only the counter.
	reporter := newProgressReporter(projectID, scanID,
		resolveProgressInterval(options), progressCallback)

	go func() {
		allFiles := []util.RepositoryIndexedFile{}
		defer func() {
			//Close emits the final, exact completion event. It must run before
			//the caller observes the paths channel closing, since that is the
			//signal callers use to treat the scan as finished.
			reporter.Close()
			//clean downloaded repositories
			for _, location := range registry.cloneLocations() {
				_ = os.RemoveAll(location)
			}
			close(out)
			pathsOut <- allFiles
			close(pathsOut)
		}()

		//This signature promises the caller the full file list, so the slice
		//has to be accumulated. Streaming still buys the important half:
		//scanning starts on the first file instead of after the last
		//directory has been read. Phase 8 addresses the accumulation itself.
		files, walkStats := util.WalkRoots(ctx, roots, util.WalkOptions{
			PruneDirs: exclusionPruneDirs(options.Exclusions),
		})

		//The total is not known until the walk finishes, so it is the running
		//discovered count and becomes exact when it does. The reporter clamps
		//it up to the position so progress can never exceed 100%.
		statsDone := make(chan struct{})
		go func() {
			defer close(statsDone)
			for s := range walkStats {
				reporter.SetTotal(s.DiscoveredSoFar)
			}
		}()

		runScanPipeline(ctx, options, files, func(result fileScanResult) {
			allFiles = append(allFiles, result.File)

			//Completion, not commencement — see FileDone. Recorded for every
			//file, including those with no findings, or the count would track
			//findings rather than work done.
			reporter.FileDone(result.File.File)

			if len(result.Diagnostics) == 0 {
				return
			}

			for _, d := range result.Diagnostics {
				transpose(d)
			}

			for _, d := range diagnostics.SubsumeOverlapping(result.Diagnostics) {
				out <- d
			}
		})

		//Wait for the stats goroutine before the deferred Close emits the
		//final event, so the total it reports is the exact one.
		<-statsDone

		//Files complete in whichever order the pool finishes them, so the list
		//is sorted before it is handed over. Callers treat it as the set of
		//files scanned, but it is also what the perf harness counts and what a
		//caller could reasonably persist, and a set that reorders itself
		//between identical runs is a diff nobody can act on.
		sort.Slice(allFiles, func(i, j int) bool {
			if allFiles[i].RepositoryIndex != allFiles[j].RepositoryIndex {
				return allFiles[i].RepositoryIndex < allFiles[j].RepositoryIndex
			}
			return allFiles[i].File < allFiles[j].File
		})
	}()

	return out, pathsOut
}
