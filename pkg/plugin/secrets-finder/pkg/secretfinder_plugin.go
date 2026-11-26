package secrets

import (
	"context"
	"os"
	"sort"

	diagnostics "github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
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
	out, pathsOut, _ := SearchSecretsOnPathsWithReport(context.Background(), paths, options, projectID, scanID, progressCallback)
	return out, pathsOut
}

// SearchSecretsOnPathsWithReport is SearchSecretsOnPathsWithProgress that also
// accepts a context and returns a single-element buffered channel delivering
// the scan's AcquisitionReport when the scan completes.
func SearchSecretsOnPathsWithReport(ctx context.Context, paths []string, options SecretSearchOptions,
	projectID, scanID string,
	progressCallback func(diagnostics.Progress)) (chan *diagnostics.SecurityDiagnostic, chan []util.RepositoryIndexedFile, <-chan gitutils.AcquisitionReport) {
	if ctx == nil {
		ctx = context.Background()
	}
	out := make(chan *diagnostics.SecurityDiagnostic)
	pathsOut := make(chan []util.RepositoryIndexedFile)
	reportOut := make(chan gitutils.AcquisitionReport, 1)

	registry, roots := acquirePaths(ctx, paths, options)
	transpose := repoTagger(registry)

	reporter := newProgressReporter(projectID, scanID,
		resolveProgressInterval(options), progressCallback)

	go func() {
		allFiles := []util.RepositoryIndexedFile{}
		defer func() {
			reporter.Close()
			acqReport := registry.acquisitionReport()
			if options.OnAcquisitionComplete != nil {
				options.OnAcquisitionComplete(acqReport)
			}
			// Only delete temporary checkouts when KeepCheckouts is false.
			if !options.KeepCheckouts {
				for _, location := range registry.cloneLocations() {
					_ = os.RemoveAll(location)
				}
			}
			reportOut <- acqReport
			close(reportOut)
			close(out)
			pathsOut <- allFiles
			close(pathsOut)
		}()

		files, walkStats := util.WalkRoots(ctx, roots, util.WalkOptions{
			PruneDirs:        exclusionPruneDirs(options.Exclusions),
			RespectGitIgnore: options.RespectGitIgnore,
			TrackedOnly:      options.TrackedOnly,
			OnRootError: func(root string, err error) {
				registry.recordFailure(root, err)
			},
		})

		statsDone := make(chan struct{})
		go func() {
			defer close(statsDone)
			for s := range walkStats {
				reporter.SetTotal(s.DiscoveredSoFar)
			}
		}()

		runScanPipeline(ctx, options, files, func(result fileScanResult) {
			allFiles = append(allFiles, result.File)

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

		<-statsDone

		sort.Slice(allFiles, func(i, j int) bool {
			if allFiles[i].RepositoryIndex != allFiles[j].RepositoryIndex {
				return allFiles[i].RepositoryIndex < allFiles[j].RepositoryIndex
			}
			return allFiles[i].File < allFiles[j].File
		})
	}()

	return out, pathsOut, reportOut
}
