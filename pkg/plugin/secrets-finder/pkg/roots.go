package secrets

// Repository acquisition.
//
// # What was wrong with cloning in a loop
//
// Acquisition used to be a `for` loop over the project's repositories calling
// gitutils.Clone one at a time, and *nothing* was scanned until the last one
// returned. Cloning is almost entirely network latency, so the loop spent its
// life blocked on a socket with every core idle, and the total was the sum of
// every repository's clone time rather than the slowest of them. On an estate
// of a few hundred repositories that is minutes of doing nothing before the
// first file is read.
//
// Two changes fix it: clones run concurrently under a bound, and each
// repository is handed to the walker the moment its own clone completes rather
// than waiting for its slowest sibling. Local filesystem paths need no
// acquisition at all, so they are released first and are typically already
// being scanned while the first clone is still in progress.
//
// # Why indices are assigned before any cloning starts
//
// Every finding carries a RepositoryIndex, and that index is the only thing
// mapping it back to the repository it came from — the transposer uses it to
// rewrite a local checkout path into the repository URL, and to attach the
// branch and repository attribute tags.
//
// Assigning indices in completion order would therefore make findings
// attributable to whichever repository happened to clone fastest, which varies
// run to run with network weather. Two identical scans would produce findings
// tagged with different repositories, and nothing in the output would show
// which was right. So indices come from the project's ordered repository list,
// fixed before the first clone starts.
//
// This also repairs an existing defect on the CLI path, where the transposer
// was built from a map iteration while the walk roots were built from a second
// map iteration — Go randomises those independently, so the two orders could
// disagree and findings could be transposed against the wrong repository.

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// defaultCloneConcurrency bounds simultaneous clones.
const defaultCloneConcurrency = 4

// resolveCloneConcurrency applies option, then environment, then the default.
// As with the other tuning knobs, an unusable value is ignored rather than
// fatal.
func resolveCloneConcurrency(options SecretSearchOptions) int {
	if options.CloneConcurrency > 0 {
		return options.CloneConcurrency
	}

	if v, ok := os.LookupEnv("CHECKMATE_CLONE_CONCURRENCY"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}

	return defaultCloneConcurrency
}

// rootRegistry maps a RepositoryIndex to what is known about that root.
//
// Slots are written by the acquisition goroutines and read by the scan's sink
// goroutine, hence the atomic pointers. A mutex would do as well, but the
// access pattern is genuinely write-once-then-read-many: a slot is filled
// before its root is offered to the walker, so no read can ever observe an
// unfilled slot for a file that exists.
type rootRegistry struct {
	entries []atomic.Pointer[repoCloneAndDetail]
}

func newRootRegistry(size int) *rootRegistry {
	return &rootRegistry{entries: make([]atomic.Pointer[repoCloneAndDetail], size)}
}

func (r *rootRegistry) set(index int, detail repoCloneAndDetail) {
	if index < 0 || index >= len(r.entries) {
		return
	}
	r.entries[index].Store(&detail)
}

func (r *rootRegistry) get(index int) *repoCloneAndDetail {
	if index < 0 || index >= len(r.entries) {
		return nil
	}
	return r.entries[index].Load()
}

// cloneLocations lists the on-disk checkouts of the git repositories acquired,
// for callers that delete the code after scanning. Local filesystem roots are
// excluded — they are the user's own directories, and removing them would be
// catastrophic.
func (r *rootRegistry) cloneLocations() []string {
	locations := []string{}
	for i := range r.entries {
		if d := r.entries[i].Load(); d != nil && d.isClone {
			locations = append(locations, d.CloneDetail.Location)
		}
	}
	return locations
}

// transpose rewrites a file's location from the local checkout back to the
// repository it came from, and reports what else is known about that
// repository. Behaviour is unchanged from the previous locationTransposer: a
// single prefix replacement, and an unknown index passes through untouched.
func (r *rootRegistry) transpose(location util.RepositoryIndexedFile) (string, string, *repoCloneAndDetail) {
	transposed := location.File
	branch := ""

	detail := r.get(location.RepositoryIndex)
	if detail == nil {
		return transposed, branch, nil
	}

	if detail.CloneDetail.Branch != nil {
		branch = *detail.CloneDetail.Branch
	}
	if detail.CloneDetail.Location != "" {
		transposed = strings.Replace(transposed, detail.CloneDetail.Location,
			detail.CloneDetail.Repository, 1)
	}

	return transposed, branch, detail
}

// acquireRepositories fixes each repository's index, then acquires them
// concurrently, publishing each root as soon as it is ready.
//
// The returned channel is closed once every root has been published. The
// registry is only fully populated at that point, but each individual entry is
// populated before its root is published, which is the guarantee the scan
// actually depends on.
func acquireRepositories(ctx context.Context, project *projects.Project, pm projects.ProjectManager,
	statusChecker projects.RepositoryStatusChecker, options SecretSearchOptions,
	reporter *progressReporter) (*rootRegistry, <-chan util.IndexedRoot) {

	repositories := project.Repositories
	registry := newRootRegistry(len(repositories))
	//Buffered to the full root count so publication never blocks on the
	//walker: an acquisition goroutine's job is to hand over and take the next
	//clone, not to wait for a directory to be read.
	roots := make(chan util.IndexedRoot, len(repositories))

	gitConfig := &gitutils.GitServiceConfig{
		GitServices: make(map[gitutils.GitServiceType]map[string]*gitutils.GitService),
	}
	if confManager, err := pm.GetGitConfigManager(); err == nil {
		if conf, err := confManager.GetConfig(); err == nil {
			gitConfig = conf
		} else {
			log.Printf("Error getting Config service: %v", err)
		}
	} else {
		log.Printf("Error getting DB Config manager: %v", err)
	}

	type cloneJob struct {
		index int
		repo  projects.Repository
	}
	jobs := []cloneJob{}
	seen := make(map[string]struct{}, len(repositories))

	for i, p := range repositories {
		switch p.LocationType {
		case "filesystem":
			//Published immediately: there is nothing to acquire, so this tree
			//is scanned while the clones are still running.
			registry.set(i, repoCloneAndDetail{
				CloneDetail: gitutils.CloneDetail{Location: p.Location, Repository: p.Location},
			})
			roots <- util.IndexedRoot{Index: i, Path: p.Location}
		case "git":
			//The same URL listed twice is one repository, as before. The
			//duplicate simply gets no root; its index stays empty, which is
			//harmless because no file will ever carry it.
			if _, present := seen[p.Location]; present {
				continue
			}
			seen[p.Location] = struct{}{}
			jobs = append(jobs, cloneJob{index: i, repo: p})
		default:
			//ignore any other types of repos
		}
	}

	go func() {
		defer close(roots)

		if len(jobs) == 0 {
			return
		}

		concurrency := resolveCloneConcurrency(options)
		if concurrency > len(jobs) {
			concurrency = len(jobs)
		}

		total := int64(len(jobs))
		var completed atomic.Int64
		var wg sync.WaitGroup
		sem := make(chan struct{}, concurrency)

		for _, job := range jobs {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(job cloneJob) {
				defer wg.Done()
				defer func() { <-sem }()

				p := job.repo
				cloneOptions := &gitutils.GitCloneOptions{
					BaseDir: path.Join(pm.GetCodeBaseDir(), project.ID),
					//Shallow. Secret scanning of a *filesystem* checkout only
					//ever reads the working tree, so the history is bytes
					//downloaded and never opened. History scanning is a
					//separate concern driven by the git service layer, and
					//asks for its own depth.
					Depth: 1,
				}
				if service, err := gitConfig.FindService(p.GitServiceID); err == nil {
					cloneOptions.Auth = service.MakeAuth()
				} else {
					log.Printf("Error finding Git service: %v, Project: %#v", err, p)
				}

				reporter.Note(fmt.Sprintf("cloning repository %s", p.Location),
					completed.Load(), total)

				//Ask the git server about the repository — archived, disabled
				//and so on.
				rp, err := statusChecker(ctx, pm, &p)
				if err != nil {
					rp = &p
				}

				clone, err := gitutils.Clone(ctx, p.Location, cloneOptions)
				if err != nil {
					//Registered and published anyway, exactly as before: Clone
					//returns the intended location even on failure, an
					//unreadable root contributes no files, and one
					//unreachable repository must not abort the scan of the
					//rest.
					log.Printf("%v", err)
				}

				registry.set(job.index, repoCloneAndDetail{
					Repository:  rp,
					CloneDetail: clone,
					isClone:     true,
				})
				roots <- util.IndexedRoot{Index: job.index, Path: clone.Location}

				reporter.Note(fmt.Sprintf("cloned repository %s", p.Location),
					completed.Add(1), total)
			}(job)
		}

		wg.Wait()
	}()

	return registry, roots
}

// acquirePaths is acquireRepositories for the CLI and SDK path, where roots
// arrive as a plain list of local paths and git URLs and there is no project
// configuration, no authentication and no status checking.
func acquirePaths(ctx context.Context, paths []string, options SecretSearchOptions) (*rootRegistry, <-chan util.IndexedRoot) {
	registry := newRootRegistry(len(paths))
	roots := make(chan util.IndexedRoot, len(paths))

	type cloneJob struct {
		index int
		url   string
	}
	jobs := []cloneJob{}
	seen := make(map[string]struct{}, len(paths))

	for i, p := range paths {
		if !gitURL.MatchString(p) {
			registry.set(i, repoCloneAndDetail{
				CloneDetail: gitutils.CloneDetail{Location: p, Repository: p},
			})
			roots <- util.IndexedRoot{Index: i, Path: p}
			continue
		}
		if _, present := seen[p]; present {
			continue
		}
		seen[p] = struct{}{}
		jobs = append(jobs, cloneJob{index: i, url: p})
	}

	go func() {
		defer close(roots)

		if len(jobs) == 0 {
			return
		}

		concurrency := resolveCloneConcurrency(options)
		if concurrency > len(jobs) {
			concurrency = len(jobs)
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, concurrency)

		for _, job := range jobs {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(job cloneJob) {
				defer wg.Done()
				defer func() { <-sem }()

				clone, err := gitutils.Clone(ctx, job.url, &gitutils.GitCloneOptions{Depth: 1})
				if err != nil {
					//Unlike the project path this one does not publish a root
					//on failure, matching what this entry point has always
					//done: a URL that could not be cloned is simply not
					//scanned.
					log.Printf("Failed to clone repository %s: %s\n", job.url, err.Error())
					return
				}

				registry.set(job.index, repoCloneAndDetail{CloneDetail: clone, isClone: true})
				roots <- util.IndexedRoot{Index: job.index, Path: clone.Location}
			}(job)
		}

		wg.Wait()
	}()

	return registry, roots
}

// repoTagger returns the consumer-side rewrite applied to every diagnostic:
// local checkout path back to repository URL, plus the branch and repository
// attribute tags. Both entry points need it and both had their own copy.
func repoTagger(registry *rootRegistry) func(*diagnostics.SecurityDiagnostic) {
	return func(diagnostic *diagnostics.SecurityDiagnostic) {
		if diagnostic.Location == nil {
			return
		}

		location, branch, detail := registry.transpose(util.RepositoryIndexedFile{
			RepositoryIndex: diagnostic.RepositoryIndex,
			File:            *diagnostic.Location,
		})
		diagnostic.Location = &location

		if branch != "" {
			diagnostic.AddTag(fmt.Sprintf("branch=%s", branch))
		}

		if detail != nil && detail.Repository != nil && detail.Repository.Attributes != nil {
			for k, v := range *detail.Repository.Attributes {
				diagnostic.AddTag(fmt.Sprintf("%s=%v", k, v))
			}
		}
	}
}
