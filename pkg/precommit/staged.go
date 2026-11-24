package precommit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
)

// LineRange is a 1-based inclusive line interval [Start, End].
type LineRange struct {
	Start int64
	End   int64
}

// StagedEntry describes one staged file from `git diff --cached --raw -z`.
type StagedEntry struct {
	Path    string
	BlobSHA string
	Status  byte // 'A', 'M', 'C', 'T'
	Mode    string
}

// StagedScanOptions configures staged Git index scanning.
type StagedScanOptions struct {
	WorkDir               string
	DiffOnly              bool
	ShowSource            bool
	CalculateChecksum     bool
	ExcludeTestFiles      bool
	ConfidentialFilesOnly bool
	ReportIgnored         bool
	Verbose               bool
	Exclusions            diagnostics.ExclusionProvider
	ExclusionOptions      *ExclusionOptions
}

// ReaderScanOptions configures scanning a single io.Reader (such as stdin).
type ReaderScanOptions struct {
	Filename              string
	ShowSource            bool
	CalculateChecksum     bool
	ExcludeTestFiles      bool
	ConfidentialFilesOnly bool
	Exclusions            diagnostics.ExclusionProvider
}

// ScanResult holds the findings and summary metrics of a pre-commit scan.
type ScanResult struct {
	RepoRoot     string
	FilesScanned int
	Diagnostics  []*diagnostics.SecurityDiagnostic
	Duration     time.Duration
}

// RepoRoot resolves the top-level directory of the Git repository containing dir.
// For standard repositories (a .git directory on disk and no GIT_DIR/GIT_WORK_TREE
// overrides), it walks upward in pure Go (~50us) to avoid spawning a git
// subprocess on every pre-commit invocation, falling back to
// `git rev-parse --show-toplevel` for worktrees, submodules, or custom Git env.
func RepoRoot(ctx context.Context, dir string) (string, error) {
	if os.Getenv("GIT_DIR") == "" && os.Getenv("GIT_WORK_TREE") == "" {
		startDir := dir
		if startDir == "" {
			if wd, err := os.Getwd(); err == nil {
				startDir = wd
			}
		}
		if startDir != "" {
			if abs, err := filepath.Abs(startDir); err == nil {
				cur := abs
				for {
					gitPath := filepath.Join(cur, ".git")
					if info, err := os.Stat(gitPath); err == nil {
						if info.IsDir() {
							// Resolve symlinks to match `git rev-parse --show-toplevel`.
							if resolved, err := filepath.EvalSymlinks(cur); err == nil {
								return resolved, nil
							}
							return cur, nil
						}
						// .git is a file (worktree/submodule) -> defer to git rev-parse.
						break
					}
					parent := filepath.Dir(cur)
					if parent == cur {
						break
					}
					cur = parent
				}
			}
		}
	}

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("not inside a git repository: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("failed to locate git repository root: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ScanStaged scans files staged in the Git index without reading working-tree
// edits. When no files are staged it returns immediately without initialising
// the scan engine or loading exclusions.
func ScanStaged(ctx context.Context, opts StagedScanOptions) (*ScanResult, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}

	repoRoot, err := RepoRoot(ctx, opts.WorkDir)
	if err != nil {
		return nil, err
	}

	entries, err := listStagedEntries(ctx, repoRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return &ScanResult{
			RepoRoot:     repoRoot,
			FilesScanned: 0,
			Diagnostics:  []*diagnostics.SecurityDiagnostic{},
			Duration:     time.Since(start),
		}, nil
	}

	exclusions := opts.Exclusions
	if exclusions == nil {
		if opts.ExclusionOptions != nil {
			exOpts := *opts.ExclusionOptions
			if exOpts.RepoRoot == "" {
				exOpts.RepoRoot = repoRoot
			}
			exclusions, err = LoadExclusions(exOpts)
			if err != nil {
				return nil, err
			}
		} else {
			exclusions, err = LoadExclusions(ExclusionOptions{
				RepoRoot:     repoRoot,
				AutoDiscover: true,
			})
			if err != nil {
				return nil, err
			}
		}
	}

	// Filter excluded paths before fetching blobs or diff hunks.
	active := make([]StagedEntry, 0, len(entries))
	hasModified := false
	for _, entry := range entries {
		absPath := filepath.Join(repoRoot, filepath.FromSlash(entry.Path))
		if exclusions != nil && (exclusions.ShouldExcludePath(entry.Path) || exclusions.ShouldExcludePath(absPath)) {
			continue
		}
		if opts.ExcludeTestFiles && isSuspectedTestPath(entry.Path) {
			continue
		}
		if entry.Status == 'M' {
			hasModified = true
		}
		active = append(active, entry)
	}

	if len(active) == 0 {
		return &ScanResult{
			RepoRoot:     repoRoot,
			FilesScanned: 0,
			Diagnostics:  []*diagnostics.SecurityDiagnostic{},
			Duration:     time.Since(start),
		}, nil
	}

	var addedHunks map[string][]LineRange
	if opts.DiffOnly && hasModified {
		addedHunks, err = stagedAddedLineRanges(ctx, repoRoot)
		if err != nil {
			return nil, err
		}
	}

	blobs, err := batchReadStagedBlobs(ctx, repoRoot, active)
	if err != nil {
		return nil, err
	}

	searchOpts := secrets.SecretSearchOptions{
		ShowSource:            opts.ShowSource,
		CalculateChecksum:     opts.CalculateChecksum,
		ConfidentialFilesOnly: opts.ConfidentialFilesOnly,
		ExcludeTestFiles:      opts.ExcludeTestFiles,
		ReportIgnored:         opts.ReportIgnored,
		Verbose:               opts.Verbose,
		Exclusions:            exclusions,
	}

	type scanJob struct {
		entry   StagedEntry
		content []byte
		skipped bool
	}
	jobs := make([]scanJob, len(active))
	for i, e := range active {
		b := blobs[i]
		jobs[i] = scanJob{entry: e, content: b.content, skipped: b.skipped}
	}

	scanOne := func(sc *secrets.ScanContext, job scanJob) []*diagnostics.SecurityDiagnostic {
		relPath := job.entry.Path
		absPath := filepath.Join(repoRoot, filepath.FromSlash(relPath))
		var hunks []LineRange
		filterByHunks := opts.DiffOnly && job.entry.Status == 'M'
		if filterByHunks {
			hunks = addedHunks[relPath]
		}
		return scanBlob(sc, relPath, absPath, job.content, job.skipped, job.entry.Status == 'A', filterByHunks, hunks, searchOpts)
	}

	var allDiags []*diagnostics.SecurityDiagnostic
	if len(jobs) == 1 {
		sc := secrets.NewScanContext(searchOpts)
		allDiags = scanOne(sc, jobs[0])
	} else {
		workers := runtime.GOMAXPROCS(0)
		if workers > len(jobs) {
			workers = len(jobs)
		}
		if workers < 1 {
			workers = 1
		}

		perJob := make([][]*diagnostics.SecurityDiagnostic, len(jobs))
		jobCh := make(chan int, len(jobs))
		for i := range jobs {
			jobCh <- i
		}
		close(jobCh)

		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				sc := secrets.NewScanContext(searchOpts)
				for idx := range jobCh {
					if ctx.Err() != nil {
						return
					}
					perJob[idx] = scanOne(sc, jobs[idx])
				}
			}()
		}
		wg.Wait()

		for _, list := range perJob {
			allDiags = append(allDiags, list...)
		}
	}

	if allDiags == nil {
		allDiags = []*diagnostics.SecurityDiagnostic{}
	}
	diagnostics.SortDiagnosticsDeterministically(allDiags)

	return &ScanResult{
		RepoRoot:     repoRoot,
		FilesScanned: len(active),
		Diagnostics:  allDiags,
		Duration:     time.Since(start),
	}, nil
}

// ScanReader scans content read from r using filename for extension,
// confidentiality, and exclusion matching.
func ScanReader(ctx context.Context, r io.Reader, opts ReaderScanOptions) (*ScanResult, error) {
	start := time.Now()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	name := strings.TrimSpace(opts.Filename)
	if name == "" {
		name = "stdin"
	}

	exclusions := opts.Exclusions
	if exclusions != nil && exclusions.ShouldExcludePath(name) {
		return &ScanResult{
			FilesScanned: 0,
			Diagnostics:  []*diagnostics.SecurityDiagnostic{},
			Duration:     time.Since(start),
		}, nil
	}
	if opts.ExcludeTestFiles && isSuspectedTestPath(name) {
		return &ScanResult{
			FilesScanned: 0,
			Diagnostics:  []*diagnostics.SecurityDiagnostic{},
			Duration:     time.Since(start),
		}, nil
	}

	// Read up to TenMB+1 unless it's a recognised source extension.
	ext := filepath.Ext(name)
	var content []byte
	var err error
	skipped := false
	if secrets.IsRecognisedSourceExt(ext) {
		content, err = io.ReadAll(r)
	} else {
		limited := io.LimitReader(r, secrets.TenMB+1)
		content, err = io.ReadAll(limited)
		if int64(len(content)) > secrets.TenMB {
			skipped = true
			content = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed reading input: %w", err)
	}

	searchOpts := secrets.SecretSearchOptions{
		ShowSource:            opts.ShowSource,
		CalculateChecksum:     opts.CalculateChecksum,
		ConfidentialFilesOnly: opts.ConfidentialFilesOnly,
		ExcludeTestFiles:      opts.ExcludeTestFiles,
		Exclusions:            exclusions,
	}

	sc := secrets.NewScanContext(searchOpts)
	diags := scanBlob(sc, name, name, content, skipped, true, false, nil, searchOpts)
	if diags == nil {
		diags = []*diagnostics.SecurityDiagnostic{}
	}
	diagnostics.SortDiagnosticsDeterministically(diags)

	return &ScanResult{
		FilesScanned: 1,
		Diagnostics:  diags,
		Duration:     time.Since(start),
	}, nil
}

func scanBlob(
	sc *secrets.ScanContext,
	relPath, absPath string,
	content []byte,
	skippedOversized bool,
	isNewlyAdded bool,
	filterByHunks bool,
	hunks []LineRange,
	opts secrets.SecretSearchOptions,
) []*diagnostics.SecurityDiagnostic {
	var found []*diagnostics.SecurityDiagnostic
	isTest := isSuspectedTestPath(relPath)

	// 1. Confidential file check (certificates, private keys, keystores).
	// In diff-only mode, report confidential files when newly added or when
	// scanning full files; for modified confidential files that have added
	// hunks, also check them.
	if isNewlyAdded || !filterByHunks || len(hunks) > 0 {
		if evidence, isConf := secrets.CheckConfidentialBytes(relPath, content, isTest); isConf {
			providerID := "ConfidentialFiles"
			loc := relPath
			var hash *string
			if opts.CalculateChecksum && !skippedOversized {
				sum := fmt.Sprintf("%x", sha256.Sum256(content))
				hash = &sum
			}
			excluded := false
			if hash != nil && opts.Exclusions != nil {
				if opts.Exclusions.ShouldExcludeHash(*hash) ||
					opts.Exclusions.ShouldExcludeHashOnPath(relPath, *hash) ||
					opts.Exclusions.ShouldExcludeHashOnPath(absPath, *hash) {
					excluded = true
				}
			}
			if !excluded {
				issue := &diagnostics.SecurityDiagnostic{
					Location:   &loc,
					ProviderID: &providerID,
					SHA256:     hash,
					Justification: diagnostics.Justification{
						Headline: evidence,
						Reasons:  []diagnostics.Evidence{evidence},
					},
				}
				if isTest {
					issue.AddTag("test")
				}
				issue.AddTag("confidential")
				found = append(found, issue)
			}
		}
	}

	if opts.ConfidentialFilesOnly || skippedOversized || len(content) == 0 {
		return diagnostics.SubsumeOverlapping(found)
	}

	// If filtering modified files by diff hunks and no lines were added, skip
	// text scanning completely (pure deletions cannot introduce a new secret).
	if filterByHunks && len(hunks) == 0 {
		return diagnostics.SubsumeOverlapping(found)
	}

	ext := filepath.Ext(relPath)
	if !secrets.IsScannableTextPath(relPath, ext) {
		return diagnostics.SubsumeOverlapping(found)
	}

	// Extensionless files: apply the same text/plain sniff as path_processing.go.
	if ext == "" {
		sample := content
		if len(sample) > 512 {
			sample = sample[:512]
		}
		if !strings.Contains(http.DetectContentType(sample), "text/plain") {
			return diagnostics.SubsumeOverlapping(found)
		}
	}

	rif := util.RepositoryIndexedFile{RepositoryIndex: 0, File: relPath}
	// Always pass ShowSource=true into the scan context so value-based
	// exclusions can inspect issue.GetValue(); strip Source afterward if the
	// caller asked for ShowSource=false.
	diags := sc.FindSecretsInFile(rif, bytes.NewReader(content), ext, true)
	for _, issue := range diags {
		if issue == nil {
			continue
		}
		loc := relPath
		issue.Location = &loc
		if isTest {
			issue.AddTag("test")
		}
		val := issue.GetValue()
		if opts.Exclusions != nil {
			if opts.Exclusions.ShouldExclude(relPath, val) || opts.Exclusions.ShouldExclude(absPath, val) {
				continue
			}
			if issue.SHA256 != nil {
				if opts.Exclusions.ShouldExcludeHashOnPath(relPath, *issue.SHA256) ||
					opts.Exclusions.ShouldExcludeHashOnPath(absPath, *issue.SHA256) {
					continue
				}
			}
		}
		if filterByHunks && !diagnosticOverlapsHunks(issue, hunks) {
			continue
		}
		if !opts.ShowSource {
			issue.Source = nil
		}
		found = append(found, issue)
	}

	return diagnostics.SubsumeOverlapping(found)
}

func diagnosticOverlapsHunks(d *diagnostics.SecurityDiagnostic, hunks []LineRange) bool {
	if len(hunks) == 0 {
		return false
	}
	startLine := d.Range.Start.Line + 1
	endLine := d.Range.End.Line + 1
	if endLine < startLine {
		endLine = startLine
	}
	for _, h := range hunks {
		if startLine <= h.End && endLine >= h.Start {
			return true
		}
	}
	return false
}

// listStagedEntries runs a single `git diff --cached --raw -z` command to
// discover every staged added, copied, modified, or type-changed file and its
// index blob SHA without spawning per-file processes.
func listStagedEntries(ctx context.Context, repoRoot string) ([]StagedEntry, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--raw", "-z", "--no-renames", "--diff-filter=ACMR")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("git diff --cached failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("git diff --cached failed: %w", err)
	}
	return parseRawDiffZ(out), nil
}

// parseRawDiffZ parses the NUL-delimited output of
// `git diff --cached --raw -z --no-renames --diff-filter=ACMR`.
// Format: ":<oldmode> <newmode> <oldsha> <newsha> <status>\x00<path>\x00"
func parseRawDiffZ(data []byte) []StagedEntry {
	var entries []StagedEntry
	parts := bytes.Split(data, []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		meta := strings.TrimSpace(string(parts[i]))
		path := string(parts[i+1])
		if meta == "" || path == "" || !strings.HasPrefix(meta, ":") {
			continue
		}
		fields := strings.Fields(meta[1:])
		if len(fields) < 5 {
			continue
		}
		newMode := fields[1]
		newSHA := fields[3]
		status := fields[4][0]
		// Skip gitlinks (submodules) and symlinks.
		if newMode == "160000" || newMode == "120000" {
			continue
		}
		entries = append(entries, StagedEntry{
			Path:    path,
			BlobSHA: newSHA,
			Status:  status,
			Mode:    newMode,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries
}

// stagedAddedLineRanges runs a single `git diff --cached -U0` for modified
// files and extracts the 1-based inclusive line ranges added or modified in
// each file.
func stagedAddedLineRanges(ctx context.Context, repoRoot string) (map[string][]LineRange, error) {
	cmd := exec.CommandContext(ctx, "git", "-c", "core.quotepath=false",
		"diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-renames", "--diff-filter=M")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("git diff --cached -U0 failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("git diff --cached -U0 failed: %w", err)
	}
	return parseUnifiedDiffHunks(out), nil
}

// parseUnifiedDiffHunks parses unified diff output (`-U0`) into a map from
// repository-relative path to 1-based inclusive added/modified line intervals.
func parseUnifiedDiffHunks(diff []byte) map[string][]LineRange {
	result := make(map[string][]LineRange)
	var currentFile string

	scanner := bufio.NewScanner(bytes.NewReader(diff))
	// Allow very long diff lines (e.g. minified JS) without aborting hunk parsing.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			currentFile = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "+++ \"b/"):
			if unq, err := strconv.Unquote(strings.TrimPrefix(line, "+++ ")); err == nil {
				currentFile = strings.TrimPrefix(unq, "b/")
			}
		case strings.HasPrefix(line, "@@ ") && currentFile != "":
			if lr, ok := parseHunkHeader(line); ok {
				result[currentFile] = append(result[currentFile], lr)
			}
		}
	}
	return result
}

// parseHunkHeader extracts the new-side 1-based line interval from a unified
// diff header such as "@@ -10,0 +11,3 @@" or "@@ -5 +5 @@".
// Returns ok=false when count is 0 (pure deletion).
func parseHunkHeader(line string) (LineRange, bool) {
	plusIdx := strings.Index(line, " +")
	if plusIdx < 0 {
		return LineRange{}, false
	}
	rest := line[plusIdx+2:]
	endIdx := strings.IndexAny(rest, " @")
	if endIdx < 0 {
		return LineRange{}, false
	}
	spec := rest[:endIdx]
	var start, count int64
	if comma := strings.IndexByte(spec, ','); comma >= 0 {
		s, err1 := strconv.ParseInt(spec[:comma], 10, 64)
		c, err2 := strconv.ParseInt(spec[comma+1:], 10, 64)
		if err1 != nil || err2 != nil {
			return LineRange{}, false
		}
		start, count = s, c
	} else {
		s, err := strconv.ParseInt(spec, 10, 64)
		if err != nil {
			return LineRange{}, false
		}
		start, count = s, 1
	}
	if count <= 0 || start <= 0 {
		return LineRange{}, false
	}
	return LineRange{Start: start, End: start + count - 1}, true
}

type stagedBlob struct {
	content []byte
	skipped bool
}

// batchReadStagedBlobs reads all staged blobs in a single `git cat-file --batch`
// subprocess, streaming object IDs over stdin and reading exact byte counts
// from stdout.
func batchReadStagedBlobs(ctx context.Context, repoRoot string, entries []StagedEntry) ([]stagedBlob, error) {
	cmd := exec.CommandContext(ctx, "git", "cat-file", "--batch")
	cmd.Dir = repoRoot

	var stdinBuf bytes.Buffer
	for _, e := range entries {
		stdinBuf.WriteString(e.BlobSHA)
		stdinBuf.WriteByte('\n')
	}
	cmd.Stdin = &stdinBuf

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git cat-file stdout pipe: %w", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git cat-file start: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 64*1024)
	results := make([]stagedBlob, len(entries))

	for i, e := range entries {
		header, err := reader.ReadString('\n')
		if err != nil {
			_ = cmd.Wait()
			return nil, fmt.Errorf("git cat-file header for %s: %w", e.Path, err)
		}
		header = strings.TrimRight(header, "\r\n")
		fields := strings.Fields(header)
		if len(fields) < 2 {
			_ = cmd.Wait()
			return nil, fmt.Errorf("unexpected git cat-file header %q", header)
		}
		if fields[1] == "missing" {
			results[i] = stagedBlob{skipped: true}
			continue
		}
		if len(fields) < 3 {
			_ = cmd.Wait()
			return nil, fmt.Errorf("unexpected git cat-file header %q", header)
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 {
			_ = cmd.Wait()
			return nil, fmt.Errorf("invalid blob size in git cat-file header %q", header)
		}

		ext := filepath.Ext(e.Path)
		isConf, _ := common.IsConfidentialFile(e.Path)
		skipSize := size > secrets.TenMB && !secrets.IsRecognisedSourceExt(ext) && !isConf
		if skipSize {
			if _, err := io.CopyN(io.Discard, reader, size+1); err != nil {
				_ = cmd.Wait()
				return nil, fmt.Errorf("draining oversized blob %s: %w", e.Path, err)
			}
			results[i] = stagedBlob{skipped: true}
			continue
		}

		buf := make([]byte, size)
		if _, err := io.ReadFull(reader, buf); err != nil {
			_ = cmd.Wait()
			return nil, fmt.Errorf("reading blob %s: %w", e.Path, err)
		}
		// Consume the trailing '\n' emitted by `git cat-file --batch`.
		if _, err := reader.ReadByte(); err != nil {
			_ = cmd.Wait()
			return nil, fmt.Errorf("reading trailing newline for %s: %w", e.Path, err)
		}
		results[i] = stagedBlob{content: buf}
	}

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderrBuf.String())
		if msg != "" {
			return nil, fmt.Errorf("git cat-file failed: %s", msg)
		}
		return nil, fmt.Errorf("git cat-file failed: %w", err)
	}
	return results, nil
}

func isSuspectedTestPath(path string) bool {
	return strings.Contains(strings.ToLower(path), "test")
}
