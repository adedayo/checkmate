package util

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ErrNotGitRepository is returned when a Git-only operation (such as
// TrackedOnly walking) targets a path outside a Git worktree or when git is
// unavailable.
var ErrNotGitRepository = errors.New("target is not inside a Git repository")

type cachedGitRoot struct {
	root string
	err  error
}

type gitRootCache struct {
	mu      sync.RWMutex
	entries map[string]cachedGitRoot
}

func newGitRootCache() *gitRootCache {
	return &gitRootCache{
		entries: make(map[string]cachedGitRoot),
	}
}

func (c *gitRootCache) resolve(ctx context.Context, dir string) (string, error) {
	key := dir
	if abs, err := filepath.Abs(dir); err == nil {
		key = abs
	}
	if c != nil {
		c.mu.RLock()
		entry, ok := c.entries[key]
		c.mu.RUnlock()
		if ok {
			return entry.root, entry.err
		}
	}

	root, err := gitWorktreeRootForDir(ctx, key)

	if c != nil {
		c.mu.Lock()
		c.entries[key] = cachedGitRoot{root: root, err: err}
		c.mu.Unlock()
	}
	return root, err
}

// GitWorktreeRoot resolves the canonical Git worktree root containing path.
// If path is a regular file, its parent directory is queried. Returns an error
// wrapping ErrNotGitRepository when path is outside a Git worktree or git is
// not available.
func GitWorktreeRoot(ctx context.Context, path string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dir := path
	if dir == "" {
		dir = "."
	}
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotGitRepository, err)
	}
	return gitWorktreeRootForDir(ctx, absDir)
}

func gitWorktreeRootForDir(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("%w: %s", ErrNotGitRepository, dir)
	}
	top := strings.TrimSpace(stdout.String())
	if top == "" {
		return "", fmt.Errorf("%w: %s", ErrNotGitRepository, dir)
	}
	return evalSymlinksIfPossible(top), nil
}

func evalSymlinksIfPossible(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

func (w *walker) reportRootError(root string, err error) {
	if w.opts.OnRootError != nil && err != nil {
		w.opts.OnRootError(root, err)
	}
}

func (w *walker) walkGitAwareRoot(root string, info os.FileInfo) {
	if !info.IsDir() {
		// Explicit regular file target:
		// - Under RespectGitIgnore (without TrackedOnly), NEVER skip explicit
		//   file targets due to .gitignore.
		// - Under TrackedOnly, verify the file is tracked in the Git index.
		if !w.opts.TrackedOnly {
			w.emit(root)
			return
		}
		dir := filepath.Dir(root)
		repoRoot, err := w.gitCache.resolve(w.ctx, dir)
		if err != nil {
			w.reportRootError(root, fmt.Errorf("%w: %s", ErrNotGitRepository, root))
			return
		}
		if w.isGitTrackedFile(repoRoot, root) {
			w.emit(root)
		}
		return
	}

	repoRoot, err := w.gitCache.resolve(w.ctx, root)
	if err != nil {
		if w.ctx.Err() != nil {
			return
		}
		if w.opts.TrackedOnly {
			w.reportRootError(root, fmt.Errorf("%w: %s", ErrNotGitRepository, root))
			return
		}
		// Non-Git directory under RespectGitIgnore: fall back cleanly to
		// standard filesystem walking so non-Git audits never drop files.
		w.markVisited(info)
		w.walkDir(root, 0)
		return
	}

	w.walkGitDir(root, repoRoot, info)
}

func (w *walker) isGitTrackedFile(repoRoot, filePath string) bool {
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}
	// Resolve symlinks on the parent directory (handles macOS /var -> /private/var)
	// without dereferencing a symlinked file itself.
	canonicalParent := evalSymlinksIfPossible(filepath.Dir(absFile))
	canonicalFile := filepath.Join(canonicalParent, filepath.Base(absFile))
	realRepoRoot := evalSymlinksIfPossible(repoRoot)

	rel, err := filepath.Rel(realRepoRoot, canonicalFile)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}

	cmd := exec.CommandContext(w.ctx, "git", "-C", realRepoRoot, "ls-files", "--error-unmatch", "--", filepath.ToSlash(rel))
	return cmd.Run() == nil
}

func (w *walker) walkGitDir(root, repoRoot string, rootInfo os.FileInfo) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		if !w.opts.TrackedOnly {
			w.markVisited(rootInfo)
			w.walkDir(root, 0)
		} else {
			w.reportRootError(root, err)
		}
		return
	}
	realRoot := evalSymlinksIfPossible(absRoot)
	realRepoRoot := evalSymlinksIfPossible(repoRoot)

	relTarget, err := filepath.Rel(realRepoRoot, realRoot)
	if err != nil || relTarget == ".." || strings.HasPrefix(relTarget, ".."+string(filepath.Separator)) {
		if !w.opts.TrackedOnly {
			w.markVisited(rootInfo)
			w.walkDir(root, 0)
		} else {
			w.reportRootError(root, fmt.Errorf("%w: %s", ErrNotGitRepository, root))
		}
		return
	}

	args := []string{"-C", realRepoRoot, "-c", "core.quotepath=false", "ls-files", "-z", "--cached"}
	if !w.opts.TrackedOnly {
		args = append(args, "--others", "--exclude-standard")
	}
	if relTarget != "." && relTarget != "" {
		args = append(args, "--", filepath.ToSlash(relTarget))
	}

	cmd := exec.CommandContext(w.ctx, "git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		if !w.opts.TrackedOnly {
			w.markVisited(rootInfo)
			w.walkDir(root, 0)
		} else {
			w.reportRootError(root, err)
		}
		return
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		if !w.opts.TrackedOnly {
			w.markVisited(rootInfo)
			w.walkDir(root, 0)
		} else {
			w.reportRootError(root, err)
		}
		return
	}

	reader := bufio.NewReaderSize(stdout, 64*1024)
	emittedAny := false
	prevPath := ""

	for {
		if w.ctx.Err() != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return
		}

		entry, readErr := reader.ReadString('\x00')
		if len(entry) > 0 {
			relFromRepo := strings.TrimSuffix(entry, "\x00")
			if relFromRepo != "" {
				relFromRepoOS := filepath.FromSlash(relFromRepo)
				var relFromTarget string
				if relTarget == "." || relTarget == "" {
					relFromTarget = relFromRepoOS
				} else {
					r, relErr := filepath.Rel(relTarget, relFromRepoOS)
					if relErr != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
						relFromTarget = ""
					} else {
						relFromTarget = r
					}
				}

				if relFromTarget != "" && relFromTarget != "." {
					fullPath := filepath.Join(root, relFromTarget)
					// Suppress consecutive duplicate entries (e.g. unmerged
					// merge-conflict stages 1/2/3 in git ls-files --cached).
					if fullPath != prevPath {
						prevPath = fullPath
						if !w.isGitPathPruned(root, relFromTarget) {
							if st, stErr := os.Lstat(fullPath); stErr == nil && !st.IsDir() {
								emittedAny = true
								w.emit(fullPath)
							}
						}
					}
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			break
		}
	}

	waitErr := cmd.Wait()
	if waitErr != nil && w.ctx.Err() == nil {
		if w.opts.TrackedOnly {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg != "" {
				w.reportRootError(root, fmt.Errorf("git ls-files failed for %s: %s: %w", root, errMsg, waitErr))
			} else {
				w.reportRootError(root, fmt.Errorf("git ls-files failed for %s: %w", root, waitErr))
			}
			return
		}
		if !emittedAny {
			w.markVisited(rootInfo)
			w.walkDir(root, 0)
		}
	}
}

func (w *walker) isGitPathPruned(root, relFromTarget string) bool {
	if w.opts.PruneDirs == nil {
		return false
	}
	dir := filepath.Dir(relFromTarget)
	if dir == "." || dir == "" {
		return false
	}
	parts := strings.Split(filepath.ToSlash(dir), "/")
	cur := root
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if w.opts.PruneDirs(cur, part) {
			return true
		}
	}
	return false
}
