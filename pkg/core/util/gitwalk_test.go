package util

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@local",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@local",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(out))
	}
}

func writeTestFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	return full
}

func relPaths(t *testing.T, root string, files []RepositoryIndexedFile) []string {
	t.Helper()
	out := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatalf("filepath.Rel(%q, %q): %v", root, f.File, err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func TestWalkFiles_RespectGitIgnoreAndTrackedOnly(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")

	// Root .gitignore with negation
	writeTestFile(t, repo, ".gitignore", ".env.*\n!.env.example\ndist/\n.temp/\nnode_modules/\n*.local\n")
	// Nested .gitignore
	writeTestFile(t, repo, "src/.gitignore", "generated/\n")
	// .git/info/exclude
	writeTestFile(t, repo, ".git/info/exclude", "private-notes.txt\n")

	// Tracked files (including one force-added despite matching .gitignore!)
	writeTestFile(t, repo, "src/app.go", "package src\n")
	writeTestFile(t, repo, ".env.example", "API_KEY=example\n")
	writeTestFile(t, repo, ".env.tracked", "SECRET=tracked_even_though_ignored\n")
	writeTestFile(t, repo, "docs/sp ace/café.txt", "unicode and spaces\n")
	writeTestFile(t, repo, "deleted-later.txt", "will be removed from disk\n")

	runGit(t, repo, "add", ".gitignore", "src/.gitignore", "src/app.go", ".env.example", "docs/sp ace/café.txt", "deleted-later.txt")
	runGit(t, repo, "add", "-f", ".env.tracked")
	runGit(t, repo, "commit", "-q", "-m", "initial")

	// Delete tracked file on disk without git rm (tests ENOENT handling).
	if err := os.Remove(filepath.Join(repo, "deleted-later.txt")); err != nil {
		t.Fatal(err)
	}

	// Untracked non-ignored files
	writeTestFile(t, repo, "src/new_untracked.go", "package src\n")
	// Untracked ignored files (root .gitignore, nested .gitignore, .git/info/exclude)
	writeTestFile(t, repo, ".env.local", "SECRET=local_dev_only\n")
	writeTestFile(t, repo, "dist/bundle.js", "console.log(1)\n")
	writeTestFile(t, repo, ".temp/cache.json", "{}\n")
	writeTestFile(t, repo, "node_modules/pkg/index.js", "module.exports = {}\n")
	writeTestFile(t, repo, "src/generated/out.go", "package gen\n")
	writeTestFile(t, repo, "private-notes.txt", "notes\n")

	// 1. RespectGitIgnore mode: tracked (even if ignored) + untracked non-ignored.
	got, _ := collect(t, []string{repo}, WalkOptions{RespectGitIgnore: true})
	rels := relPaths(t, repo, got)

	wantIncluded := []string{
		".gitignore",
		"src/.gitignore",
		"src/app.go",
		".env.example",
		".env.tracked", // tracked-but-ignored MUST still be scanned
		"docs/sp ace/café.txt",
		"src/new_untracked.go",
	}
	for _, w := range wantIncluded {
		if !containsStr(rels, w) {
			t.Errorf("RespectGitIgnore missing %q; got %v", w, rels)
		}
	}

	wantExcluded := []string{
		".env.local",
		"dist/bundle.js",
		".temp/cache.json",
		"node_modules/pkg/index.js",
		"src/generated/out.go",
		"private-notes.txt",
		"deleted-later.txt",
	}
	for _, ex := range wantExcluded {
		if containsStr(rels, ex) {
			t.Errorf("RespectGitIgnore should have skipped %q; got %v", ex, rels)
		}
	}

	// 2. TrackedOnly mode: strictly tracked existing files (skips untracked non-ignored too).
	gotTracked, _ := collect(t, []string{repo}, WalkOptions{TrackedOnly: true})
	trackedRels := relPaths(t, repo, gotTracked)
	if containsStr(trackedRels, "src/new_untracked.go") {
		t.Errorf("TrackedOnly should skip untracked file src/new_untracked.go; got %v", trackedRels)
	}
	if !containsStr(trackedRels, ".env.tracked") {
		t.Errorf("TrackedOnly must include tracked-but-ignored .env.tracked; got %v", trackedRels)
	}
	if containsStr(trackedRels, "deleted-later.txt") {
		t.Errorf("TrackedOnly must skip deleted working-tree file; got %v", trackedRels)
	}

	// 3. Subdirectory scoping preserves original root prefix and filters to subdir.
	subDir := filepath.Join(repo, "src")
	gotSub, _ := collect(t, []string{subDir}, WalkOptions{RespectGitIgnore: true})
	subRels := relPaths(t, subDir, gotSub)
	if !containsStr(subRels, "app.go") || !containsStr(subRels, "new_untracked.go") {
		t.Errorf("subdir RespectGitIgnore missing expected files; got %v", subRels)
	}
	if containsStr(subRels, "generated/out.go") {
		t.Errorf("subdir RespectGitIgnore should skip nested ignored generated/out.go; got %v", subRels)
	}

	// 4. Explicit regular file target bypasses .gitignore under RespectGitIgnore,
	//    but is checked for tracked status under TrackedOnly.
	envLocal := filepath.Join(repo, ".env.local")
	gotExplicit, _ := collect(t, []string{envLocal}, WalkOptions{RespectGitIgnore: true})
	if len(gotExplicit) != 1 || gotExplicit[0].File != envLocal {
		t.Fatalf("RespectGitIgnore must scan explicit file arg %s; got %v", envLocal, gotExplicit)
	}
	gotExplicitTrackedUntracked, _ := collect(t, []string{envLocal}, WalkOptions{TrackedOnly: true})
	if len(gotExplicitTrackedUntracked) != 0 {
		t.Fatalf("TrackedOnly must skip untracked explicit file %s; got %v", envLocal, gotExplicitTrackedUntracked)
	}
	envTracked := filepath.Join(repo, ".env.tracked")
	gotExplicitTracked, _ := collect(t, []string{envTracked}, WalkOptions{TrackedOnly: true})
	if len(gotExplicitTracked) != 1 || gotExplicitTracked[0].File != envTracked {
		t.Fatalf("TrackedOnly must scan tracked explicit file %s; got %v", envTracked, gotExplicitTracked)
	}

	// 5. PruneDirs layers on top of Git-aware walking.
	gotPruned, _ := collect(t, []string{repo}, WalkOptions{
		RespectGitIgnore: true,
		PruneDirs: func(_ string, name string) bool {
			return name == "docs"
		},
	})
	prunedRels := relPaths(t, repo, gotPruned)
	for _, r := range prunedRels {
		if strings.HasPrefix(r, "docs/") {
			t.Errorf("PruneDirs should have pruned %q", r)
		}
	}
}

func TestWalkFiles_NonGitFallbackAndTrackedOnlyError(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".gitignore", ".env.local\n")
	writeTestFile(t, dir, ".env.local", "SECRET=should_be_scanned_outside_git\n")
	writeTestFile(t, dir, "main.go", "package main\n")

	// RespectGitIgnore outside Git falls back to full filesystem walk.
	got, _ := collect(t, []string{dir}, WalkOptions{RespectGitIgnore: true})
	rels := relPaths(t, dir, got)
	if !containsStr(rels, ".env.local") {
		t.Fatalf("RespectGitIgnore outside Git must fall back and include .env.local; got %v", rels)
	}

	// TrackedOnly outside Git reports ErrNotGitRepository via OnRootError and emits nothing.
	var mu sync.Mutex
	var rootErrs []error
	gotTracked, _ := collect(t, []string{dir}, WalkOptions{
		TrackedOnly: true,
		OnRootError: func(_ string, err error) {
			mu.Lock()
			rootErrs = append(rootErrs, err)
			mu.Unlock()
		},
	})
	if len(gotTracked) != 0 {
		t.Fatalf("TrackedOnly outside Git should emit 0 files; got %v", gotTracked)
	}
	if len(rootErrs) != 1 || !errors.Is(rootErrs[0], ErrNotGitRepository) {
		t.Fatalf("expected ErrNotGitRepository, got %v", rootErrs)
	}
}

func TestWalkFiles_GitDeduplicatesMergeConflictsAndIntentToAdd(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	writeTestFile(t, repo, "shared.txt", "base\n")
	runGit(t, repo, "add", "shared.txt")
	runGit(t, repo, "commit", "-q", "-m", "base")

	runGit(t, repo, "checkout", "-q", "-b", "branch-a")
	writeTestFile(t, repo, "shared.txt", "from-a\n")
	runGit(t, repo, "commit", "-q", "-am", "a")

	runGit(t, repo, "checkout", "-q", "-")
	writeTestFile(t, repo, "shared.txt", "from-b\n")
	runGit(t, repo, "commit", "-q", "-am", "b")

	// Trigger a merge conflict so shared.txt appears in stages 1, 2, 3.
	cmd := exec.Command("git", "merge", "branch-a")
	cmd.Dir = repo
	_ = cmd.Run() // expected non-zero exit due to conflict

	// Also test intent-to-add (`git add -N`).
	writeTestFile(t, repo, "intent.txt", "intent\n")
	runGit(t, repo, "add", "-N", "intent.txt")

	got, _ := collect(t, []string{repo}, WalkOptions{RespectGitIgnore: true})
	counts := map[string]int{}
	for _, f := range got {
		counts[f.File]++
	}
	for path, c := range counts {
		if c != 1 {
			t.Errorf("expected path %q to be emitted once, got %d times", path, c)
		}
	}
	if counts[filepath.Join(repo, "shared.txt")] != 1 {
		t.Errorf("expected conflicted shared.txt once, got counts=%v", counts)
	}
	if counts[filepath.Join(repo, "intent.txt")] != 1 {
		t.Errorf("expected intent.txt once, got counts=%v", counts)
	}
}

func TestWalkFiles_GitCancellation(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	for i := 0; i < 50; i++ {
		writeTestFile(t, repo, filepath.Join("pkg", "f"+string(rune('a'+i%26))+string(rune('0'+i/26))+".go"), "package p\n")
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-q", "-m", "init")

	ctx, cancel := context.WithCancel(context.Background())
	files, stats := WalkFiles(ctx, []string{repo}, WalkOptions{RespectGitIgnore: true})
	// Read one file then cancel immediately.
	<-files
	cancel()
	for range files {
	}
	for range stats {
	}
}
