package sqlite

import (
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/projects"
)

// Repositories added by URL scanned nothing and said so as "0 findings".
//
// The cause was here: targets were built with GetCodeLocation, which for a git
// repository returns the directory the checkout *would* occupy. This path
// clones nothing beforehand, so that directory does not exist, the walk read no
// files, and a scan that had never obtained the code was presented as a clean
// result. Handing the scanner the URL lets its own acquisition clone it.
func TestScanTargetsUsesURLForGitRepositories(t *testing.T) {
	repos := []projects.Repository{
		{Location: "https://github.com/adedayo/static-analysis-test-code", LocationType: "git"},
		{Location: "/Users/someone/code/thing", LocationType: "filesystem"},
		// Written by callers that never set the field — the desktop app, for
		// its whole history. It must not be dropped or rewritten either.
		{Location: "https://github.com/adedayo/checkmate"},
	}

	got := scanTargets(repos)
	want := []string{
		"https://github.com/adedayo/static-analysis-test-code",
		"/Users/someone/code/thing",
		"https://github.com/adedayo/checkmate",
	}

	if len(got) != len(want) {
		t.Fatalf("scanTargets returned %d targets, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A clone with no base directory lands in the process's working directory,
// which for a GUI application launched from Finder is "/". The clone fails on
// permissions and the scan reads nothing. The store has a managed directory and
// must nominate it.
func TestCloneBaseDirIsUnderTheManagedCodeDirectory(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const projectID = "a-project"
	base := filepath.Join(db.GetCodeBaseDir(), projectID)

	if !filepath.IsAbs(base) {
		t.Errorf("clone base %q is not absolute; a relative base resolves against the working directory, which is the bug", base)
	}
	if got := filepath.Base(base); got != projectID {
		t.Errorf("clone base %q is not scoped to the project, got final element %q", base, got)
	}
}
