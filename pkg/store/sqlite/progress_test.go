package sqlite

// 005 — progress reporting through the SQLite store.
//
// `sqlite.DB.RunScan` accepts a `progressMonitor func(diagnostics.Progress)`
// and, before this change, never invoked it. Every caller — the WebSocket
// handler, the platform API and the cron scheduler — passes a working
// callback that was silently discarded, so the WebSocket scan summary reported
// `fileCount: 0` for every scan.
//
// Go does not error on an unused function parameter, so nothing but a test can
// detect this. These tests were written to fail against the previous
// implementation and are the reason the fix is verifiable rather than merely
// plausible.
//
// Note the assertions deliberately do NOT look at the persisted `file_count`
// column: that value is derived from the paths channel and was already correct
// while progress was entirely absent. Asserting on it would have passed both
// before and after, and proved nothing.

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
)

// progressRecorder collects progress events from any goroutine.
type progressRecorder struct {
	mu     sync.Mutex
	events []diagnostics.Progress
}

func (r *progressRecorder) record(p diagnostics.Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, p)
}

func (r *progressRecorder) snapshot() []diagnostics.Progress {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]diagnostics.Progress, len(r.events))
	copy(out, r.events)
	return out
}

// newScanFixture writes a small tree containing a couple of detectable secrets
// and returns its path plus the number of files written.
func newScanFixture(t *testing.T) (string, int) {
	t.Helper()
	dir := t.TempDir()

	files := map[string]string{
		"app.go":     "package main\n\nconst apiKey = \"AKIAIOSFODNN7EXAMPLE\"\n",
		"config.yml": "database:\n  password: sup3rs3cr3tvalue!\n",
		"README.md":  "# Fixture\n\nNo secrets here.\n",
		"empty.txt":  "\n",
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir, len(files)
}

// runScanWithProgress drives a full scan through the SQLite store and returns
// the progress events observed.
func runScanWithProgress(t *testing.T, target string) []diagnostics.Progress {
	t.Helper()

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	proj, err := db.CreateProject(projects.ProjectDescription{
		Name:      "progress-fixture",
		Workspace: "default",
		Repositories: []projects.Repository{
			{Location: target, LocationType: "filesystem"},
		},
		ScanPolicy: projects.ScanPolicy{Policy: diagnostics.DefaultExclusion()},
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	rec := &progressRecorder{}

	summariser := func(projID, sID string,
		issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {
		return &projects.ScanSummary{}
	}

	db.RunScan(
		context.Background(),
		proj.ID,
		proj.ScanPolicy,
		nil, // scanner is unused by this implementation; it calls the finder directly
		func(string) {},
		nil,
		rec.record,
		summariser,
		nil,
	)

	return rec.snapshot()
}

// TestRunScanEmitsProgress is the primary regression guard: before the fix this
// failed with zero events.
func TestRunScanEmitsProgress(t *testing.T) {
	target, _ := newScanFixture(t)

	events := runScanWithProgress(t, target)

	if len(events) == 0 {
		t.Fatal("RunScan emitted no progress events; " +
			"progressMonitor is accepted but never invoked")
	}
}

// TestRunScanProgressIsMonotonic guards the property the UI actually depends
// on. A progress bar that moves backwards is worse than one that does not move.
func TestRunScanProgressIsMonotonic(t *testing.T) {
	target, _ := newScanFixture(t)

	events := runScanWithProgress(t, target)
	if len(events) == 0 {
		t.Skip("no events; covered by TestRunScanEmitsProgress")
	}

	var prev int64 = -1
	for i, e := range events {
		if e.Position < prev {
			t.Errorf("event %d: position went backwards: %d then %d",
				i, prev, e.Position)
		}
		prev = e.Position
	}
}

// TestRunScanFinalProgressReachesFileCount asserts the value the WebSocket
// summary reports. This is the assertion that corresponds to the user-visible
// `fileCount: 0` symptom.
func TestRunScanFinalProgressReachesFileCount(t *testing.T) {
	target, wantFiles := newScanFixture(t)

	events := runScanWithProgress(t, target)
	if len(events) == 0 {
		t.Skip("no events; covered by TestRunScanEmitsProgress")
	}

	final := events[len(events)-1]
	if final.Position <= 0 {
		t.Fatalf("final progress position is %d, want > 0", final.Position)
	}

	// The walker may legitimately see fewer files than written if any are
	// excluded by policy, so assert a sane upper bound rather than equality.
	if final.Position > int64(wantFiles) {
		t.Errorf("final position %d exceeds files written (%d)",
			final.Position, wantFiles)
	}
}
