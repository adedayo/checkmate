package secrets

// Phase 7 — worker pool guards.
//
// The pool's whole justification is that it changes nothing except how long a
// scan takes, so most of what is worth asserting here is a negative: results
// do not depend on worker count, findings do not leak between workers, and
// delivery to the caller stays single-threaded.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// TestResolveWorkersPrecedence pins option > environment > GOMAXPROCS, and
// that a nonsense environment value is ignored rather than obeyed.
//
// The last part is the one worth having: CHECKMATE_SCAN_WORKERS=0 or
// CHECKMATE_SCAN_WORKERS=auto reaching the pool as a literal zero would create
// no workers at all, and a scan with no workers does not fail — it silently
// reports zero findings, which reads exactly like a clean codebase.
func TestResolveWorkersPrecedence(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		envSet  bool
		options SecretSearchOptions
		want    int
	}{
		{name: "default", want: runtime.GOMAXPROCS(0)},
		{name: "option wins", options: SecretSearchOptions{Workers: 3}, want: 3},
		{name: "env used", env: "5", envSet: true, want: 5},
		{
			name:    "option beats env",
			env:     "5",
			envSet:  true,
			options: SecretSearchOptions{Workers: 2},
			want:    2,
		},
		{name: "zero env ignored", env: "0", envSet: true, want: runtime.GOMAXPROCS(0)},
		{name: "negative env ignored", env: "-4", envSet: true, want: runtime.GOMAXPROCS(0)},
		{name: "garbage env ignored", env: "auto", envSet: true, want: runtime.GOMAXPROCS(0)},
		{name: "padded env accepted", env: "  6 ", envSet: true, want: 6},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.envSet {
				t.Setenv("CHECKMATE_SCAN_WORKERS", c.env)
			} else {
				_ = os.Unsetenv("CHECKMATE_SCAN_WORKERS")
			}
			if got := resolveWorkers(c.options); got != c.want {
				t.Errorf("resolveWorkers = %d, want %d", got, c.want)
			}
		})
	}
}

// TestResolveWorkersNeverReturnsZero is the invariant the table above is
// really protecting, stated directly so it survives a rewrite of the table.
func TestResolveWorkersNeverReturnsZero(t *testing.T) {
	for _, v := range []string{"0", "-1", "", "auto", "1.5", "999999999999999999999"} {
		t.Setenv("CHECKMATE_SCAN_WORKERS", v)
		if n := resolveWorkers(SecretSearchOptions{}); n < 1 {
			t.Fatalf("CHECKMATE_SCAN_WORKERS=%q yielded %d workers; "+
				"a pool of zero workers scans nothing and reports success", v, n)
		}
	}
}

// TestScanResultsIndependentOfWorkerCount is the core equivalence claim of
// this phase.
//
// TestScanEquivalence already compares against the golden baseline, but it
// runs at whatever GOMAXPROCS the machine happens to have. This pins the
// property directly across a range of pool sizes including 1 (sequential) and
// a count far above the number of files, so an off-by-one in work distribution
// or state shared between workers shows up as a difference rather than as an
// occasional CI flake.
func TestScanResultsIndependentOfWorkerCount(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	repoA := filepath.Join(root, "repo-a")
	repoB := filepath.Join(root, "repo-b")

	var reference []byte
	for _, workers := range []int{1, 2, 3, 8, 64} {
		opts := baselineOptions()
		opts.Workers = workers

		run := runScan(t, opts, repoA, repoB)
		if len(run.Findings) == 0 {
			t.Fatalf("workers=%d produced no findings", workers)
		}

		got, err := serialiseCanonical(canonicaliseAll(root, run.Findings))
		if err != nil {
			t.Fatalf("workers=%d: serialising: %v", workers, err)
		}

		if reference == nil {
			reference = got
			continue
		}
		if string(reference) != string(got) {
			t.Fatalf("workers=%d produced different findings from workers=1; "+
				"scan results depend on pool size", workers)
		}
	}
}

// TestScannedFileSetIndependentOfWorkerCount asserts the same for the file
// list, which is a separate return value with its own ordering and is used by
// callers to report scan coverage.
func TestScannedFileSetIndependentOfWorkerCount(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	repoA := filepath.Join(root, "repo-a")

	var reference []util.RepositoryIndexedFile
	for _, workers := range []int{1, 4, 32} {
		opts := baselineOptions()
		opts.Workers = workers

		run := runScan(t, opts, repoA)
		if len(run.Files) == 0 {
			t.Fatalf("workers=%d scanned no files", workers)
		}

		if reference == nil {
			reference = run.Files
			continue
		}
		if len(reference) != len(run.Files) {
			t.Fatalf("workers=%d scanned %d files, workers=1 scanned %d",
				workers, len(run.Files), len(reference))
		}
		for i := range reference {
			if reference[i] != run.Files[i] {
				t.Fatalf("workers=%d: file %d is %+v, want %+v — the scanned "+
					"file list is not deterministic", workers, i, run.Files[i], reference[i])
			}
		}
	}
}

// TestPipelineDeliversResultsSerially asserts the sink callback is never
// invoked concurrently.
//
// This is not a stylistic preference. Everything hanging off that callback —
// the WebSocket broadcaster, the SSE broker, the scan-results writer, the SDK
// channel — was written for a single producer and none of it is guarded. If
// the pool ever delivered from N goroutines the failure would be a data race
// in somebody else's package, discovered in production rather than here.
//
// The counter is deliberately checked *inside* the callback rather than by
// running under -race alone, so the test fails deterministically instead of
// only when the scheduler cooperates.
func TestPipelineDeliversResultsSerially(t *testing.T) {
	root := materialiseCorpus(t, scaleCorpus(400))

	files, _ := util.WalkFiles(context.Background(), []string{root}, util.WalkOptions{})

	opts := baselineOptions()
	opts.Workers = 8

	var inFlight atomic.Int32
	var overlaps atomic.Int32
	var seen int

	runScanPipeline(context.Background(), opts, files, func(result fileScanResult) {
		if inFlight.Add(1) != 1 {
			overlaps.Add(1)
		}
		seen++
		time.Sleep(time.Microsecond)
		inFlight.Add(-1)
	})

	if seen == 0 {
		t.Fatal("pipeline delivered no results; the test proves nothing")
	}
	if n := overlaps.Load(); n != 0 {
		t.Errorf("sink callback was entered concurrently %d times; downstream "+
			"consumers assume a single producer", n)
	}
}

// TestPipelineGroupsFindingsByFile asserts each result carries only its own
// file's findings.
//
// Every worker owns a private collector, and a mistake there — sharing one, or
// failing to clear it between files — would attribute one file's secrets to
// another. The finding still exists, so no count changes and the equivalence
// test could plausibly still pass; only the location is wrong, which is the
// single field a user acts on.
func TestPipelineGroupsFindingsByFile(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())

	files, _ := util.WalkFiles(context.Background(), []string{root}, util.WalkOptions{})

	opts := baselineOptions()
	opts.Workers = 8

	var results int
	var findings int
	runScanPipeline(context.Background(), opts, files, func(result fileScanResult) {
		results++
		for _, d := range result.Diagnostics {
			findings++
			if d.Location == nil {
				t.Errorf("finding for %s has no location", result.File.File)
				continue
			}
			if *d.Location != result.File.File {
				t.Errorf("finding attributed to %q was delivered with file %q",
					*d.Location, result.File.File)
			}
			if d.RepositoryIndex != result.File.RepositoryIndex {
				t.Errorf("finding for %s carries repository index %d, want %d",
					result.File.File, d.RepositoryIndex, result.File.RepositoryIndex)
			}
		}
	})

	if results == 0 || findings == 0 {
		t.Fatalf("pipeline yielded %d results and %d findings; the assertions "+
			"above never ran", results, findings)
	}
}

// TestScanCancellation asserts a cancelled scan stops promptly and that what
// it produced before stopping is valid.
//
// "Valid" is the important half. Aborting a scan is a routine event — a user
// closes the browser tab, a CI job times out, a container is evicted — and the
// results collected up to that point are still reported. A partial result set
// containing a half-populated diagnostic would be worse than no result at all,
// because nothing downstream distinguishes the two.
func TestScanCancellation(t *testing.T) {
	root := materialiseCorpus(t, scaleCorpus(5000))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	files, _ := util.WalkFiles(ctx, []string{root}, util.WalkOptions{})

	opts := baselineOptions()
	opts.Workers = 4

	const cancelAfter = 25

	var delivered []*diagnostics.SecurityDiagnostic
	var scanned int

	done := make(chan struct{})
	go func() {
		defer close(done)
		runScanPipeline(ctx, opts, files, func(result fileScanResult) {
			scanned++
			delivered = append(delivered, result.Diagnostics...)
			if scanned == cancelAfter {
				cancel()
			}
		})
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled scan did not return; the pool is not observing ctx")
	}

	if scanned < cancelAfter {
		t.Fatalf("only %d files were scanned before cancellation at %d",
			scanned, cancelAfter)
	}

	// The pool does not stop dead — workers finish the file in hand and the
	// buffered results still drain — but it must stop soon, not at the end.
	// 5000 files with a cancel at 25 gives an enormous margin: anything under
	// the full corpus proves ctx is being observed, and the bound below is
	// generous enough not to flake on a loaded machine.
	if scanned > 2000 {
		t.Errorf("scanned %d of 5000 files after cancellation at file %d; "+
			"cancellation is not taking effect promptly", scanned, cancelAfter)
	}

	// Everything delivered must be a complete, usable finding.
	for i, d := range delivered {
		if d == nil {
			t.Fatalf("partial result %d is nil", i)
		}
		if d.Location == nil || *d.Location == "" {
			t.Errorf("partial result %d has no location", i)
		}
		if d.ProviderID == nil || *d.ProviderID == "" {
			t.Errorf("partial result %d has no provider ID", i)
		}
		if d.Justification.Headline.Description == "" {
			t.Errorf("partial result %d has no headline", i)
		}
	}
}

// TestScanCancellationBeforeStart asserts an already-cancelled context does
// not hang or panic — the case a caller hits when the user aborts between
// clone and scan.
func TestScanCancellationBeforeStart(t *testing.T) {
	root := materialiseCorpus(t, scaleCorpus(200))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	files, _ := util.WalkFiles(ctx, []string{root}, util.WalkOptions{})

	opts := baselineOptions()
	opts.Workers = 4

	done := make(chan struct{})
	go func() {
		defer close(done)
		runScanPipeline(ctx, opts, files, func(fileScanResult) {})
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("pipeline did not return for an already-cancelled context")
	}
}

// TestSortDiagnosticsCanonicallyOrdersAcrossFiles guards the ordering the
// persistence layers now rely on.
//
// SortDiagnosticsDeterministically opens on RawRange.StartIndex, which is a
// per-file offset. Sorting a multi-file result set with it interleaves files
// by coincidence of offset, which is stable but meaningless — and, worse,
// looks correct in a spot check. This asserts the location-first order groups
// files together.
func TestSortDiagnosticsCanonicallyOrdersAcrossFiles(t *testing.T) {
	loc := func(s string) *string { return &s }

	diags := []*diagnostics.SecurityDiagnostic{
		{Location: loc("b.go"), RawRange: diagnostics.CharRange{StartIndex: 10, EndIndex: 20}},
		{Location: loc("a.go"), RawRange: diagnostics.CharRange{StartIndex: 90, EndIndex: 99}},
		{Location: loc("b.go"), RawRange: diagnostics.CharRange{StartIndex: 5, EndIndex: 8}},
		{Location: loc("a.go"), RawRange: diagnostics.CharRange{StartIndex: 1, EndIndex: 4}},
	}

	diagnostics.SortDiagnosticsCanonically(diags)

	want := []struct {
		location string
		start    int64
	}{
		{"a.go", 1}, {"a.go", 90}, {"b.go", 5}, {"b.go", 10},
	}

	for i, w := range want {
		if *diags[i].Location != w.location || diags[i].RawRange.StartIndex != w.start {
			t.Fatalf("position %d is %s@%d, want %s@%d",
				i, *diags[i].Location, diags[i].RawRange.StartIndex, w.location, w.start)
		}
	}
}

// TestSortDiagnosticsCanonicallyIsOrderIndependent asserts the sort is a
// function of content alone — the property that makes it usable as the
// determinism fix for parallel output.
func TestSortDiagnosticsCanonicallyIsOrderIndependent(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	run := runScan(t, baselineOptions(), filepath.Join(root, "repo-a"))

	if len(run.Findings) < 2 {
		t.Fatalf("need at least two findings to permute, got %d", len(run.Findings))
	}

	forward := append([]*diagnostics.SecurityDiagnostic(nil), run.Findings...)
	diagnostics.SortDiagnosticsCanonically(forward)

	reversed := make([]*diagnostics.SecurityDiagnostic, len(run.Findings))
	for i, d := range run.Findings {
		reversed[len(run.Findings)-1-i] = d
	}
	diagnostics.SortDiagnosticsCanonically(reversed)

	for i := range forward {
		if forward[i] != reversed[i] {
			t.Fatalf("canonical sort is order-dependent at position %d", i)
		}
	}
}
