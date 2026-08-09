package secrets

// Phase 0 harness — performance baseline.
//
// These benchmarks and measurements record the CURRENT engine's behaviour so
// that the improvements claimed in proposal.md can be demonstrated rather than
// asserted. Nothing here gates CI on a performance number (hosted runners are
// far too noisy for that); the throughput and RSS gates arrive in Phase 10 once
// there is a stable comparison to make.
//
// Record the baseline with:
//
//	go test ./pkg/plugin/secrets-finder/pkg/ -run '^$' -bench 'Scan' -benchtime 1x -v
//	go test ./pkg/plugin/secrets-finder/pkg/ -run 'TestBaseline' -v -timeout 30m
//
// Note the deliberately generous timeouts. The adversarial fixtures currently
// exercise the O(n^2) readChunks path (P4), and on the 10MB minified fixture
// that is minutes, not seconds — which is exactly the number worth recording.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// requirePerfBaseline gates the slow measurement tests behind an explicit
// opt-in.
//
// These tests deliberately exercise pathological inputs — a 10MB file with no
// newlines currently drives readChunks into quadratic string concatenation,
// which takes minutes, and is far slower again under `-race`. That is the
// number worth recording, but it must not run in ordinary CI, which executes
// `go test -race ./...` with the default 10 minute timeout.
//
// Enable with:
//
//	CHECKMATE_PERF_BASELINE=1 go test ./pkg/plugin/secrets-finder/pkg/ \
//	    -run 'TestBaseline' -v -timeout 60m
func requirePerfBaseline(t *testing.T) {
	t.Helper()
	if os.Getenv("CHECKMATE_PERF_BASELINE") == "" {
		t.Skip("set CHECKMATE_PERF_BASELINE=1 to run performance baseline measurements")
	}
}

// ---------------------------------------------------------------------------
// Throughput
// ---------------------------------------------------------------------------

// BenchmarkScanReferenceCorpus measures the small, feature-complete corpus.
// Useful for spotting per-file overhead regressions (P3: ~240 finder
// allocations per file) rather than raw throughput.
func BenchmarkScanReferenceCorpus(b *testing.B) {
	root := materialiseCorpus(b, referenceCorpus())
	repoA := filepath.Join(root, "repo-a")
	repoB := filepath.Join(root, "repo-b")
	opts := baselineOptions()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runScan(b, opts, repoA, repoB)
	}
}

// BenchmarkScanScale measures throughput over synthetic codebases of
// increasing size. The files-per-second figure is the headline number the
// change is judged on.
func BenchmarkScanScale(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			root := materialiseCorpus(b, scaleCorpus(n))
			scaleRoot := filepath.Join(root, "scale")
			opts := baselineOptions()
			// Checksums require a second full read of every file today (S2);
			// disable here so the benchmark measures matching throughput
			// rather than duplicated I/O.
			opts.CalculateChecksum = false

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				run := runScan(b, opts, scaleRoot)
				b.ReportMetric(
					float64(n)/run.Duration.Seconds(), "files/s")
				b.ReportMetric(
					float64(len(run.Findings)), "findings")
			}
		})
	}
}

// BenchmarkFinderConstruction isolates P3 directly: the cost of building the
// ~240-object finder set that the engine currently rebuilds for every single
// file. Phase 2 must drive this to zero per file by hoisting it into a
// per-worker ScanContext.
func BenchmarkFinderConstruction(b *testing.B) {
	opts := baselineOptions()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider := GetFinderForFileType(".go", opts)
		if len(provider.GetFinders()) == 0 {
			b.Fatal("no finders constructed")
		}
	}
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

// memoryProfile captures peak heap usage sampled during a scan.
//
// This measures Go heap rather than process RSS. That is sufficient for the
// Phase 0 baseline — the accumulation problems being tracked (P2's whole file
// list, P6's whole result set) are all heap — and it avoids a platform-specific
// RSS dependency. The hard <512MB RSS gate lands in Phase 8 alongside the
// streaming sink.
type memoryProfile struct {
	PeakHeapInUse  uint64
	PeakHeapAlloc  uint64
	TotalAllocated uint64
	NumGC          uint32
	Duration       time.Duration
	Findings       int
	Files          int
}

func (m memoryProfile) String() string {
	return fmt.Sprintf(
		"peak heap in-use %s, peak heap alloc %s, total allocated %s, GCs %d, "+
			"%d findings over %d files in %v",
		humanBytes(m.PeakHeapInUse), humanBytes(m.PeakHeapAlloc),
		humanBytes(m.TotalAllocated), m.NumGC, m.Findings, m.Files, m.Duration)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}

// profileScan runs a scan while sampling heap statistics, returning the peak
// observed. Sampling (rather than a single post-hoc reading) is essential:
// GC may well have reclaimed the peak by the time the scan returns.
func profileScan(tb testing.TB, opts SecretSearchOptions, paths ...string) memoryProfile {
	tb.Helper()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var peakInUse, peakAlloc uint64
	stop := make(chan struct{})
	var sampling atomic.Bool
	sampling.Store(true)

	go func() {
		defer close(stop)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		var ms runtime.MemStats
		for sampling.Load() {
			<-ticker.C
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peakInUse {
				peakInUse = ms.HeapInuse
			}
			if ms.HeapAlloc > peakAlloc {
				peakAlloc = ms.HeapAlloc
			}
		}
	}()

	run := runScan(tb, opts, paths...)

	sampling.Store(false)
	<-stop

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	return memoryProfile{
		PeakHeapInUse:  peakInUse,
		PeakHeapAlloc:  peakAlloc,
		TotalAllocated: after.TotalAlloc - before.TotalAlloc,
		NumGC:          after.NumGC - before.NumGC,
		Duration:       run.Duration,
		Findings:       len(run.Findings),
		Files:          len(run.Files),
	}
}

// TestBaselineMemoryProfile records how memory scales with corpus size.
//
// The expected (defective) shape is roughly linear growth in peak heap with
// file count, because the walk materialised the entire file list (P2)
// and the result set is accumulated whole (P6). After Phase 8 this line should
// be flat.
func TestBaselineMemoryProfile(t *testing.T) {
	requirePerfBaseline(t)

	opts := baselineOptions()
	opts.CalculateChecksum = false

	for _, n := range []int{1_000, 10_000, 50_000} {
		t.Run(fmt.Sprintf("files=%d", n), func(t *testing.T) {
			root := materialiseCorpus(t, scaleCorpus(n))
			profile := profileScan(t, opts, filepath.Join(root, "scale"))
			t.Logf("BASELINE %d files: %s", n, profile)
			t.Logf("BASELINE %d files: %.1f bytes peak heap per file",
				n, float64(profile.PeakHeapInUse)/float64(n))
		})
	}
}

// ---------------------------------------------------------------------------
// Adversarial fixtures
// ---------------------------------------------------------------------------

// TestBaselineAdversarial records the current cost of each pathological
// fixture individually, so the improvement per pathology is attributable.
//
// The 10MB minified fixture is the headline case: a single file with no
// newlines drives readChunks into `largeChunk += ...` on every one of ~2,560
// iterations, copying a string that grows toward 10MB — on the order of 13GB
// of memcpy, plus ~614k goroutine creations from the per-consumer-per-chunk
// fan-out. Phase 3 must bring this under one second.
func TestBaselineAdversarial(t *testing.T) {
	requirePerfBaseline(t)

	root := materialiseCorpus(t, adversarialCorpus())
	opts := baselineOptions()
	opts.CalculateChecksum = false

	cases := []struct {
		name    string
		path    string
		limit   time.Duration
		purpose string
	}{
		{"minified-10mb", "adversarial/bundle.min.js", 10 * time.Minute,
			"P4: quadratic readChunks + goroutine storm"},
		{"oneline-json-4mb", "adversarial/oneline.json", 10 * time.Minute,
			"P4 via the YAML/JSON finder branch"},
		{"base64-blob-2mb", "adversarial/blob.yaml", 10 * time.Minute,
			"P4 with zero whitespace"},
		{"binary-text-ext", "adversarial/payload.conf", 2 * time.Minute,
			"S7: binary sniff gap for known extensions"},
		{"binary-no-ext", "adversarial/blobdata", 2 * time.Minute,
			"S7: extensionless binary is correctly skipped today"},
		{"oversize-log", "adversarial/huge.log", 2 * time.Minute,
			"cutOffSize skip path must be preserved"},
		{"deep-nesting", "adversarial/deep", 2 * time.Minute,
			"P2: walker recursion depth"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := runScanWithTimeout(t, tc.limit, opts, filepath.Join(root, tc.path))
			t.Logf("BASELINE %-18s %-10v %3d findings  (%s)",
				tc.name, run.Duration.Round(time.Millisecond),
				len(run.Findings), tc.purpose)
		})
	}
}

// TestBaselineSymlinkLoop verifies the walker terminates on a cyclic symlink.
//
// util.FindFiles has no visited-directory guard, so this documents the current
// behaviour. filepath.WalkDir does not follow symlinks by default, which is
// what saves it today — Phase 5 must preserve termination while adding an
// explicit (device, inode) guard.
//
// Phase 5 update: the guard now exists, and WalkFiles still does not follow
// symlinks by default, so this fixture's result is unchanged.
func TestBaselineSymlinkLoop(t *testing.T) {
	requirePerfBaseline(t)

	root := materialiseCorpus(t, referenceCorpus())
	if !addSymlinkLoop(t, root) {
		t.Skip("platform does not support symlink creation")
	}

	opts := baselineOptions()
	opts.CalculateChecksum = false

	run := runScanWithTimeout(t, 2*time.Minute, opts, filepath.Join(root, "adversarial"))
	t.Logf("BASELINE symlink-loop: terminated in %v with %d findings over %d files",
		run.Duration.Round(time.Millisecond), len(run.Findings), len(run.Files))
}
