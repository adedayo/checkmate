package secrets

// Phase 9 tests: progress is coalesced onto an interval rather than emitted
// per file, and completion is always observed.

import (
	"sync"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// recorder captures progress events. The reporter promises never to invoke the
// callback from two goroutines at once, but the *test* reads while the ticker
// may still be running, so it locks.
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
	return append([]diagnostics.Progress(nil), r.events...)
}

// TestResolveProgressIntervalPrecedence pins option > environment > default.
//
// The unparseable cases are the ones worth having. A tuning variable is set by
// an operator under time pressure, often as a bare number, and the failure mode
// to avoid is a mistyped value silently producing an interval of zero — which
// is per-file progress again, the precise behaviour this phase removes, and
// invisible until someone profiles a slow scan.
func TestResolveProgressIntervalPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		option  time.Duration
		env     string
		hasEnv  bool
		expects time.Duration
	}{
		{name: "default", expects: defaultProgressInterval},
		{name: "option wins", option: time.Second, env: "50ms", hasEnv: true, expects: time.Second},
		{name: "duration from env", env: "50ms", hasEnv: true, expects: 50 * time.Millisecond},
		{name: "bare number is milliseconds", env: "500", hasEnv: true, expects: 500 * time.Millisecond},
		{name: "whitespace tolerated", env: "  1s  ", hasEnv: true, expects: time.Second},
		{name: "garbage ignored", env: "soon", hasEnv: true, expects: defaultProgressInterval},
		{name: "zero ignored", env: "0", hasEnv: true, expects: defaultProgressInterval},
		{name: "negative ignored", env: "-5s", hasEnv: true, expects: defaultProgressInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hasEnv {
				t.Setenv("CHECKMATE_PROGRESS_INTERVAL", tc.env)
			}
			got := resolveProgressInterval(SecretSearchOptions{ProgressInterval: tc.option})
			if got != tc.expects {
				t.Errorf("interval = %v, want %v", got, tc.expects)
			}
		})
	}
}

// TestProgressIsCoalesced is the whole point of the phase: the number of
// progress events must be governed by elapsed time, not by the number of files.
//
// It asserts a bound rather than an exact count because the ticker's phase
// relative to the work is not something a test can pin without making itself
// flaky. The bound is loose — 50 events for 100,000 files — and still fails by
// three orders of magnitude if per-file emission ever comes back.
func TestProgressIsCoalesced(t *testing.T) {
	rec := &progressRecorder{}
	reporter := newProgressReporter("p", "s", 20*time.Millisecond, rec.record)

	const files = 100_000
	reporter.SetTotal(files)
	for i := 0; i < files; i++ {
		reporter.FileDone("file")
	}
	//Long enough for several ticks, so the assertion is about coalescing and
	//not about the scan having outrun the first tick.
	time.Sleep(120 * time.Millisecond)
	reporter.Close()

	events := rec.snapshot()
	if len(events) == 0 {
		t.Fatal("no progress events emitted")
	}
	if len(events) > 50 {
		t.Errorf("emitted %d events for %d files; progress is not coalesced", len(events), files)
	}
}

// TestFinalProgressEventIsComplete: a ticker on its own leaves progress
// wherever the last tick fell, so a scan finishing between ticks rests at 99%
// forever. Close must emit an exact, final event.
func TestFinalProgressEventIsComplete(t *testing.T) {
	rec := &progressRecorder{}
	//An interval longer than the test guarantees no tick ever fires, so the
	//event asserted below can only have come from Close.
	reporter := newProgressReporter("proj", "scan", time.Hour, rec.record)

	for i := 0; i < 7; i++ {
		reporter.FileDone("f")
	}
	//A stale, larger total: discovery may have run ahead of a cancelled or
	//pruned scan, and completion must still report 100%.
	reporter.SetTotal(1000)
	reporter.Close()

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected exactly one (final) event, got %d", len(events))
	}
	final := events[0]
	if final.Position != 7 || final.Total != 7 {
		t.Errorf("final event = %d/%d, want 7/7", final.Position, final.Total)
	}
	if final.ProjectID != "proj" || final.ScanID != "scan" {
		t.Errorf("final event lost its identifiers: %+v", final)
	}
}

// TestProgressCloseIsIdempotent — Scan closes the reporter through a defer, and
// a future refactor adding an explicit close on an early return must not panic
// on a doubly-closed channel.
func TestProgressCloseIsIdempotent(t *testing.T) {
	reporter := newProgressReporter("p", "s", time.Hour, func(diagnostics.Progress) {})
	reporter.Close()
	reporter.Close()
}

// TestProgressNeverExceedsTotal. Consumers render Position/Total as a
// percentage, and the walk's total is a *running* discovered count that
// legitimately lags the scan early on. Reporting 40 of 12 would show 333%.
func TestProgressNeverExceedsTotal(t *testing.T) {
	rec := &progressRecorder{}
	reporter := newProgressReporter("p", "s", time.Millisecond, rec.record)

	//Deliberately inverted: more files completed than discovery has admitted to.
	reporter.SetTotal(12)
	for i := 0; i < 40; i++ {
		reporter.FileDone("f")
	}
	time.Sleep(20 * time.Millisecond)
	reporter.Close()

	for _, e := range rec.snapshot() {
		if e.Position > e.Total {
			t.Fatalf("progress exceeded 100%%: %d/%d", e.Position, e.Total)
		}
	}
}

// TestProgressWithoutCallbackDoesNotEmitOrLeak covers the CLI and SDK paths,
// which pass no progress callback at all.
func TestProgressWithoutCallbackDoesNotEmitOrLeak(t *testing.T) {
	reporter := newProgressReporter("p", "s", time.Millisecond, nil)
	reporter.SetTotal(3)
	reporter.FileDone("a")
	reporter.Note("cloning", 1, 3)

	done := make(chan struct{})
	go func() {
		defer close(done)
		reporter.Close()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		//Close waits for the ticker goroutine, and there is no ticker
		//goroutine when there is no callback. If that wiring is ever broken
		//every CLI scan hangs at the end.
		t.Fatal("Close blocked with a nil callback")
	}
}

// TestProgressReportsMostRecentFile — the file name is what a user actually
// watches, and coalescing must not reduce it to an empty string.
func TestProgressReportsMostRecentFile(t *testing.T) {
	rec := &progressRecorder{}
	reporter := newProgressReporter("p", "s", time.Hour, rec.record)
	reporter.FileDone("/a/b/first.go")
	reporter.FileDone("/a/b/last.go")
	reporter.Close()

	events := rec.snapshot()
	if len(events) != 1 || events[0].CurrentFile != "/a/b/last.go" {
		t.Fatalf("expected the most recent file, got %+v", events)
	}
}
