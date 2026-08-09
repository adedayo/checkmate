package secrets

// Progress coalescing.
//
// # The problem with per-file progress
//
// Progress used to be one callback per file. That callback is not cheap and it
// is not local: depending on how the scan was started it broadcasts to every
// connected WebSocket client, writes to the SSE broker, or crosses the Wails
// bridge into a JavaScript runtime. On a million-file estate that is a million
// fan-outs, and the fan-out is synchronous — the scan's sink goroutine cannot
// deliver the next file's findings until every subscriber has been served. The
// engine ends up rate-limited by a progress bar that no human can read at more
// than a few updates a second anyway.
//
// So the counters are updated by the scan (an atomic add, a pointer store) and
// a separate ticker turns them into events. The cost of progress becomes
// independent of the number of files, and the callback contract —
// diagnostics.Progress, unchanged — is what every existing consumer already
// expects, so none of them had to be touched.
//
// # Why the final event is guaranteed
//
// A ticker alone leaves progress wherever the last tick happened to fall, so a
// scan that finishes 40ms after a tick comes to rest at 99%. Close() emits one
// last event from the final counter values, with Total forced equal to
// Position, so completion is always observed exactly once and is always exact.

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// defaultProgressInterval is the coalescing window.
//
// 250ms is chosen from the consumer's side, not the producer's: it is about
// the fastest a progress bar can move and still be read, and four events a
// second is negligible for a WebSocket broadcast. Making it smaller buys the
// user nothing; making it larger makes a short scan look stalled.
const defaultProgressInterval = 250 * time.Millisecond

// resolveProgressInterval applies option, then environment, then the default.
//
// A malformed or non-positive environment value is ignored rather than fatal.
// A mistyped tuning knob must not fail a scan, and there is no value in
// "progress every 0s" — that is the behaviour this file exists to remove, so
// it is not reachable by accident.
func resolveProgressInterval(options SecretSearchOptions) time.Duration {
	if options.ProgressInterval > 0 {
		return options.ProgressInterval
	}

	if v, ok := os.LookupEnv("CHECKMATE_PROGRESS_INTERVAL"); ok {
		v = strings.TrimSpace(v)
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		//A bare number is read as milliseconds. Operators write "500" far more
		//often than "500ms", and rejecting it would silently give them the
		//default while they believed they had tuned it.
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Millisecond
		}
	}

	return defaultProgressInterval
}

// progressReporter coalesces scan progress onto a fixed interval.
//
// All the update methods are safe to call from any goroutine; the emitting
// callback is only ever invoked from the reporter's own ticker goroutine, or
// from Close, and never from both at once. That matters: the downstream
// consumers were written against a sequential producer.
type progressReporter struct {
	projectID, scanID string
	callback          func(diagnostics.Progress)

	position atomic.Int64
	total    atomic.Int64
	//current is the most recently completed file, stored as a pointer so it
	//can be swapped atomically without a lock on the scan's hot path.
	current atomic.Pointer[string]

	stop     chan struct{}
	done     chan struct{}
	closeMu  sync.Mutex
	isClosed bool
}

// newProgressReporter starts the ticker. Close must be called exactly once, or
// the ticker goroutine leaks.
//
// A nil callback yields a reporter that counts but emits nothing, which is
// what the CLI and SDK paths want — they take no progress callback, and making
// every call site nil-check would put the check on the hot path.
func newProgressReporter(projectID, scanID string, interval time.Duration,
	callback func(diagnostics.Progress)) *progressReporter {

	p := &progressReporter{
		projectID: projectID,
		scanID:    scanID,
		callback:  callback,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}

	if callback == nil {
		close(p.done)
		return p
	}

	if interval <= 0 {
		interval = defaultProgressInterval
	}

	go func() {
		defer close(p.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.emit(false)
			}
		}
	}()

	return p
}

// SetTotal records the denominator. It may be called repeatedly as discovery
// runs: the walk streams, so the total is a running count that only becomes
// exact when discovery finishes.
func (p *progressReporter) SetTotal(total int64) {
	p.total.Store(total)
}

// FileDone records the completion of one file.
//
// Completion, not commencement: with a worker pool the two are different
// events, and counting starts would let Position run ahead of the work
// actually done — progress that reaches 100% while the scan is still running.
func (p *progressReporter) FileDone(file string) {
	p.position.Add(1)
	if p.callback != nil {
		p.current.Store(&file)
	}
}

// Note records a one-off status line without advancing the position, for
// phases that are not file counts — repository cloning, most of all, which can
// dominate the wall clock of a multi-repository scan and would otherwise show
// nothing at all.
func (p *progressReporter) Note(note string, position, total int64) {
	if p.callback == nil {
		return
	}
	p.position.Store(position)
	p.total.Store(total)
	p.current.Store(&note)
	p.emit(false)
}

// Reset returns the counters to zero between phases, so that the file-scanning
// position does not start from wherever the cloning phase left it.
func (p *progressReporter) Reset() {
	p.position.Store(0)
	p.total.Store(0)
	p.current.Store(nil)
}

func (p *progressReporter) emit(final bool) {
	if p.callback == nil {
		return
	}

	position := p.position.Load()
	total := p.total.Load()
	if final || total < position {
		//Never report a position beyond the total: consumers divide the two
		//and would render over 100%. Before discovery completes the running
		//total legitimately lags the scan, so this is the ordinary case and
		//not an error.
		total = position
	}

	current := ""
	if f := p.current.Load(); f != nil {
		current = *f
	}

	p.callback(diagnostics.Progress{
		ProjectID:   p.projectID,
		ScanID:      p.scanID,
		CurrentFile: current,
		Position:    position,
		Total:       total,
	})
}

// Close stops the ticker and emits the final, exact event.
//
// It waits for the ticker goroutine to exit before emitting so that the
// completion event cannot be overtaken by a tick that was already in flight,
// which would leave the consumer resting on a stale sub-100% value — the exact
// symptom this is here to prevent. Calling it more than once is harmless.
func (p *progressReporter) Close() {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.isClosed {
		return
	}
	p.isClosed = true

	close(p.stop)
	<-p.done
	p.emit(true)
}
