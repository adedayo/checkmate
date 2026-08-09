package secrets

// The worker pool.
//
// Both entry points into the engine — SecretScanner.Scan (the API/app path)
// and SearchSecretsOnPaths (the CLI/SDK path) — used to do the same thing:
// build one set of path consumers, then feed every discovered file through
// them one at a time on the calling goroutine. Discovery already streams
// (Phase 5) and per-file scanning is already free of cross-file state
// (Phase 3), so the single remaining reason the scan ran on one core was that
// nobody had wired a second one up.
//
// # Why a worker owns its consumers rather than sharing them
//
// The obvious parallelisation — keep one consumer set, call ConsumePath from N
// goroutines — is wrong, and quietly so. pathBasedSourceSecretFinder holds a
// ScanContext, and a ScanContext holds two pieces of per-file mutable state:
// the aggregator that collects the current file's findings, and the ruleGate's
// candidate set. Two goroutines in there would interleave one file's findings
// into another file's aggregate and evaluate rules against the wrong
// candidate set. Neither would crash; both would silently corrupt results.
//
// So each worker constructs its own consumers, and therefore its own
// ScanContext, and is single-threaded within itself. That is exactly the
// arrangement ScanContext's doc comment already anticipated. What is shared
// between workers is only what is immutable: the compiled exclusion provider,
// the prefilter automaton and the vendor rule tables.
//
// # Why results come back through one goroutine
//
// Findings are handed to the caller by a single sink goroutine rather than
// broadcast from the workers. The downstream consumers — the WebSocket
// broadcaster, the SSE broker, the results file writer, the SDK channel — were
// all written against a sequential producer, and none of them documents thread
// safety. Serialising delivery here keeps that contract intact, so
// parallelism stops at the engine boundary and nothing downstream has to
// change. It also restores per-file grouping, which SearchSecretsOnPaths needs
// for overlap subsumption.

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// fileScanResult is one file's complete contribution to the scan.
//
// Results are batched per file rather than streamed per finding because the
// callers need the grouping: SearchSecretsOnPaths subsumes overlapping
// findings within a file, and SecretScanner.Scan reports progress per file.
// Batching also means the sink is woken once per file instead of once per
// finding, which matters on the fixture files that produce hundreds.
type fileScanResult struct {
	File util.RepositoryIndexedFile
	//Diagnostics may be empty; the result is still delivered, because
	//"this file was scanned" is what drives progress.
	Diagnostics []*diagnostics.SecurityDiagnostic
}

// resolveWorkers determines the scan pool size.
//
// Precedence is explicit option, then environment, then GOMAXPROCS. The
// environment variable is there for operators who need to cap CheckMate's
// footprint on a shared CI runner without a code change; an unparseable or
// non-positive value is ignored rather than fatal, since a mistyped tuning
// knob should not fail a scan.
func resolveWorkers(options SecretSearchOptions) int {
	if options.Workers > 0 {
		return options.Workers
	}

	if v, ok := os.LookupEnv("CHECKMATE_SCAN_WORKERS"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}

	if n := runtime.GOMAXPROCS(0); n > 0 {
		return n
	}
	return 1
}

// scanWorker is one worker's private consumer set.
//
// It is not safe for concurrent use, by construction — see the file comment.
type scanWorker struct {
	mux util.PathMultiplexer
	//collected accumulates the diagnostics broadcast during the current
	//ConsumePath call. The consumers broadcast synchronously from within that
	//call, so no synchronisation is needed and none would be correct: a lock
	//here would suggest the rest of the worker were shareable, and it is not.
	collected []*diagnostics.SecurityDiagnostic
}

// newScanWorker builds the consumer set for one worker.
//
// This is the consumer construction that previously lived, duplicated and
// subtly divergent, in both SecretScanner.Scan and SearchSecretsOnPaths.
func newScanWorker(options SecretSearchOptions) *scanWorker {
	w := &scanWorker{}

	//We always search for confidential files; source secret scanning is the
	//part ConfidentialFilesOnly turns off.
	size := 1
	if !options.ConfidentialFilesOnly {
		size = 2
	}
	consumers := make([]util.PathConsumer, 0, size)
	consumers = append(consumers, &confidentialFilesFinder{
		ExclusionProvider: options.Exclusions,
		options:           options,
	})
	if !options.ConfidentialFilesOnly {
		consumers = append(consumers, newPathBasedSourceSecretFinder(options))
	}

	providers := make([]diagnostics.SecurityDiagnosticsProvider, 0, len(consumers))
	for _, c := range consumers {
		providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
	}
	common.RegisterDiagnosticsConsumer(func(d *diagnostics.SecurityDiagnostic) {
		w.collected = append(w.collected, d)
	}, providers...)

	//Sharing one gate evaluation across the consumers, as before (Phase 6.1).
	w.mux = newGatedPathMultiplexer(options.Exclusions, consumers...)

	return w
}

// scan processes one file and returns everything its consumers broadcast.
//
// The slice is handed off rather than reused between files: it travels to the
// sink goroutine, so recycling the backing array would let the next file
// overwrite the previous file's findings while they were still in flight.
func (w *scanWorker) scan(rif util.RepositoryIndexedFile) []*diagnostics.SecurityDiagnostic {
	w.collected = nil
	w.mux.ConsumePath(rif)
	found := w.collected
	w.collected = nil
	return found
}

// runScanPipeline scans every file arriving on `files` using a pool of
// workers, and invokes onResult once per file from a single goroutine.
//
// It returns when the pool has finished — either because `files` was closed
// and drained, or because ctx was cancelled. onResult is never called
// concurrently, and never called again after runScanPipeline returns.
func runScanPipeline(ctx context.Context, options SecretSearchOptions,
	files <-chan util.RepositoryIndexedFile, onResult func(fileScanResult)) {

	workers := resolveWorkers(options)

	//Capacity is 4× the pool, not the 1024 the design suggested for a
	//per-finding channel. A buffered result holds one file's entire finding
	//set, each carrying its source text when ShowSource is on, so 1024 of them
	//is a memory commitment of a completely different order — precisely the
	//kind of unbounded accumulation this change exists to remove. 4× is enough
	//to keep every worker off the sink's critical path while a slow consumer
	//(a WebSocket broadcast, a database write) is served.
	results := make(chan fileScanResult, 4*workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()

			//Built on receipt of the first file, not up front. A ScanContext
			//is ~8 provider sets and the dominant fixed cost in the pool, and
			//a scan of three files has no use for sixteen of them.
			var worker *scanWorker

			for rif := range files {
				if ctx.Err() != nil {
					return
				}
				if worker == nil {
					worker = newScanWorker(options)
				}

				result := fileScanResult{File: rif, Diagnostics: worker.scan(rif)}

				select {
				case results <- result:
				case <-ctx.Done():
					//Dropping this file's findings is correct on
					//cancellation: the caller has asked us to stop, and
					//everything already delivered remains valid.
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	//The sink. Abandoning `files` mid-flight is safe because WalkFiles selects
	//on the same ctx when emitting, so the walker unblocks and exits rather
	//than leaking on a channel nobody is reading.
	for result := range results {
		onResult(result)
	}
}
