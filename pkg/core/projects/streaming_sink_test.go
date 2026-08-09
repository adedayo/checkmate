package projects

// Phase 8 — streaming sink guards.
//
// The sink used to accumulate every finding of a scan in a slice and encode
// the lot at close. These tests pin the two properties that replaced it:
// memory does not grow with the number of findings, and a scan that dies
// mid-write still yields everything it had already found.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// newTestConsumer wires a consumer against a throwaway scan directory and
// returns it with the project manager that can read it back.
func newTestConsumer(tb testing.TB) (*streamingDiagnosticConsumer, simpleProjectManager, string, string) {
	tb.Helper()

	base := tb.TempDir()
	pm := MakeSimpleProjectManager(base).(simpleProjectManager)

	const projectID, scanID = "proj", "scan"
	if err := os.MkdirAll(path.Join(pm.projectsLocation, projectID, scanID), 0o755); err != nil {
		tb.Fatalf("creating scan directory: %v", err)
	}

	return createDiagnosticConsumer(pm.projectsLocation, projectID, scanID), pm, projectID, scanID
}

// makeDiagnostic builds a finding distinguishable by index, so ordering and
// completeness can both be asserted.
func makeDiagnostic(i int) *diagnostics.SecurityDiagnostic {
	location := fmt.Sprintf("/repo/file%04d.go", i)
	provider := "TestProvider"
	sha := fmt.Sprintf("%064x", i)

	d := &diagnostics.SecurityDiagnostic{
		Location:   &location,
		ProviderID: &provider,
		SHA256:     &sha,
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: fmt.Sprintf("finding %d", i),
				Confidence:  diagnostics.High,
			},
		},
	}
	d.RawRange.StartIndex = int64(i)
	d.RawRange.EndIndex = int64(i + 10)
	return d
}

// TestStreamingSinkWritesIncrementally asserts findings reach the disk during
// the scan rather than at close.
//
// This is the property that makes an aborted scan recoverable, and it is
// invisible to any test that only checks the final file: an accumulator
// produces a byte-identical result at close. So the assertion has to be made
// while the scan is still notionally running.
func TestStreamingSinkWritesIncrementally(t *testing.T) {
	sdc, pm, projectID, scanID := newTestConsumer(t)

	// 256KB buffer, so enough findings to force at least one flush.
	const n = 5000
	for i := 0; i < n; i++ {
		sdc.ReceiveDiagnostic(makeDiagnostic(i))
	}

	// Deliberately BEFORE close.
	info, err := os.Stat(path.Join(pm.projectsLocation, projectID, scanID, defaultScanResultsFile))
	if err != nil {
		t.Fatalf("results file does not exist mid-scan: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("results file is empty mid-scan; findings are still being " +
			"accumulated in memory and an aborted scan would lose all of them")
	}

	if err := sdc.close(time.Now(), time.Now()); err != nil {
		t.Fatalf("closing sink: %v", err)
	}

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}
	if len(results) != n {
		t.Errorf("read %d findings, wrote %d", len(results), n)
	}
}

// TestStreamingSinkRoundTrip asserts nothing is lost or altered in the format
// change, field by field.
func TestStreamingSinkRoundTrip(t *testing.T) {
	sdc, pm, projectID, scanID := newTestConsumer(t)

	const n = 200
	for i := 0; i < n; i++ {
		sdc.ReceiveDiagnostic(makeDiagnostic(i))
	}
	if err := sdc.close(time.Now(), time.Now()); err != nil {
		t.Fatalf("closing sink: %v", err)
	}

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}
	if len(results) != n {
		t.Fatalf("read %d findings, wrote %d", len(results), n)
	}

	for i, got := range results {
		want := makeDiagnostic(i)
		if *got.Location != *want.Location {
			t.Errorf("finding %d: location %q, want %q", i, *got.Location, *want.Location)
		}
		if *got.SHA256 != *want.SHA256 {
			t.Errorf("finding %d: sha %q, want %q", i, *got.SHA256, *want.SHA256)
		}
		if got.Justification.Headline.Description != want.Justification.Headline.Description {
			t.Errorf("finding %d: headline %q, want %q", i,
				got.Justification.Headline.Description,
				want.Justification.Headline.Description)
		}
		if got.Justification.Headline.Confidence != want.Justification.Headline.Confidence {
			t.Errorf("finding %d: confidence changed", i)
		}
		if got.RawRange != want.RawRange {
			t.Errorf("finding %d: raw range %+v, want %+v", i, got.RawRange, want.RawRange)
		}
	}
}

// TestScanResultsAreSortedOnRead asserts the read side restores the canonical
// order the streaming writer cannot produce.
//
// Phase 7.6 made findings deterministic before persistence; streaming undoes
// that by writing in arrival order. If the sort had simply been dropped rather
// than moved, this is the test that would have caught it — and nothing else
// would have, because the file itself still looks perfectly well-formed.
func TestScanResultsAreSortedOnRead(t *testing.T) {
	sdc, pm, projectID, scanID := newTestConsumer(t)

	// Write in deliberately scrambled order, as a parallel scan would.
	for _, i := range []int{7, 3, 9, 1, 5, 0, 8, 2, 6, 4} {
		sdc.ReceiveDiagnostic(makeDiagnostic(i))
	}
	if err := sdc.close(time.Now(), time.Now()); err != nil {
		t.Fatalf("closing sink: %v", err)
	}

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}
	if len(results) != 10 {
		t.Fatalf("read %d findings, want 10", len(results))
	}

	for i := 1; i < len(results); i++ {
		if *results[i-1].Location > *results[i].Location {
			t.Fatalf("results are not sorted by location: %q precedes %q",
				*results[i-1].Location, *results[i].Location)
		}
	}
}

// TestScanResultsSurviveAbortedScan asserts a truncated file still yields its
// complete findings.
//
// A killed scan leaves a half-written final line. That is the ordinary state
// of an abort, not corruption, and it must not fail the read: doing so would
// discard thousands of valid findings to punish the one the process died
// halfway through — turning a partial result into no result at exactly the
// moment the user most wants to see what was found.
func TestScanResultsSurviveAbortedScan(t *testing.T) {
	sdc, pm, projectID, scanID := newTestConsumer(t)

	const n = 500
	for i := 0; i < n; i++ {
		sdc.ReceiveDiagnostic(makeDiagnostic(i))
	}
	if err := sdc.close(time.Now(), time.Now()); err != nil {
		t.Fatalf("closing sink: %v", err)
	}

	resultsPath := path.Join(pm.projectsLocation, projectID, scanID, defaultScanResultsFile)
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("reading results file: %v", err)
	}

	// Simulate the process dying mid-write: keep a whole number of lines, then
	// append a fragment of the next one.
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d NDJSON lines, got %d — the file is not one "+
			"document per line", n, len(lines))
	}

	const keep = 300
	truncated := strings.Join(lines[:keep], "\n") + "\n" + lines[keep][:40]
	if err := os.WriteFile(resultsPath, []byte(truncated), 0o644); err != nil {
		t.Fatalf("truncating results file: %v", err)
	}

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("an aborted scan's results must still be readable, got: %v", err)
	}
	if len(results) != keep {
		t.Errorf("recovered %d findings from a truncated file, want %d", len(results), keep)
	}
	for i, d := range results {
		if d.Location == nil || *d.Location == "" {
			t.Fatalf("recovered finding %d is incomplete", i)
		}
	}
}

// TestLegacyScanResultsReadable asserts results written as a single JSON array
// — the format used until this change — still load.
//
// The sniff that makes this work is two lines, and without it such a file
// decodes as an empty set. That failure mode is the dangerous one: an empty
// result set renders as "no secrets found", which is indistinguishable from a
// clean codebase and gives exactly the wrong assurance.
func TestLegacyScanResultsReadable(t *testing.T) {
	_, pm, projectID, scanID := newTestConsumer(t)

	legacy := []*diagnostics.SecurityDiagnostic{
		makeDiagnostic(2), makeDiagnostic(0), makeDiagnostic(1),
	}

	resultsPath := path.Join(pm.projectsLocation, projectID, scanID, defaultScanResultsFile)
	file, err := os.Create(resultsPath)
	if err != nil {
		t.Fatalf("creating legacy file: %v", err)
	}
	if err := json.NewEncoder(file).Encode(legacy); err != nil {
		t.Fatalf("writing legacy file: %v", err)
	}
	_ = file.Close()

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("reading legacy results: %v", err)
	}
	if len(results) != len(legacy) {
		t.Fatalf("read %d findings from the legacy array, want %d — a stored "+
			"scan reading as empty is indistinguishable from a clean codebase",
			len(results), len(legacy))
	}
	for i := 1; i < len(results); i++ {
		if *results[i-1].Location > *results[i].Location {
			t.Error("legacy results are not canonically sorted on read")
		}
	}
}

// TestEmptyScanResultsReadable covers a scan that found nothing, and a scan
// killed before its first flush. Both leave a zero-length file, which must
// read as "no findings" rather than as an error.
func TestEmptyScanResultsReadable(t *testing.T) {
	sdc, pm, projectID, scanID := newTestConsumer(t)
	if err := sdc.close(time.Now(), time.Now()); err != nil {
		t.Fatalf("closing sink: %v", err)
	}

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		t.Fatalf("empty results file must read cleanly, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("read %d findings from an empty file", len(results))
	}
}

// TestScanSinkMemoryIsFlatInFindingCount is the memory claim of this phase,
// stated as the property that actually matters.
//
// The plan called for a fixed budget (< 512MB) on a 1M-file corpus. A fixed
// threshold measured on one machine is a poor guard: it passes on a laptop
// with headroom, flakes under CI memory pressure, and is then deleted. The
// defect being prevented is not "uses more than 512MB", it is "grows with the
// number of findings" — so that is what is asserted, by scaling the finding
// count tenfold and requiring the retained heap not to follow.
//
// An accumulator fails this outright: 10× the findings is 10× the retained
// slice. The streaming sink retains one 256KB buffer regardless.
func TestScanSinkMemoryIsFlatInFindingCount(t *testing.T) {
	measure := func(n int) uint64 {
		sdc, _, _, _ := newTestConsumer(t)

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		for i := 0; i < n; i++ {
			sdc.ReceiveDiagnostic(makeDiagnostic(i))
		}

		// Measured before close, while a scan would still be running and an
		// accumulator would still be holding everything.
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		_ = sdc.close(time.Now(), time.Now())

		if after.HeapAlloc < before.HeapAlloc {
			return 0
		}
		return after.HeapAlloc - before.HeapAlloc
	}

	small := measure(10_000)
	large := measure(100_000)

	// Ten times the findings must not cost anything like ten times the heap.
	// The bound is deliberately loose — this is a guard against linear growth,
	// not a budget — but an accumulator overshoots it by an order of magnitude.
	const tolerance = 3
	if large > small*tolerance+(4<<20) {
		t.Errorf("retained heap grew from %d bytes at 10k findings to %d bytes "+
			"at 100k: memory is scaling with finding count, so the sink is "+
			"accumulating rather than streaming", small, large)
	}
}
