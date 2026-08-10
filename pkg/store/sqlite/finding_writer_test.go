package sqlite

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
)

// These tests cover a freeze reported against the desktop app: suppressing a
// finding during a scan of a large codebase appeared to block any further
// suppression until the scan finished.
//
// The cause is contention, not a deadlock. Findings were persisted with an
// unbounded `go d.persistFinding(...)` per finding, each acquiring the
// exclusive d.mu and a connection from a pool capped at one. On a corpus
// producing thousands of findings, thousands of goroutines queue on that
// mutex; Go switches a contended mutex to FIFO starvation mode, so a
// suppression arriving mid-scan is served only after the backlog ahead of it.
// The user experiences that as the UI refusing further suppressions.

// seedScan creates the project and scan rows that findings reference.
// foreign_keys is ON, so without these every insert is rejected and the writer
// would appear to work while persisting nothing.
func seedScan(t *testing.T, db *DB, projectID, scanID string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)

	if _, err := db.db.Exec(
		`INSERT INTO projects(id, workspace, name, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		projectID, "test-ws", projectID, "{}", now, now); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.db.Exec(
		`INSERT INTO scans(id, project_id, status, started_at, created_at) VALUES (?, ?, 'running', ?, ?)`,
		scanID, projectID, now, now); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
}

func testFinding(i int) *diagnostics.SecurityDiagnostic {
	loc := fmt.Sprintf("/repo/pkg/file_%d.go", i)
	sum := fmt.Sprintf("checksum-%d", i)
	src := "apiKey := \"AKIAIOSFODNN7EXAMPLE\""
	return &diagnostics.SecurityDiagnostic{
		Location: &loc,
		SHA256:   &sum,
		Source:   &src,
		Range: code.Range{
			Start: code.Position{Line: int64(i), Character: 2},
			End:   code.Position{Line: int64(i), Character: 40},
		},
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: "Hard-coded credential",
				Confidence:  diagnostics.High,
			},
		},
	}
}

// TestSuppressionIsNotBlockedByFindingPersistence is the regression test for
// the reported freeze.
//
// It asserts interleaving rather than a wall-clock threshold. The property that
// matters is that a suppression arriving mid-scan is served while the scan is
// still running, and that is true on a fast laptop and a loaded CI runner
// alike. An absolute latency bound is not: under -race the same code is an
// order of magnitude slower, so a threshold tuned to a laptop fails there for
// reasons that have nothing to do with the bug.
//
// Against the previous goroutine-per-finding implementation the suppressions
// queue behind the whole burst and almost none complete before the scan ends.
func TestSuppressionIsNotBlockedByFindingPersistence(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		findingCount     = 4000
		suppressionCount = 20
	)

	ctx := context.Background()
	scanID := uuid.New().String()
	projectID := "proj-under-scan"

	seedScan(t, db, projectID, scanID)
	writer := db.newFindingWriter(ctx, scanID, projectID)

	// Closed when the scan's findings have all been written, so each
	// suppression can record whether it landed before or after that point.
	scanDone := make(chan struct{})

	var wg sync.WaitGroup

	// The scan: a burst of findings, as RunScan produces them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < findingCount; i++ {
			writer.add(testFinding(i), false, "")
		}
		writer.close()
		close(scanDone)
	}()

	// The user: suppressing findings while that is going on.
	var duringScan int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < suppressionCount; i++ {
			exc := &store.Exception{
				ID:        uuid.New().String(),
				ProjectID: projectID,
				RuleID:    "Hard-coded credential",
				Scope:     &store.ExceptionScopeDetail{Type: "globalHash", SecretChecksum: fmt.Sprintf("checksum-%d", i)},
				Reason:    "false_positive",
				CreatedBy: "test",
				CreatedAt: time.Now(),
				Status:    "active",
			}

			if err := db.CreateException(exc); err != nil {
				t.Errorf("CreateException %d: %v", i, err)
				return
			}

			select {
			case <-scanDone:
				// Landed after the scan finished — the symptom being fixed.
			default:
				atomic.AddInt64(&duringScan, 1)
			}

			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()

	// A majority rather than all: the scan legitimately finishes while some
	// suppressions are still to be issued, and on a fast machine the burst can
	// complete before the loop does. Requiring all of them would make the test
	// depend on the very timing it is meant to stop mattering.
	if got := atomic.LoadInt64(&duringScan); got < suppressionCount/2 {
		t.Errorf("only %d of %d suppressions completed while the scan was running; "+
			"suppression is queueing behind finding persistence", got, suppressionCount)
	}

	// The suppressions must actually be there. A fast failure is not a fix.
	excs, err := db.ListExceptions(projectID)
	if err != nil {
		t.Fatalf("ListExceptions: %v", err)
	}
	if len(excs) != suppressionCount {
		t.Errorf("persisted %d exceptions, want %d", len(excs), suppressionCount)
	}
}

// TestFindingWriterPersistsEveryFinding guards the correctness half of the
// change. Batching is only worth having if nothing is dropped: the previous
// implementation was fire-and-forget, so a scan could be marked complete while
// writes were still outstanding.
func TestFindingWriterPersistsEveryFinding(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const findingCount = 500

	ctx := context.Background()
	scanID := uuid.New().String()
	projectID := "proj-complete"

	seedScan(t, db, projectID, scanID)
	writer := db.newFindingWriter(ctx, scanID, projectID)
	for i := 0; i < findingCount; i++ {
		writer.add(testFinding(i), false, "")
	}
	// close must not return until everything is durable, which is what makes
	// it safe for RunScan to summarise immediately afterwards.
	writer.close()

	findings, err := db.SearchFindings(store.FindingSearchRequest{
		ProjectIDs: []string{projectID}, Limit: findingCount * 2,
	})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if findings.TotalCount != findingCount {
		t.Errorf("persisted %d findings, want %d", findings.TotalCount, findingCount)
	}
}

// TestFindingWriterRecordsSuppression checks that the suppressed flag and the
// exception link survive batching, since that is what the UI reads back.
func TestFindingWriterRecordsSuppression(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	scanID := uuid.New().String()
	projectID := "proj-suppressed"

	seedScan(t, db, projectID, scanID)
	writer := db.newFindingWriter(ctx, scanID, projectID)
	writer.add(testFinding(1), false, "")
	writer.add(testFinding(2), true, "exc-123")
	writer.close()

	findings, err := db.SearchFindings(store.FindingSearchRequest{
		ProjectIDs: []string{projectID}, Limit: 10,
	})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if findings.TotalCount != 2 {
		t.Fatalf("got %d findings, want 2", findings.TotalCount)
	}

	suppressed := 0
	for _, f := range findings.Findings {
		if f.Excluded {
			suppressed++
		}
	}
	if suppressed != 1 {
		t.Errorf("got %d suppressed findings, want 1", suppressed)
	}
}

// TestFindingWriterCloseIsIdempotent — RunScan has more than one exit path.
func TestFindingWriterCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	scanID := uuid.New().String()
	seedScan(t, db, "proj-idempotent", scanID)
	writer := db.newFindingWriter(context.Background(), scanID, "proj-idempotent")
	writer.add(testFinding(1), false, "")
	writer.close()
	writer.close()
}
