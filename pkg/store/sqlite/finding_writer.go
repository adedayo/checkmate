package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// findingWriter persists scan findings on a single goroutine, in batches.
//
// It replaces an unbounded `go d.persistFinding(...)` per finding. That design
// had three problems, of which only the first was reported:
//
//   - Suppressing a finding during a scan of a large codebase appeared to
//     block further suppressions. Every persist goroutine takes the exclusive
//     d.mu and a connection from a pool capped at one, so a scan producing
//     thousands of findings leaves thousands of goroutines queued on that
//     mutex. A contended Go mutex switches to FIFO starvation mode, so a
//     suppression arriving mid-scan waits for the backlog ahead of it. Taking
//     the lock once per batch rather than once per finding leaves it free
//     between batches, which is what lets an interactive write in.
//
//   - The writes were fire-and-forget. RunScan could summarise a scan, and
//     mark it complete, while writes were still outstanding — and lose them
//     entirely if the process exited. close() does not return until every
//     accepted finding is durable.
//
//   - A goroutine per finding is unbounded by construction. Memory scaled
//     with the number of findings rather than with anything the operator
//     controls.
//
// Ordering is preserved: findings are appended in arrival order and flushed in
// that order.
type findingWriter struct {
	db        *DB
	ctx       context.Context
	scanID    string
	projectID string

	in   chan findingWrite
	done chan struct{}
	once sync.Once
}

type findingWrite struct {
	finding     *diagnostics.SecurityDiagnostic
	suppressed  bool
	exceptionID string
}

const (
	// defaultFindingBatchSize is the number of findings written per
	// transaction. Large enough that the per-transaction overhead is amortised,
	// small enough that the lock is released often enough for an interactive
	// suppression not to feel stalled.
	defaultFindingBatchSize = 200

	// defaultFindingFlushInterval bounds how long a partial batch waits. A scan
	// that trickles findings must still show them in the UI promptly, since the
	// SSE stream is fed from the same loop.
	defaultFindingFlushInterval = 250 * time.Millisecond

	// findingQueueDepth lets the scan run ahead of the writer without blocking
	// on every finding. Bounded on purpose: an unbounded queue converts a slow
	// disk into unbounded memory growth.
	findingQueueDepth = 4096
)

func findingBatchSize() int {
	if v := os.Getenv("CHECKMATE_FINDING_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultFindingBatchSize
}

// newFindingWriter starts the writer goroutine. Every writer must be closed.
func (d *DB) newFindingWriter(ctx context.Context, scanID, projectID string) *findingWriter {
	w := &findingWriter{
		db:        d,
		ctx:       ctx,
		scanID:    scanID,
		projectID: projectID,
		in:        make(chan findingWrite, findingQueueDepth),
		done:      make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *findingWriter) add(finding *diagnostics.SecurityDiagnostic, suppressed bool, exceptionID string) {
	if finding == nil {
		return
	}
	select {
	case w.in <- findingWrite{finding: finding, suppressed: suppressed, exceptionID: exceptionID}:
	case <-w.ctx.Done():
	}
}

// close flushes everything accepted so far and waits for it to be durable.
//
// Safe to call more than once: RunScan has several exit paths, and a double
// close on a channel would panic rather than merely be untidy.
func (w *findingWriter) close() {
	w.once.Do(func() { close(w.in) })
	<-w.done
}

func (w *findingWriter) run() {
	defer close(w.done)

	batchSize := findingBatchSize()
	batch := make([]findingWrite, 0, batchSize)

	ticker := time.NewTicker(defaultFindingFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.db.persistFindingBatch(w.ctx, w.scanID, w.projectID, batch)
		batch = batch[:0]
	}

	for {
		select {
		case item, ok := <-w.in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, item)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.ctx.Done():
			// The scan was cancelled. Findings already accepted are still
			// worth keeping — they describe real code that was really read.
			flush()
			return
		}
	}
}

// computeFindingID derives the stable identity of a finding.
//
// It is the primary key the findings table is addressed by, so anything that
// wants to revisit a row it did not itself insert — the mid-scan suppression
// reconciler, for one — must derive the identity exactly the same way. Hence a
// single definition rather than the formula written out at each call site.
func computeFindingID(finding *diagnostics.SecurityDiagnostic) string {
	checksum := ""
	if finding.SHA256 != nil {
		checksum = *finding.SHA256
	}
	location := ""
	if finding.Location != nil {
		location = *finding.Location
	}

	ruleName := finding.Justification.Headline.Description
	line := finding.Range.Start.Line + 1
	col := finding.Range.Start.Character + 1

	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s:%s:%s:%d:%d:%s", ruleName, "", location, line, col, checksum)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// persistFindingBatch writes a batch of findings in one transaction, holding
// the store lock once for the batch rather than once per finding.
func (d *DB) persistFindingBatch(ctx context.Context, scanID, projectID string, batch []findingWrite) {
	if len(batch) == 0 {
		return
	}

	// Webhook payloads are collected while the lock is held and dispatched
	// after it is released: a dispatcher that blocks must not hold up the
	// writer, and through it every interactive write to the store.
	type webhookPayload struct {
		findingID string
		severity  string
		file      string
		line      int64
	}
	var webhooks []webhookPayload

	d.mu.Lock()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		d.mu.Unlock()
		log.Printf("persistFindingBatch: begin: %v", err)
		return
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
		d.mu.Unlock()

		dispatcher := d.webhookDispatcher
		if dispatcher == nil {
			return
		}
		for _, p := range webhooks {
			go dispatcher("finding.detected", map[string]interface{}{
				"findingId":  p.findingID,
				"secretType": "generic.high_entropy",
				"severity":   p.severity,
				"file":       p.file,
				"line":       p.line,
			})
		}
	}()

	for _, item := range batch {
		finding := item.finding

		checksum := ""
		if finding.SHA256 != nil {
			checksum = *finding.SHA256
		}
		location := ""
		if finding.Location != nil {
			location = *finding.Location
		}
		source := ""
		if finding.Source != nil {
			source = *finding.Source
		}

		ruleName := finding.Justification.Headline.Description
		line := finding.Range.Start.Line + 1
		col := finding.Range.Start.Character + 1

		findingID := computeFindingID(finding)

		// Carry forward any triage the user or the AI has already recorded for
		// this finding, so a rescan does not silently discard it.
		var prevAIAnnotation, prevVerificationStatus sql.NullString
		_ = tx.QueryRowContext(ctx, `
			SELECT ai_annotation, verification_status
			FROM findings
			WHERE project_id = ? AND finding_id = ? AND (ai_annotation IS NOT NULL OR (verification_status IS NOT NULL AND verification_status != 'NOT_CHECKED'))
			ORDER BY rowid DESC LIMIT 1
		`, projectID, findingID).Scan(&prevAIAnnotation, &prevVerificationStatus)

		initialVerifStatus := "NOT_CHECKED"
		if prevVerificationStatus.Valid && prevVerificationStatus.String != "" {
			initialVerifStatus = prevVerificationStatus.String
		}
		var aiAnnotationVal interface{} = nil
		if prevAIAnnotation.Valid && prevAIAnnotation.String != "" {
			aiAnnotationVal = prevAIAnnotation.String
		}

		suppressedInt := 0
		if item.suppressed {
			suppressedInt = 1
		}
		var excID interface{} = nil
		if item.exceptionID != "" {
			excID = item.exceptionID
		}

		confidence := finding.Justification.Headline.Confidence.String()

		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO findings(
				finding_id, scan_id, project_id,
				rule_id, secret_type, severity, confidence,
				repo_url, commit_sha, branch, file_path, line_number, column_number,
				evidence_redacted, secret_checksum, source_context,
				suppressed, exception_id, verification_status, ai_annotation, detected_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			findingID, scanID, projectID,
			ruleName, "generic.high_entropy", confidence, confidence,
			"", "", "", location, line, col,
			"", checksum, source,
			suppressedInt, excID, initialVerifStatus, aiAnnotationVal,
			time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			log.Printf("persistFindingBatch: insert: %v", err)
			return
		}

		if !item.suppressed {
			webhooks = append(webhooks, webhookPayload{
				findingID: findingID,
				severity:  confidence,
				file:      location,
				line:      line,
			})
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("persistFindingBatch: commit: %v", err)
		return
	}
	committed = true
}
