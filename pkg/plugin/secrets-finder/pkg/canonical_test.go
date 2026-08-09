package secrets

// Phase 0 harness — canonicalisation and the scan driver.
//
// Canonicalisation exists so that the finding set produced by the engine can be
// compared byte-for-byte across runs, machines and — critically — across the
// sequential engine and the forthcoming parallel one. Parallel scanning makes
// emission order nondeterministic, so ordering must be normalised away while
// preserving every semantic field.

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// canonicalFinding is a stable, machine-independent projection of
// diagnostics.SecurityDiagnostic.
//
// Every field that carries detection meaning is retained. Fields deliberately
// excluded:
//
//	ID           — not populated by the engine at this layer
//	AIAnnotation — populated post-scan by the triage layer, not the engine
//
// RepositoryIndex IS retained: it is the field corrupted by the stale
// `vendorFinders` cache, and the whole point of the Phase 1 baseline re-record
// is that this value changes visibly and intentionally.
type canonicalFinding struct {
	Location        string   `json:"location"`
	ProviderID      string   `json:"providerID"`
	RepositoryIndex int      `json:"repositoryIndex"`
	Excluded        bool     `json:"excluded"`
	StartLine       int64    `json:"startLine"`
	StartChar       int64    `json:"startChar"`
	EndLine         int64    `json:"endLine"`
	EndChar         int64    `json:"endChar"`
	HighlightStart  string   `json:"highlightStart"`
	HighlightEnd    string   `json:"highlightEnd"`
	RawStart        int64    `json:"rawStart"`
	RawEnd          int64    `json:"rawEnd"`
	Headline        string   `json:"headline"`
	HeadlineConf    string   `json:"headlineConfidence"`
	Reasons         []string `json:"reasons"`
	SHA256          string   `json:"sha256"`
	Source          string   `json:"source"`
	Tags            []string `json:"tags"`
}

// canonicalise projects a diagnostic into its stable form. `root` is stripped
// from the location so the baseline is independent of the temp directory.
func canonicalise(root string, d *diagnostics.SecurityDiagnostic) canonicalFinding {
	cf := canonicalFinding{
		RepositoryIndex: d.RepositoryIndex,
		Excluded:        d.Excluded,
		StartLine:       d.Range.Start.Line,
		StartChar:       d.Range.Start.Character,
		EndLine:         d.Range.End.Line,
		EndChar:         d.Range.End.Character,
		HighlightStart: fmt.Sprintf("%d:%d",
			d.HighlightRange.Start.Line, d.HighlightRange.Start.Character),
		HighlightEnd: fmt.Sprintf("%d:%d",
			d.HighlightRange.End.Line, d.HighlightRange.End.Character),
		Headline:     d.Justification.Headline.Description,
		HeadlineConf: d.Justification.Headline.Confidence.String(),
		Reasons:      []string{},
		Tags:         []string{},
	}

	if d.Location != nil {
		cf.Location = relativeLocation(root, *d.Location)
	}
	if d.ProviderID != nil {
		cf.ProviderID = *d.ProviderID
	}
	if d.SHA256 != nil {
		cf.SHA256 = *d.SHA256
	}
	if d.Source != nil {
		cf.Source = *d.Source
	}
	for _, r := range d.Justification.Reasons {
		cf.Reasons = append(cf.Reasons, fmt.Sprintf("%s|%s", r.Description, r.Confidence.String()))
	}
	// Reasons order is detector-defined and stable; do NOT sort — a change in
	// reason ordering is a genuine behavioural change worth catching.
	if d.Tags != nil {
		cf.Tags = append(cf.Tags, *d.Tags...)
		// Tags accumulate from several independent sources (test/confidential
		// classification, branch, repository attributes) whose interleaving is
		// not semantically meaningful, so these ARE sorted.
		sort.Strings(cf.Tags)
	}

	cf.RawStart = d.RawRange.StartIndex
	cf.RawEnd = d.RawRange.EndIndex
	return cf
}

// relativeLocation converts an absolute corpus path into a slash-separated
// path relative to the corpus root, so baselines are portable across machines
// and operating systems.
func relativeLocation(root, loc string) string {
	if rel, err := filepath.Rel(root, loc); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(loc)
}

// canonicalKey is the total ordering used to sort findings. It must be a total
// order over the corpus — any ties would reintroduce nondeterminism once
// scanning is parallelised — so it deliberately extends all the way down to
// the evidence and source text.
func canonicalKey(c canonicalFinding) string {
	return strings.Join([]string{
		c.Location,
		fmt.Sprintf("%012d", c.StartLine),
		fmt.Sprintf("%012d", c.StartChar),
		fmt.Sprintf("%012d", c.EndLine),
		fmt.Sprintf("%012d", c.EndChar),
		fmt.Sprintf("%012d", c.RawStart),
		fmt.Sprintf("%012d", c.RawEnd),
		c.ProviderID,
		c.SHA256,
		c.Headline,
		c.HeadlineConf,
		strings.Join(c.Reasons, ","),
		strings.Join(c.Tags, ","),
		c.Source,
		fmt.Sprintf("%d", c.RepositoryIndex),
		fmt.Sprintf("%t", c.Excluded),
	}, "\x00")
}

// canonicaliseAll projects, sorts and returns the full finding set.
func canonicaliseAll(root string, diags []*diagnostics.SecurityDiagnostic) []canonicalFinding {
	out := make([]canonicalFinding, 0, len(diags))
	for _, d := range diags {
		out = append(out, canonicalise(root, d))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return canonicalKey(out[i]) < canonicalKey(out[j])
	})
	return out
}

// serialiseCanonical renders the finding set as indented JSON with a trailing
// newline, so golden files diff cleanly in review.
func serialiseCanonical(findings []canonicalFinding) ([]byte, error) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ---------------------------------------------------------------------------
// Scan driver
// ---------------------------------------------------------------------------

// scanRun is the outcome of driving the engine over a corpus.
type scanRun struct {
	Findings []*diagnostics.SecurityDiagnostic
	Files    []util.RepositoryIndexedFile
	Duration time.Duration
}

// baselineOptions are the options used for the golden baseline.
//
// ShowSource and CalculateChecksum are both enabled so that the baseline
// covers the source-extraction and hashing paths — the latter matters because
// Phase 3 moves checksum computation inline (S2) and must not change a single
// hash.
func baselineOptions() SecretSearchOptions {
	return SecretSearchOptions{
		ShowSource:            true,
		CalculateChecksum:     true,
		Exclusions:            diagnostics.MakeEmptyExcludes(),
		ConfidentialFilesOnly: false,
		Verbose:               false,
		ReportIgnored:         false,
		ExcludeTestFiles:      false,
	}
}

// runScan drives the current engine over `paths` and collects everything it
// emits. It drains both returned channels; failing to drain `pathsOut` would
// deadlock the producer goroutine, since that channel is unbuffered.
func runScan(tb testing.TB, opts SecretSearchOptions, paths ...string) scanRun {
	tb.Helper()

	start := time.Now()
	diagsCh, pathsCh := SearchSecretsOnPaths(paths, opts)

	var run scanRun
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range pathsCh {
			run.Files = append(run.Files, f...)
		}
	}()

	for d := range diagsCh {
		run.Findings = append(run.Findings, d)
	}
	<-done

	run.Duration = time.Since(start)
	return run
}

// runScanWithTimeout fails the test if the scan exceeds `limit`. Used by the
// adversarial fixtures, where the current engine's O(n^2) behaviour is the
// thing under measurement and an unbounded run would hang CI.
func runScanWithTimeout(tb testing.TB, limit time.Duration, opts SecretSearchOptions, paths ...string) scanRun {
	tb.Helper()

	type result struct{ run scanRun }
	ch := make(chan result, 1)
	go func() {
		ch <- result{run: runScan(tb, opts, paths...)}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()

	select {
	case r := <-ch:
		return r.run
	case <-ctx.Done():
		tb.Fatalf("scan of %v did not complete within %v", paths, limit)
		return scanRun{}
	}
}
