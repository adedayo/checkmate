package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// These tests cover mid-scan suppression.
//
// Two things were wrong. The first was silent: matchException switched on scope
// types ("global", "project", "directory", "file", "line") that nothing in the
// product writes. The desktop app and the API both write "globalHash",
// "globalString", "globalRegex", "pathRegex", "pathString", "pathHash" and
// "pathRegexRegex". The sets did not intersect, so the store-side suppression
// check never matched anything and every finding was recorded unsuppressed —
// with no error anywhere to say so.
//
// The second was scope: even a working matcher was built once, before the
// findings loop, so an exception created during a scan did not affect that
// scan.

func excScope(t string, scope *store.ExceptionScopeDetail) *store.Exception {
	return &store.Exception{
		ID:     "exc-" + t,
		RuleID: "*",
		Status: "active",
		Scope:  scope,
	}
}

func findingAt(path, checksum, source string, line int64) *diagnostics.SecurityDiagnostic {
	return &diagnostics.SecurityDiagnostic{
		Location: &path,
		SHA256:   &checksum,
		Source:   &source,
		Range: code.Range{
			Start: code.Position{Line: line, Character: 0},
			End:   code.Position{Line: line, Character: 10},
		},
		Justification: diagnostics.Justification{
			Headline: diagnostics.Evidence{
				Description: "Hard-coded credential",
				Confidence:  diagnostics.High,
			},
		},
	}
}

// TestMatcherUnderstandsTheScopeTypesTheProductWrites is the regression test
// for the dead switch. Every scope type below is one the desktop app creates;
// before the fix, not one of them suppressed anything.
func TestMatcherUnderstandsTheScopeTypesTheProductWrites(t *testing.T) {
	finding := findingAt("/repo/pkg/api/keys.go", "abc123", `key := "AKIAIOSFODNN7EXAMPLE"`, 41)

	cases := []struct {
		name    string
		scope   *store.ExceptionScopeDetail
		matches bool
	}{
		{"globalHash matches on checksum", &store.ExceptionScopeDetail{
			Type: "globalHash", SecretChecksum: "abc123"}, true},
		{"globalHash ignores a different checksum", &store.ExceptionScopeDetail{
			Type: "globalHash", SecretChecksum: "different"}, false},

		{"globalString matches on the secret text", &store.ExceptionScopeDetail{
			Type: "globalString", StringMatch: "AKIAIOSFODNN7EXAMPLE"}, true},
		{"globalString ignores unrelated text", &store.ExceptionScopeDetail{
			Type: "globalString", StringMatch: "not-in-source"}, false},

		{"globalRegex matches the value", &store.ExceptionScopeDetail{
			Type: "globalRegex", RegexMatch: `AKIA[0-9A-Z]{16}`}, true},
		{"globalRegex that does not match", &store.ExceptionScopeDetail{
			Type: "globalRegex", RegexMatch: `^ghp_[0-9a-z]+$`}, false},

		{"pathRegex matches the file path", &store.ExceptionScopeDetail{
			Type: "pathRegex", RegexMatch: `/pkg/api/`}, true},
		{"pathRegex on another tree", &store.ExceptionScopeDetail{
			Type: "pathRegex", RegexMatch: `/vendor/`}, false},

		{"pathHash matches path and checksum", &store.ExceptionScopeDetail{
			Type: "pathHash", Path: "/repo/pkg/api/keys.go", SecretChecksum: "abc123"}, true},
		{"pathHash right hash wrong file", &store.ExceptionScopeDetail{
			Type: "pathHash", Path: "/repo/pkg/api/other.go", SecretChecksum: "abc123"}, false},

		{"pathString matches path and text", &store.ExceptionScopeDetail{
			Type: "pathString", Path: "/repo/pkg/api/keys.go", StringMatch: "AKIAIOSFODNN7EXAMPLE"}, true},

		{"pathRegexRegex matches both patterns", &store.ExceptionScopeDetail{
			Type: "pathRegexRegex", Path: `/pkg/api/.*\.go$`, RegexMatch: `AKIA[0-9A-Z]{16}`}, true},
		{"pathRegexRegex path matches but value does not", &store.ExceptionScopeDetail{
			Type: "pathRegexRegex", Path: `/pkg/api/.*\.go$`, RegexMatch: `ghp_[0-9a-z]+`}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, id := matchException(finding, []*store.Exception{excScope(tc.scope.Type, tc.scope)})
			require.Equal(t, tc.matches, matched)
			if tc.matches {
				require.NotEmpty(t, id, "a match must name the exception that caused it")
			}
		})
	}
}

// A path exception must not leak onto a file whose name merely ends the same
// way. "/src/app.go" is not "/src/myapp.go".
func TestPathScopeDoesNotMatchOnPartialSegment(t *testing.T) {
	finding := findingAt("/repo/src/myapp.go", "abc123", "secret", 1)
	matched, _ := matchException(finding, []*store.Exception{
		excScope("pathHash", &store.ExceptionScopeDetail{
			Type: "pathHash", Path: "/src/app.go", SecretChecksum: "abc123"}),
	})
	require.False(t, matched)
}

// An exception whose regex does not compile must suppress nothing, and must not
// take the scan down with it.
func TestMalformedRegexExceptionIsInert(t *testing.T) {
	finding := findingAt("/repo/a.go", "abc123", "secret", 1)
	matched, _ := matchException(finding, []*store.Exception{
		excScope("globalRegex", &store.ExceptionScopeDetail{
			Type: "globalRegex", RegexMatch: "([unclosed"}),
	})
	require.False(t, matched)
}

// Inactive and expired exceptions must not suppress.
func TestOnlyActiveUnexpiredExceptionsSuppress(t *testing.T) {
	finding := findingAt("/repo/a.go", "abc123", "secret", 1)

	revoked := excScope("globalHash", &store.ExceptionScopeDetail{
		Type: "globalHash", SecretChecksum: "abc123"})
	revoked.Status = "revoked"
	matched, _ := matchException(finding, []*store.Exception{revoked})
	require.False(t, matched, "a revoked exception must not suppress")

	yesterday := time.Now().Add(-24 * time.Hour)
	expired := excScope("globalHash", &store.ExceptionScopeDetail{
		Type: "globalHash", SecretChecksum: "abc123"})
	expired.ExpiresAt = &yesterday
	matched, _ = matchException(finding, []*store.Exception{expired})
	require.False(t, matched, "an expired exception must not suppress")
}

// A rule-scoped exception must not suppress findings from other rules.
func TestRuleScopedExceptionDoesNotSuppressOtherRules(t *testing.T) {
	finding := findingAt("/repo/a.go", "abc123", "secret", 1)

	exc := excScope("globalHash", &store.ExceptionScopeDetail{
		Type: "globalHash", SecretChecksum: "abc123"})
	exc.RuleID = "Some other rule"

	matched, _ := matchException(finding, []*store.Exception{exc})
	require.False(t, matched)
}

// TestReconcileSuppressesFindingsRecordedBeforeTheException is the test for the
// retroactive pass.
//
// The scenario: a scan of a large codebase produces thousands of copies of the
// same false positive. The operator suppresses it part-way through. Without
// reconciliation the findings recorded before that click stay visible and the
// ones after are hidden — the same secret gets two different verdicts in one
// scan, decided by timing, and the summary and score are computed from the
// mixture.
func TestReconcileSuppressesFindingsRecordedBeforeTheException(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projectID := uuid.NewString()
	scanID := uuid.NewString()
	seedScan(t, db, projectID, scanID)

	ctx := context.Background()

	// The scan runs and records everything unsuppressed: at this point no
	// exception exists.
	const findingCount = 10
	var findings []*diagnostics.SecurityDiagnostic
	writer := db.newFindingWriter(ctx, scanID, projectID)
	for i := 0; i < findingCount; i++ {
		f := findingAt(
			fmt.Sprintf("/repo/vendor/dep_%d.go", i),
			fmt.Sprintf("checksum-%d", i),
			`token := "AKIAIOSFODNN7EXAMPLE"`,
			int64(i),
		)
		findings = append(findings, f)
		writer.add(f, false, "")
	}
	writer.close()

	require.Equal(t, 0, countSuppressed(t, db, scanID),
		"precondition: nothing suppressed yet")

	// Mid-scan, the operator decides everything under /vendor/ is noise.
	createVendorException(t, db, projectID)

	db.reconcileSuppressions(ctx, scanID, projectID, findings)

	require.Equal(t, findingCount, countSuppressed(t, db, scanID),
		"every finding recorded before the exception should now be suppressed")

	// The in-memory slice matters too: the summary, severity counts and score
	// are computed from it, not from the database.
	for i, f := range findings {
		require.True(t, f.Excluded, "finding %d should be marked excluded in memory", i)
	}
}

// Reconciliation must leave findings the exception does not cover alone.
func TestReconcileLeavesUncoveredFindingsAlone(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projectID := uuid.NewString()
	scanID := uuid.NewString()
	seedScan(t, db, projectID, scanID)
	ctx := context.Background()

	vendored := findingAt("/repo/vendor/dep.go", "c1", "secret", 1)
	ours := findingAt("/repo/pkg/api/keys.go", "c2", "secret", 2)

	writer := db.newFindingWriter(ctx, scanID, projectID)
	writer.add(vendored, false, "")
	writer.add(ours, false, "")
	writer.close()

	createVendorException(t, db, projectID)

	db.reconcileSuppressions(ctx, scanID, projectID,
		[]*diagnostics.SecurityDiagnostic{vendored, ours})

	require.Equal(t, 1, countSuppressed(t, db, scanID))
	require.True(t, vendored.Excluded)
	require.False(t, ours.Excluded, "a finding in our own code must remain visible")
}

// With no exceptions at all, reconciliation must be a no-op rather than an
// error or a mass suppression.
func TestReconcileWithNoExceptionsIsANoOp(t *testing.T) {
	db, err := New(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	projectID := uuid.NewString()
	scanID := uuid.NewString()
	seedScan(t, db, projectID, scanID)
	ctx := context.Background()

	f := findingAt("/repo/a.go", "c1", "secret", 1)
	writer := db.newFindingWriter(ctx, scanID, projectID)
	writer.add(f, false, "")
	writer.close()

	db.reconcileSuppressions(ctx, scanID, projectID, []*diagnostics.SecurityDiagnostic{f})

	require.Equal(t, 0, countSuppressed(t, db, scanID))
	require.False(t, f.Excluded)
}

// createVendorException suppresses anything under a /vendor/ path — the
// canonical "thousands of false positives from code we did not write" case.
func createVendorException(t *testing.T, db *DB, projectID string) {
	t.Helper()
	require.NoError(t, db.CreateException(&store.Exception{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		RuleID:    "*",
		Status:    "active",
		Reason:    "vendored dependency",
		CreatedAt: time.Now(),
		Scope: &store.ExceptionScopeDetail{
			Type:       "pathRegex",
			RegexMatch: `/vendor/`,
		},
	}))
}

func countSuppressed(t *testing.T, db *DB, scanID string) int {
	t.Helper()
	var n int
	err := db.db.QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND suppressed = 1`, scanID).Scan(&n)
	require.NoError(t, err)
	return n
}
