package sqlite

import (
	"context"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/store"
)

// exceptionMatcher decides whether a finding is covered by an active exception.
//
// This is the *store-side* half of suppression, and it exists because the
// engine-side half cannot help mid-scan. BuildExclusionProvider compiles an
// ExclusionProvider once, before the scanner starts, so an exception created
// while a scan is running has no effect on that scan at all — the provider the
// workers are consulting was built minutes ago. The matcher is what lets a
// suppression created at, say, file 40,000 of 90,000 apply to the findings
// still to come, and (via reconcile) to the ones already recorded.
//
// It previously understood scope types — "global", "project", "directory",
// "file", "line" — that nothing in the product ever writes. The desktop app and
// the API both write "globalHash", "globalString", "globalRegex", "pathRegex",
// "pathString", "pathHash" and "pathRegexRegex", which are the types
// BuildExclusionProvider handles. The two sets did not intersect, so the switch
// never matched anything and every finding was recorded unsuppressed. The
// scope types below are therefore the ones actually in use; the legacy names
// are kept because old databases may still contain them.
//
// Semantics deliberately mirror diagnostics.CompileExcludes, so that a
// suppression applied mid-scan and the same suppression applied by the engine
// on the next scan agree about which findings they cover. Where they disagree,
// the operator sees a finding vanish on rescan for no visible reason.
type exceptionMatcher struct {
	entries []exceptionEntry
}

type exceptionEntry struct {
	exception *store.Exception

	// Pre-compiled so the findings loop does not pay compilation per finding.
	// A regex that fails to compile disables only its own entry: a malformed
	// exception should suppress nothing, not abort the scan.
	valueRegex *regexp.Regexp
	pathRegex  *regexp.Regexp
}

// newExceptionMatcher builds a matcher from every exception that is active and
// unexpired at the moment of the call. Callers refresh it to pick up changes.
func newExceptionMatcher(exceptions []*store.Exception) *exceptionMatcher {
	m := &exceptionMatcher{}
	now := time.Now()

	for _, exc := range exceptions {
		if exc == nil || exc.Scope == nil {
			continue
		}
		if exc.Status != "active" {
			continue
		}
		if exc.ExpiresAt != nil && exc.ExpiresAt.Before(now) {
			continue
		}

		entry := exceptionEntry{exception: exc}

		switch exc.Scope.Type {
		case "globalRegex", "pathRegexRegex":
			re, err := regexp.Compile(exc.Scope.RegexMatch)
			if err != nil {
				continue
			}
			entry.valueRegex = re
		case "pathRegex":
			re, err := regexp.Compile(exc.Scope.RegexMatch)
			if err != nil {
				continue
			}
			entry.pathRegex = re
		}

		// pathRegexRegex scopes a value regex to a *path pattern*, matching
		// ExcludeDefinition.PathRegexExcludedRegExs, whose map key is a path
		// regex rather than a literal path.
		if exc.Scope.Type == "pathRegexRegex" {
			re, err := regexp.Compile(exc.Scope.Path)
			if err != nil {
				continue
			}
			entry.pathRegex = re
		}

		m.entries = append(m.entries, entry)
	}

	return m
}

func (m *exceptionMatcher) empty() bool {
	return m == nil || len(m.entries) == 0
}

// match reports whether the finding is suppressed, and by which exception.
func (m *exceptionMatcher) match(finding *diagnostics.SecurityDiagnostic) (bool, string) {
	if m == nil || finding == nil {
		return false, ""
	}

	ruleName := finding.Justification.Headline.Description

	location := ""
	if finding.Location != nil {
		location = *finding.Location
	}
	checksum := ""
	if finding.SHA256 != nil {
		checksum = *finding.SHA256
	}
	source := ""
	if finding.Source != nil {
		source = *finding.Source
	}

	for _, entry := range m.entries {
		exc := entry.exception
		if exc.RuleID != "" && exc.RuleID != "*" && exc.RuleID != ruleName {
			continue
		}

		scope := exc.Scope
		switch scope.Type {

		// Value-based, project-wide.
		case "globalHash", "value":
			if checksum != "" && checksum == scope.SecretChecksum {
				return true, exc.ID
			}
		case "globalString":
			if scope.StringMatch != "" && strings.Contains(source, scope.StringMatch) {
				return true, exc.ID
			}
		case "globalRegex":
			if entry.valueRegex != nil && source != "" && entry.valueRegex.MatchString(source) {
				return true, exc.ID
			}

		// Path-based.
		case "pathRegex":
			if entry.pathRegex != nil && location != "" && entry.pathRegex.MatchString(location) {
				return true, exc.ID
			}
		case "pathString":
			if pathsEqual(location, scope.Path) && scope.StringMatch != "" &&
				strings.Contains(source, scope.StringMatch) {
				return true, exc.ID
			}
		case "pathHash":
			if pathsEqual(location, scope.Path) && checksum != "" && checksum == scope.SecretChecksum {
				return true, exc.ID
			}
		case "pathRegexRegex":
			if entry.pathRegex != nil && entry.valueRegex != nil &&
				location != "" && entry.pathRegex.MatchString(location) &&
				entry.valueRegex.MatchString(source) {
				return true, exc.ID
			}

		// Legacy scope types. Never written by the current product, but a
		// database that predates the rename may still hold them.
		case "global", "project":
			return true, exc.ID
		case "directory":
			if location != "" && scope.Path != "" && strings.HasPrefix(location, scope.Path) {
				return true, exc.ID
			}
		case "file":
			if pathsEqual(location, scope.Path) {
				return true, exc.ID
			}
		case "line":
			if pathsEqual(location, scope.Path) && scope.LineStart != nil && scope.LineEnd != nil {
				line := int(finding.Range.Start.Line + 1)
				if line >= *scope.LineStart && line <= *scope.LineEnd {
					return true, exc.ID
				}
			}
		}
	}

	return false, ""
}

// pathsEqual compares a finding's location with an exception's path.
//
// Both should be absolute, but exceptions can be imported from another machine
// or hand-edited, so a suffix match on a path boundary is accepted. Requiring
// the boundary is what stops "/src/app.go" from matching "/src/myapp.go".
func pathsEqual(location, path string) bool {
	if location == "" || path == "" {
		return false
	}
	if location == path {
		return true
	}
	if strings.HasSuffix(location, path) && strings.HasPrefix(path, "/") {
		return true
	}
	return false
}

// matchException evaluates a finding against a list of exceptions.
func matchException(finding *diagnostics.SecurityDiagnostic, exceptions []*store.Exception) (bool, string) {
	return newExceptionMatcher(exceptions).match(finding)
}

// listExceptionsQuietly fetches a project's exceptions, treating failure as
// "no exceptions".
//
// This runs on the scan goroutine's refresh path, where a transient read error
// must not abort a scan that may have been running for an hour. The cost of
// swallowing it is one refresh interval of stale suppressions.
func (d *DB) listExceptionsQuietly(projectID string) []*store.Exception {
	exceptions, err := d.ListExceptions(projectID)
	if err != nil {
		log.Printf("listExceptionsQuietly: %v", err)
		return nil
	}
	return exceptions
}

// reconcileSuppressions applies the final exception set to findings already
// recorded for a scan.
//
// Suppression is one-way here: a finding covered by an exception is marked
// suppressed. The reverse — un-suppressing because an exception was revoked
// mid-scan — is deliberately not done. A revocation means "I want to see this
// again", which is a request about future scans; retroactively resurrecting
// findings inside a scan the operator is watching would be a surprise, and the
// next scan surfaces them anyway.
//
// The findings slice is updated in place as well as the database, because the
// summary, severity counts and score are computed from it.
func (d *DB) reconcileSuppressions(ctx context.Context, scanID, projectID string, findings []*diagnostics.SecurityDiagnostic) {
	if len(findings) == 0 {
		return
	}

	matcher := newExceptionMatcher(d.listExceptionsQuietly(projectID))
	if matcher.empty() {
		return
	}

	type pending struct {
		findingID   string
		exceptionID string
	}
	var updates []pending

	for _, finding := range findings {
		if finding == nil || finding.Excluded {
			continue
		}
		suppressed, excID := matcher.match(finding)
		if !suppressed {
			continue
		}
		finding.Excluded = true
		updates = append(updates, pending{
			findingID:   computeFindingID(finding),
			exceptionID: excID,
		})
	}

	if len(updates) == 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("reconcileSuppressions: begin: %v", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		UPDATE findings
		SET suppressed = 1, exception_id = ?
		WHERE scan_id = ? AND finding_id = ?`)
	if err != nil {
		log.Printf("reconcileSuppressions: prepare: %v", err)
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, u := range updates {
		var excID interface{}
		if u.exceptionID != "" {
			excID = u.exceptionID
		}
		if _, err := stmt.ExecContext(ctx, excID, scanID, u.findingID); err != nil {
			log.Printf("reconcileSuppressions: update %s: %v", u.findingID, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("reconcileSuppressions: commit: %v", err)
		return
	}
	committed = true

	log.Printf("reconcileSuppressions: retroactively suppressed %d finding(s) in scan %s", len(updates), scanID)
}
