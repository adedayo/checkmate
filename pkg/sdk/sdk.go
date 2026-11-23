package sdk

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"gopkg.in/yaml.v3"
)

// Scanner is the main entry point for the CheckMate Go SDK.
// Create one with NewScanner and reuse it across scans — it holds no
// per-scan state.
type Scanner struct {
	opts Options
}

// NewScanner creates a new Scanner with the provided options.
func NewScanner(opts Options) *Scanner {
	return &Scanner{opts: opts}
}

// ScanPath scans one or more local filesystem paths or git repository URLs
// and returns all findings. Blocks until the scan completes.
// Returns a non-nil error if all targets fail acquisition.
//
// Paths can be any mix of:
//   - Absolute or relative local filesystem directories
//   - Git repository URLs (https://, ssh://, or git@)
func (s *Scanner) ScanPath(ctx context.Context, paths ...string) ([]Finding, error) {
	rep, err := s.ScanPathWithReport(ctx, paths...)
	if rep == nil {
		return nil, err
	}
	return rep.Findings, err
}

// ScanPathWithReport scans one or more paths or git repository URLs and returns
// both findings and structured AcquisitionReport outcomes. If all targets fail
// acquisition, a non-nil error is returned alongside the report.
func (s *Scanner) ScanPathWithReport(ctx context.Context, paths ...string) (*ScanReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	secOpts := s.buildSecretSearchOptions()
	findingsCh, pathsCh, reportCh := secrets.SearchSecretsOnPathsWithReport(ctx, paths, secOpts, "", "", nil)

	var findings []Finding
	for diag := range findingsCh {
		select {
		case <-ctx.Done():
			return &ScanReport{Findings: findings}, ctx.Err()
		default:
			findings = append(findings, s.convertDiagnostic(diag))
		}
	}
	<-pathsCh
	acq := <-reportCh

	rep := &ScanReport{
		Findings:    findings,
		Acquisition: acq,
	}
	if acq.Succeeded == 0 && acq.Failed > 0 {
		if len(acq.Failures) > 0 {
			f := acq.Failures[0]
			return rep, fmt.Errorf("failed to acquire %s (%s): %s", f.Target, f.ErrorKind, f.Message)
		}
		return rep, fmt.Errorf("all %d scan target(s) failed acquisition", acq.Failed)
	}
	return rep, nil
}

// ScanGitRepo clones and scans a remote git repository (full history).
// Equivalent to ScanPath with a git URL.
func (s *Scanner) ScanGitRepo(ctx context.Context, repoURL string) ([]Finding, error) {
	return s.ScanPath(ctx, repoURL)
}

// ScanStream scans one or more paths and streams findings as they are detected.
// The returned channel is closed when the scan completes.
// Progress is not included in the stream; use ScanStreamWithProgress for that.
func (s *Scanner) ScanStream(ctx context.Context, paths ...string) <-chan Finding {
	out := make(chan Finding, 64)
	go func() {
		defer close(out)
		secOpts := s.buildSecretSearchOptions()
		findingsCh, _ := secrets.SearchSecretsOnPaths(paths, secOpts)
		for diag := range findingsCh {
			select {
			case <-ctx.Done():
				return
			case out <- s.convertDiagnostic(diag):
			}
		}
	}()
	return out
}

// ScanStreamWithProgress scans and streams both findings and progress updates.
// Returns two channels: findings and progress. Both are closed on completion.
// Note: CheckMate plugin currently does not report progress during filesystem scans.
func (s *Scanner) ScanStreamWithProgress(ctx context.Context, paths ...string) (<-chan Finding, <-chan ScanProgress) {
	findingsOut := make(chan Finding, 64)
	progressOut := make(chan ScanProgress, 16)

	go func() {
		defer close(findingsOut)
		defer close(progressOut)

		secOpts := s.buildSecretSearchOptions()
		findingsCh, _ := secrets.SearchSecretsOnPaths(paths, secOpts)
		for diag := range findingsCh {
			select {
			case <-ctx.Done():
				return
			case findingsOut <- s.convertDiagnostic(diag):
			}
		}
	}()

	return findingsOut, progressOut
}

// buildSecretSearchOptions translates SDK Options to the internal secrets package options.
func (s *Scanner) buildSecretSearchOptions() secrets.SecretSearchOptions {
	resolver := s.opts.AuthResolver
	if resolver == nil && s.opts.GitAuth != nil {
		resolver = &gitutils.ChainedAuthResolver{
			ExplicitAuth: s.opts.GitAuth,
		}
	}
	opts := secrets.SecretSearchOptions{
		ShowSource:            s.opts.ShowSource,
		CalculateChecksum:     s.opts.CalculateChecksum,
		ExcludeTestFiles:      s.opts.ExcludeTestFiles,
		ConfidentialFilesOnly: s.opts.SensitiveFilesOnly,
		Exclusions:            diagnostics.MakeEmptyExcludes(),
		AuthResolver:          resolver,
		CloneDepth:            s.opts.GitDepth,
		FullHistory:           s.opts.GitDepth == 0,
		KeepCheckouts:         s.opts.KeepCheckouts,
		CloneBaseDir:          s.opts.CloneBaseDir,
		InsecureSkipTLS:       s.opts.InsecureSkipTLS,
	}

	if s.opts.ExclusionFile != "" {
		data, err := os.ReadFile(s.opts.ExclusionFile)
		if err != nil {
			log.Printf("sdk: warning: cannot read exclusion file %s: %v", s.opts.ExclusionFile, err)
		} else {
			var excludeDef diagnostics.ExcludeDefinition
			if err := yaml.Unmarshal(data, &excludeDef); err != nil {
				log.Printf("sdk: warning: cannot parse exclusion file %s: %v", s.opts.ExclusionFile, err)
			} else {
				merged := secrets.MergeExclusions(excludeDef, secrets.MakeCommonExclusions())
				container := diagnostics.ExcludeContainer{ExcludeDef: &merged}
				if excl, err := diagnostics.CompileExcludes(container); err == nil {
					opts.Exclusions = excl
				}
			}
		}
	}

	return opts
}

// computeFindingID generates a stable hash for a finding.
func computeFindingID(rule, repo, file string, line, column int, checksum string) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s:%s:%s:%d:%d:%s", rule, repo, file, line, column, checksum)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// convertDiagnostic converts the internal SecurityDiagnostic type to the public
// SDK Finding type with stable deterministic ID.
func (s *Scanner) convertDiagnostic(diag *diagnostics.SecurityDiagnostic) Finding {
	if diag == nil {
		return Finding{}
	}

	location := ""
	if diag.Location != nil {
		location = *diag.Location
	}

	checksum := ""
	if diag.SHA256 != nil {
		checksum = *diag.SHA256
	}
	
	source := ""
	if diag.Source != nil {
		source = *diag.Source
	}

	ruleName := diag.Justification.Headline.Description
	line := int(diag.Range.Start.Line + 1)
	col := int(diag.Range.Start.Character + 1)

	findingID := computeFindingID(
		ruleName,
		"",
		location,
		line,
		col,
		checksum,
	)

	return Finding{
		ID:                 findingID,
		RuleID:             ruleName,
		SecretType:         classifySecretType(ruleName),
		Severity:           Severity(diag.Justification.Headline.Confidence.String()),
		Confidence:         Confidence(diag.Justification.Headline.Confidence.String()),
		RepositoryURL:      "",
		CommitSHA:          "",
		Branch:             "",
		File:               location,
		Line:               line,
		Column:             col,
		EvidenceRedacted:   "", // Omitted for now unless we calculate it from source
		SecretChecksum:     checksum,
		SourceContext:      source,
		VerificationStatus: VerificationNotChecked,
	}
}

// classifySecretType maps a rule name to a structured SecretType.
func classifySecretType(ruleName string) SecretType {
	name := strings.ToUpper(ruleName)
	if strings.Contains(name, "AWS_ACCESS") {
		return SecretTypeAWSAccessKey
	}
	if strings.Contains(name, "AWS_SECRET") {
		return SecretTypeAWSSecretKey
	}
	if strings.Contains(name, "GITHUB") {
		return SecretTypeGitHubPAT
	}
	if strings.Contains(name, "RSA") {
		return SecretTypeRSAPrivateKey
	}
	if strings.Contains(name, "PASSWORD") {
		return SecretTypePassword
	}
	if strings.Contains(name, "JWT") {
		return SecretTypeJWT
	}
	return SecretTypeHighEntropy
}
