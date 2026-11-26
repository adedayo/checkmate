package account

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxRepos is the default repository enrolment/resolution cap
	// (overridable via CHECKMATE_ACCOUNT_MAX_REPOS or ResolveOptions.MaxRepos).
	DefaultMaxRepos = 500

	// ProviderGitHub identifies the GitHub hosting provider.
	ProviderGitHub = "github"
)

// Typed errors returned by account parsing and resolution.
var (
	ErrNotAnAccount         = errors.New("reference points to a repository or invalid path rather than an account")
	ErrAccountNotFound      = errors.New("account not found")
	ErrTooManyRepositories  = errors.New("account exceeds maximum repository cap")
	ErrRateLimited          = errors.New("provider API rate limit exceeded")
	ErrAmbiguousService     = errors.New("multiple configured git services match this provider; specify --service / ServiceID")
	ErrInvalidCredential    = errors.New("explicit git credential or service is invalid or unauthorized")
	ErrUnsupportedProvider  = errors.New("unsupported git hosting provider")
	ErrNonAdvancingProgress = errors.New("provider pagination failed to advance")
)

// TooManyRepositoriesError wraps ErrTooManyRepositories with the observed count and cap.
type TooManyRepositoriesError struct {
	Observed int
	Limit    int
}

func (e *TooManyRepositoriesError) Error() string {
	return fmt.Sprintf("%s: observed at least %d repositories (cap: %d; raise CHECKMATE_ACCOUNT_MAX_REPOS or --max-repos to override)",
		ErrTooManyRepositories.Error(), e.Observed, e.Limit)
}

func (e *TooManyRepositoriesError) Unwrap() error { return ErrTooManyRepositories }

// RateLimitError wraps ErrRateLimited with reset metadata and guidance.
type RateLimitError struct {
	Authenticated bool
	Limit         int
	Remaining     int
	ResetAt       time.Time
	RetryAfter    time.Duration
}

func (e *RateLimitError) Error() string {
	var b strings.Builder
	b.WriteString(ErrRateLimited.Error())
	if !e.ResetAt.IsZero() {
		fmt.Fprintf(&b, " (resets at %s)", e.ResetAt.UTC().Format(time.RFC3339))
	} else if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " (retry after %s)", e.RetryAfter.Round(time.Second))
	}
	if !e.Authenticated {
		b.WriteString("; anonymous GitHub API requests are limited to 60/hour per IP - provide a GitHub token (--git-token, GITHUB_TOKEN, or --service) to raise the limit to 5,000/hour")
	}
	return b.String()
}

func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// AccountRef identifies a hosting account in a provider-neutral form.
type AccountRef struct {
	Provider  string `json:"provider"`            // e.g. "github"
	Login     string `json:"login"`               // account or organization login
	ServiceID string `json:"serviceId,omitempty"` // optional configured git service ID
}

// AccountFilter controls which repositories are retained from an account.
//
// IMPORTANT: The zero value of AccountFilter is NOT the documented defaults
// because IncludePrivate defaults to true while its Go zero value is false.
// Call DefaultAccountFilter() to obtain the standard defaults.
type AccountFilter struct {
	IncludeArchived bool     `json:"includeArchived"`
	IncludeDisabled bool     `json:"includeDisabled"`
	IncludeForks    bool     `json:"includeForks"`
	IncludePrivate  bool     `json:"includePrivate"`
	IncludeNames    []string `json:"includeNames,omitempty"`
	ExcludeNames    []string `json:"excludeNames,omitempty"`
}

// DefaultAccountFilter returns the documented default repository filter:
// excludes archived, disabled, and fork repositories; includes private
// repositories when credentials can see them.
func DefaultAccountFilter() AccountFilter {
	return AccountFilter{
		IncludeArchived: false,
		IncludeDisabled: false,
		IncludeForks:    false,
		IncludePrivate:  true,
	}
}

// ResolvedRepository is the provider-neutral representation of a repository
// belonging to a resolved account.
type ResolvedRepository struct {
	Location      string `json:"location"`                // canonical clone URL (https://github.com/owner/repo.git)
	Name          string `json:"name"`                    // repository name
	Private       bool   `json:"private"`                 // true if private
	Fork          bool   `json:"fork"`                    // true if fork
	Archived      bool   `json:"archived"`                // true if archived
	Disabled      bool   `json:"disabled,omitempty"`      // true if disabled
	SizeBytes     int64  `json:"sizeBytes"`               // size in bytes (-1 if unknown)
	DefaultBranch string `json:"defaultBranch,omitempty"` // default branch name
}

// RateLimitStatus surfaces provider quota telemetry from the resolution.
type RateLimitStatus struct {
	Limit     int       `json:"limit,omitempty"`
	Remaining int       `json:"remaining,omitempty"`
	ResetAt   time.Time `json:"resetAt,omitempty"`
}

// AccountResolution is the complete, deterministically ordered result of
// resolving a hosting account.
type AccountResolution struct {
	Ref                   AccountRef           `json:"ref"`
	AccountType           string               `json:"accountType"` // "user" | "organization"
	Authenticated         bool                 `json:"authenticated"`
	ServiceID             string               `json:"serviceId,omitempty"`
	PotentiallyIncomplete bool                 `json:"potentiallyIncomplete"`
	IncompletenessReason  string               `json:"incompletenessReason,omitempty"`
	Repositories          []ResolvedRepository `json:"repositories"` // canonically sorted by Location
	ExcludedCounts        map[string]int       `json:"excludedCounts,omitempty"`
	TotalSizeBytes        int64                `json:"totalSizeBytes"`
	RateLimit             RateLimitStatus      `json:"rateLimit,omitempty"`
}

// ParseAccountRef parses an account URL (https://github.com/<login>),
// provider-qualified shorthand (github:<login>), or rejects repository URLs
// with ErrNotAnAccount.
func ParseAccountRef(raw string) (AccountRef, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return AccountRef{}, fmt.Errorf("%w: empty reference", ErrNotAnAccount)
	}

	// Reject SSH git repository URLs (git@github.com:owner/repo.git).
	if strings.HasPrefix(s, "git@") {
		return AccountRef{}, fmt.Errorf("%w: %q is a repository URL", ErrNotAnAccount, raw)
	}

	// Provider-qualified shorthand: github:<login>
	if !strings.Contains(s, "://") && strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", 2)
		provider := strings.ToLower(strings.TrimSpace(parts[0]))
		rest := strings.Trim(strings.TrimSpace(parts[1]), "/")
		if provider != ProviderGitHub {
			return AccountRef{}, fmt.Errorf("%w: %q", ErrUnsupportedProvider, provider)
		}
		if rest == "" || strings.Contains(rest, "/") {
			return AccountRef{}, fmt.Errorf("%w: %q", ErrNotAnAccount, raw)
		}
		return AccountRef{Provider: ProviderGitHub, Login: rest}, nil
	}

	// URL form: https://github.com/<login>[/]
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return AccountRef{}, fmt.Errorf("%w: %v", ErrNotAnAccount, err)
		}
		host := strings.ToLower(u.Hostname())
		if host != "github.com" && host != "www.github.com" {
			return AccountRef{}, fmt.Errorf("%w: host %q", ErrUnsupportedProvider, host)
		}
		trimmed := strings.Trim(u.Path, "/")
		if trimmed == "" {
			return AccountRef{}, fmt.Errorf("%w: missing login in %q", ErrNotAnAccount, raw)
		}
		segments := strings.Split(trimmed, "/")
		if len(segments) > 1 {
			return AccountRef{}, fmt.Errorf("%w: %q looks like a repository or sub-path, not an account", ErrNotAnAccount, raw)
		}
		login := strings.TrimSpace(segments[0])
		if login == "" || strings.HasSuffix(strings.ToLower(login), ".git") {
			return AccountRef{}, fmt.Errorf("%w: %q", ErrNotAnAccount, raw)
		}
		return AccountRef{Provider: ProviderGitHub, Login: login}, nil
	}

	// Bare login with no slash -> default to GitHub account login.
	if strings.Contains(s, "/") {
		return AccountRef{}, fmt.Errorf("%w: %q looks like owner/repo, not an account", ErrNotAnAccount, raw)
	}
	return AccountRef{Provider: ProviderGitHub, Login: s}, nil
}
