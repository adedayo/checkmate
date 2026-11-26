package account

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
)

// AccountResolver resolves a provider account reference into a canonically
// sorted, filtered list of repositories.
type AccountResolver interface {
	Resolve(ctx context.Context, ref AccountRef, filter AccountFilter) (AccountResolution, error)
}

// ResolveOptions configures a Resolver instance. All fields are optional.
type ResolveOptions struct {
	// MaxRepos overrides CHECKMATE_ACCOUNT_MAX_REPOS and DefaultMaxRepos (500).
	MaxRepos int
	// Token is an explicit personal access token for authenticated resolution.
	Token string
	// AnonymousOnly disables automatic environment/config token lookup.
	AnonymousOnly bool
	// ConfigManager is an optional GitConfigManager used for ServiceID / host lookup.
	ConfigManager gitutils.GitConfigManager
	// HTTPClient is an optional HTTP client (defaults to http.DefaultClient).
	HTTPClient *http.Client
	// GitHubRESTBaseURL overrides https://api.github.com (primarily for testing).
	GitHubRESTBaseURL string
	// GitHubGraphQLEndpoint overrides https://api.github.com/graphql (primarily for testing).
	GitHubGraphQLEndpoint string
}

// repoLister is the narrow transport seam implemented by both the anonymous
// REST transport and the authenticated GraphQL transport. Filtering, sorting,
// deduplication, cap enforcement, and result assembly live strictly above this
// interface so both transports behave identically.
type repoLister interface {
	AccountType(ctx context.Context, login string) (string, RateLimitStatus, error)
	ListPage(ctx context.Context, login, accountType, pageToken string) (pageResult, error)
}

type pageResult struct {
	Repositories []ResolvedRepository
	NextToken    string
	HasNextPage  bool
	RateLimit    RateLimitStatus
}

// Resolver is the default AccountResolver supporting GitHub (anonymous REST
// and authenticated GraphQL).
type Resolver struct {
	opts ResolveOptions
}

// NewResolver constructs a Resolver with the provided options.
func NewResolver(opts ResolveOptions) *Resolver {
	return &Resolver{opts: opts}
}

// Resolve resolves ref using the appropriate transport, applies filter,
// enforces the repository cap, and returns a canonically sorted resolution.
func (r *Resolver) Resolve(ctx context.Context, ref AccountRef, filter AccountFilter) (AccountResolution, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	provider := strings.ToLower(strings.TrimSpace(ref.Provider))
	if provider == "" {
		provider = ProviderGitHub
	}
	login := strings.TrimSpace(ref.Login)
	if login == "" {
		return AccountResolution{}, fmt.Errorf("%w: empty login", ErrNotAnAccount)
	}
	ref.Provider = provider
	ref.Login = login

	if provider != ProviderGitHub {
		return AccountResolution{}, fmt.Errorf("%w: %q", ErrUnsupportedProvider, provider)
	}

	cred, err := r.resolveGitHubCredential(ref)
	if err != nil {
		return AccountResolution{}, err
	}

	client := r.opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var lister repoLister
	if cred.authenticated {
		endpoint := r.opts.GitHubGraphQLEndpoint
		if endpoint == "" {
			endpoint = cred.graphqlEndpoint
		}
		if endpoint == "" {
			endpoint = defaultGitHubGraphQLEndpoint
		}
		lister = &githubGraphQLLister{
			endpoint: endpoint,
			token:    cred.token,
			client:   client,
		}
	} else {
		baseURL := r.opts.GitHubRESTBaseURL
		if baseURL == "" {
			baseURL = defaultGitHubRESTBaseURL
		}
		lister = &githubRESTLister{
			baseURL: strings.TrimRight(baseURL, "/"),
			client:  client,
		}
	}

	maxRepos := resolveMaxRepos(r.opts.MaxRepos)
	return resolveWithLister(ctx, lister, ref, filter, cred.authenticated, cred.serviceID, maxRepos)
}

func resolveMaxRepos(explicit int) int {
	if explicit > 0 {
		return explicit
	}
	if v, ok := os.LookupEnv("CHECKMATE_ACCOUNT_MAX_REPOS"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return DefaultMaxRepos
}

func resolveWithLister(
	ctx context.Context,
	lister repoLister,
	ref AccountRef,
	filter AccountFilter,
	authenticated bool,
	serviceID string,
	maxRepos int,
) (AccountResolution, error) {
	accountType, rl, err := lister.AccountType(ctx, ref.Login)
	if err != nil {
		return AccountResolution{}, err
	}

	seen := make(map[string]struct{})
	seenTokens := make(map[string]struct{})
	excluded := make(map[string]int)
	var kept []ResolvedRepository
	var totalObserved int
	var totalSize int64

	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return AccountResolution{}, err
		}

		page, err := lister.ListPage(ctx, ref.Login, accountType, pageToken)
		if err != nil {
			return AccountResolution{}, err
		}
		if page.RateLimit.Limit > 0 || !page.RateLimit.ResetAt.IsZero() {
			rl = page.RateLimit
		}

		for _, repo := range page.Repositories {
			if repo.Location == "" {
				continue
			}
			if _, dup := seen[repo.Location]; dup {
				continue
			}
			seen[repo.Location] = struct{}{}
			totalObserved++
			if maxRepos > 0 && totalObserved > maxRepos {
				return AccountResolution{}, &TooManyRepositoriesError{
					Observed: totalObserved,
					Limit:    maxRepos,
				}
			}

			if reason, drop := filterRepository(repo, filter, authenticated); drop {
				excluded[reason]++
				continue
			}

			kept = append(kept, repo)
			if repo.SizeBytes > 0 {
				totalSize += repo.SizeBytes
			}
		}

		if !page.HasNextPage {
			break
		}
		if page.NextToken == "" || page.NextToken == pageToken {
			return AccountResolution{}, fmt.Errorf("%w: repeated or empty page token %q", ErrNonAdvancingProgress, page.NextToken)
		}
		if _, visited := seenTokens[page.NextToken]; visited {
			return AccountResolution{}, fmt.Errorf("%w: cyclic page token %q", ErrNonAdvancingProgress, page.NextToken)
		}
		seenTokens[page.NextToken] = struct{}{}
		pageToken = page.NextToken
	}

	// Guardrail 6 (determinism): single canonical byte-wise ascending sort by
	// clone URL so enrolment order is independent of page arrival and transport.
	sort.Slice(kept, func(i, j int) bool {
		return kept[i].Location < kept[j].Location
	})
	if kept == nil {
		kept = []ResolvedRepository{}
	}

	res := AccountResolution{
		Ref:            ref,
		AccountType:    accountType,
		Authenticated:  authenticated,
		ServiceID:      serviceID,
		Repositories:   kept,
		ExcludedCounts: excluded,
		TotalSizeBytes: totalSize,
		RateLimit:      rl,
	}
	if !authenticated {
		res.PotentiallyIncomplete = true
		res.IncompletenessReason = "Resolved anonymously; private repositories are not visible."
	}
	return res, nil
}

// filterRepository applies filter rules in deterministic precedence order and
// returns (exclusionReason, true) if repo should be excluded.
func filterRepository(repo ResolvedRepository, f AccountFilter, authenticated bool) (string, bool) {
	if repo.Archived && !f.IncludeArchived {
		return "archived", true
	}
	if repo.Disabled && !f.IncludeDisabled {
		return "disabled", true
	}
	if repo.Fork && !f.IncludeForks {
		return "fork", true
	}
	// Spec R6: includePrivate has no effect on anonymous resolutions and MUST
	// NOT record exclusions there.
	if authenticated && repo.Private && !f.IncludePrivate {
		return "private", true
	}
	// ExcludeNames takes precedence over IncludeNames.
	if len(f.ExcludeNames) > 0 && matchesAnyGlob(repo.Name, f.ExcludeNames) {
		return "excludeNames", true
	}
	if len(f.IncludeNames) > 0 && !matchesAnyGlob(repo.Name, f.IncludeNames) {
		return "includeNames", true
	}
	return "", false
}

func matchesAnyGlob(name string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if matched, err := path.Match(pat, name); err == nil && matched {
			return true
		}
	}
	return false
}
