package account

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
)

const (
	defaultGitHubRESTBaseURL     = "https://api.github.com"
	defaultGitHubGraphQLEndpoint = "https://api.github.com/graphql"
	githubUserAgent              = "checkmate-account-resolver"
)

type resolvedCredential struct {
	authenticated   bool
	token           string
	serviceID       string
	graphqlEndpoint string
}

func (r *Resolver) resolveGitHubCredential(ref AccountRef) (resolvedCredential, error) {
	// 1. Explicit token takes precedence.
	if tok := strings.TrimSpace(r.opts.Token); tok != "" {
		return resolvedCredential{
			authenticated: true,
			token:         tok,
			serviceID:     strings.TrimSpace(ref.ServiceID),
		}, nil
	}

	// 2. Explicit ServiceID lookup: MUST fail closed (never silent anonymous fallback).
	if svcID := strings.TrimSpace(ref.ServiceID); svcID != "" {
		if r.opts.ConfigManager == nil {
			return resolvedCredential{}, fmt.Errorf("%w: service %q requested without a configured Git service store", ErrInvalidCredential, svcID)
		}
		cfg, err := r.opts.ConfigManager.GetConfig()
		if err != nil {
			return resolvedCredential{}, fmt.Errorf("%w: failed to load Git service configuration for %q", ErrInvalidCredential, svcID)
		}
		svc, err := cfg.FindService(svcID)
		if err != nil {
			return resolvedCredential{}, fmt.Errorf("%w: service %q not found", ErrInvalidCredential, svcID)
		}
		if strings.TrimSpace(svc.API_Key) == "" {
			return resolvedCredential{}, fmt.Errorf("%w: service %q has no API token configured", ErrInvalidCredential, svcID)
		}
		return resolvedCredential{
			authenticated:   true,
			token:           strings.TrimSpace(svc.API_Key),
			serviceID:       svc.ID,
			graphqlEndpoint: strings.TrimSpace(svc.GraphQLEndPoint),
		}, nil
	}

	if r.opts.AnonymousOnly {
		return resolvedCredential{authenticated: false}, nil
	}

	// 3. Look up matching GitHub service in ConfigManager if provided.
	if r.opts.ConfigManager != nil {
		if cfg, err := r.opts.ConfigManager.GetConfig(); err == nil && cfg != nil {
			var matches []*gitutils.GitService
			for svcType, services := range cfg.GitServices {
				for _, svc := range services {
					if svc == nil || strings.TrimSpace(svc.API_Key) == "" {
						continue
					}
					if svcType == gitutils.GitHub || svc.Type == gitutils.GitHub || strings.Contains(strings.ToLower(svc.InstanceURL), "github.com") {
						matches = append(matches, svc)
					}
				}
			}
			if len(matches) > 1 {
				return resolvedCredential{}, ErrAmbiguousService
			}
			if len(matches) == 1 {
				return resolvedCredential{
					authenticated:   true,
					token:           strings.TrimSpace(matches[0].API_Key),
					serviceID:       matches[0].ID,
					graphqlEndpoint: strings.TrimSpace(matches[0].GraphQLEndPoint),
				}, nil
			}
		}
	}

	// 4. Environment token lookup.
	for _, envVar := range []string{"GITHUB_TOKEN", "CHECKMATE_GIT_TOKEN"} {
		if tok := strings.TrimSpace(os.Getenv(envVar)); tok != "" {
			return resolvedCredential{
				authenticated: true,
				token:         tok,
			}, nil
		}
	}

	// 5. Anonymous default (public repositories over REST).
	return resolvedCredential{authenticated: false}, nil
}

// ---------------------------------------------------------------------------
// Anonymous GitHub REST transport
// ---------------------------------------------------------------------------

type githubRESTLister struct {
	baseURL string
	client  *http.Client
}

func (l *githubRESTLister) AccountType(ctx context.Context, login string) (string, RateLimitStatus, error) {
	endpoint := fmt.Sprintf("%s/users/%s", l.baseURL, url.PathEscape(login))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", RateLimitStatus{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := l.client.Do(req)
	if err != nil {
		return "", RateLimitStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	rl := parseRESTRateLimit(resp.Header)
	if resp.StatusCode == http.StatusNotFound {
		return "", rl, fmt.Errorf("%w: %s", ErrAccountNotFound, login)
	}
	if isRateLimitedHTTP(resp.StatusCode, rl, resp.Header) {
		return "", rl, makeRateLimitError(false, rl, resp.Header)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", rl, fmt.Errorf("github REST account lookup failed with HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", rl, fmt.Errorf("decoding github REST user response: %w", err)
	}
	return normaliseAccountType(payload.Type), rl, nil
}

func (l *githubRESTLister) ListPage(ctx context.Context, login, _ string, pageToken string) (pageResult, error) {
	endpoint := pageToken
	if endpoint == "" {
		endpoint = fmt.Sprintf("%s/users/%s/repos?per_page=100&type=owner&page=1", l.baseURL, url.PathEscape(login))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return pageResult{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := l.client.Do(req)
	if err != nil {
		return pageResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	rl := parseRESTRateLimit(resp.Header)
	if resp.StatusCode == http.StatusNotFound {
		return pageResult{}, fmt.Errorf("%w: %s", ErrAccountNotFound, login)
	}
	if isRateLimitedHTTP(resp.StatusCode, rl, resp.Header) {
		return pageResult{}, makeRateLimitError(false, rl, resp.Header)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return pageResult{}, fmt.Errorf("github REST repo listing failed with HTTP %d", resp.StatusCode)
	}

	var raw []struct {
		Name          string `json:"name"`
		CloneURL      string `json:"clone_url"`
		HTMLURL       string `json:"html_url"`
		Private       bool   `json:"private"`
		Fork          bool   `json:"fork"`
		Archived      bool   `json:"archived"`
		Disabled      bool   `json:"disabled"`
		Size          *int64 `json:"size"` // kilobytes
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return pageResult{}, fmt.Errorf("decoding github REST repos response: %w", err)
	}

	repos := make([]ResolvedRepository, 0, len(raw))
	for _, r := range raw {
		loc := normaliseCloneURL(r.CloneURL, r.HTMLURL)
		sizeBytes := int64(-1)
		if r.Size != nil {
			sizeBytes = (*r.Size) * 1024
		}
		repos = append(repos, ResolvedRepository{
			Location:      loc,
			Name:          r.Name,
			Private:       r.Private,
			Fork:          r.Fork,
			Archived:      r.Archived,
			Disabled:      r.Disabled,
			SizeBytes:     sizeBytes,
			DefaultBranch: r.DefaultBranch,
		})
	}

	nextURL := parseLinkNext(resp.Header.Get("Link"))
	return pageResult{
		Repositories: repos,
		NextToken:    nextURL,
		HasNextPage:  nextURL != "",
		RateLimit:    rl,
	}, nil
}

// ---------------------------------------------------------------------------
// Authenticated GitHub GraphQL transport
// ---------------------------------------------------------------------------

type githubGraphQLLister struct {
	endpoint string
	token    string
	client   *http.Client
}

const (
	accountTypeProbeQuery = `query($login: String!) {
		repositoryOwner(login: $login) {
			__typename
		}
		rateLimit {
			limit
			remaining
			resetAt
		}
	}`

	accountReposQuery = `query($login: String!, $cursor: String) {
		repositoryOwner(login: $login) {
			__typename
			repositories(first: 100, after: $cursor, ownerAffiliations: OWNER) {
				nodes {
					name
					url
					isPrivate
					isFork
					isArchived
					isDisabled
					diskUsage
					defaultBranchRef {
						name
					}
				}
				pageInfo {
					endCursor
					hasNextPage
				}
			}
		}
		rateLimit {
			limit
			remaining
			resetAt
		}
	}`
)

func (l *githubGraphQLLister) doGraphQL(ctx context.Context, query string, vars map[string]any, dst any) (RateLimitStatus, error) {
	body := struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables,omitempty"`
	}{
		Query:     query,
		Variables: vars,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return RateLimitStatus{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.endpoint, &buf)
	if err != nil {
		return RateLimitStatus{}, err
	}
	req.Header.Set("Authorization", "bearer "+l.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := l.client.Do(req)
	if err != nil {
		return RateLimitStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	rl := parseRESTRateLimit(resp.Header)
	if resp.StatusCode == http.StatusUnauthorized {
		return rl, fmt.Errorf("%w: GitHub GraphQL returned HTTP 401", ErrInvalidCredential)
	}
	if isRateLimitedHTTP(resp.StatusCode, rl, resp.Header) {
		return rl, makeRateLimitError(true, rl, resp.Header)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		rawErr, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return rl, fmt.Errorf("github GraphQL request failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawErr)))
	}

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return rl, fmt.Errorf("decoding github GraphQL response: %w", err)
	}
	return rl, nil
}

type graphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type graphQLRateLimit struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"resetAt"`
}

func (l *githubGraphQLLister) AccountType(ctx context.Context, login string) (string, RateLimitStatus, error) {
	var resp struct {
		Errors []graphQLError `json:"errors"`
		Data   struct {
			RepositoryOwner *struct {
				TypeName string `json:"__typename"`
			} `json:"repositoryOwner"`
			RateLimit *graphQLRateLimit `json:"rateLimit"`
		} `json:"data"`
	}

	rl, err := l.doGraphQL(ctx, accountTypeProbeQuery, map[string]any{"login": login}, &resp)
	if err != nil {
		return "", rl, err
	}
	if resp.Data.RateLimit != nil {
		rl = RateLimitStatus{
			Limit:     resp.Data.RateLimit.Limit,
			Remaining: resp.Data.RateLimit.Remaining,
			ResetAt:   resp.Data.RateLimit.ResetAt,
		}
	}
	if gErr := classifyGraphQLErrors(resp.Errors, rl); gErr != nil {
		return "", rl, gErr
	}
	if resp.Data.RepositoryOwner == nil || resp.Data.RepositoryOwner.TypeName == "" {
		return "", rl, fmt.Errorf("%w: %s", ErrAccountNotFound, login)
	}
	return normaliseAccountType(resp.Data.RepositoryOwner.TypeName), rl, nil
}

func (l *githubGraphQLLister) ListPage(ctx context.Context, login, _ string, pageToken string) (pageResult, error) {
	vars := map[string]any{"login": login}
	if pageToken != "" {
		vars["cursor"] = pageToken
	}

	var resp struct {
		Errors []graphQLError `json:"errors"`
		Data   struct {
			RepositoryOwner *struct {
				TypeName     string `json:"__typename"`
				Repositories struct {
					Nodes []struct {
						Name             string `json:"name"`
						URL              string `json:"url"`
						IsPrivate        bool   `json:"isPrivate"`
						IsFork           bool   `json:"isFork"`
						IsArchived       bool   `json:"isArchived"`
						IsDisabled       bool   `json:"isDisabled"`
						DiskUsage        *int64 `json:"diskUsage"` // kilobytes
						DefaultBranchRef *struct {
							Name string `json:"name"`
						} `json:"defaultBranchRef"`
					} `json:"nodes"`
					PageInfo struct {
						EndCursor   string `json:"endCursor"`
						HasNextPage bool   `json:"hasNextPage"`
					} `json:"pageInfo"`
				} `json:"repositories"`
			} `json:"repositoryOwner"`
			RateLimit *graphQLRateLimit `json:"rateLimit"`
		} `json:"data"`
	}

	rl, err := l.doGraphQL(ctx, accountReposQuery, vars, &resp)
	if err != nil {
		return pageResult{}, err
	}
	if resp.Data.RateLimit != nil {
		rl = RateLimitStatus{
			Limit:     resp.Data.RateLimit.Limit,
			Remaining: resp.Data.RateLimit.Remaining,
			ResetAt:   resp.Data.RateLimit.ResetAt,
		}
	}
	if gErr := classifyGraphQLErrors(resp.Errors, rl); gErr != nil {
		return pageResult{}, gErr
	}
	if resp.Data.RepositoryOwner == nil {
		return pageResult{}, fmt.Errorf("%w: %s", ErrAccountNotFound, login)
	}

	nodes := resp.Data.RepositoryOwner.Repositories.Nodes
	repos := make([]ResolvedRepository, 0, len(nodes))
	for _, n := range nodes {
		sizeBytes := int64(-1)
		if n.DiskUsage != nil {
			sizeBytes = (*n.DiskUsage) * 1024
		}
		branch := ""
		if n.DefaultBranchRef != nil {
			branch = n.DefaultBranchRef.Name
		}
		repos = append(repos, ResolvedRepository{
			Location:      normaliseCloneURL("", n.URL),
			Name:          n.Name,
			Private:       n.IsPrivate,
			Fork:          n.IsFork,
			Archived:      n.IsArchived,
			Disabled:      n.IsDisabled,
			SizeBytes:     sizeBytes,
			DefaultBranch: branch,
		})
	}

	pi := resp.Data.RepositoryOwner.Repositories.PageInfo
	return pageResult{
		Repositories: repos,
		NextToken:    pi.EndCursor,
		HasNextPage:  pi.HasNextPage,
		RateLimit:    rl,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func classifyGraphQLErrors(errs []graphQLError, rl RateLimitStatus) error {
	if len(errs) == 0 {
		return nil
	}
	for _, e := range errs {
		if strings.EqualFold(e.Type, "RATE_LIMITED") || strings.Contains(strings.ToLower(e.Message), "rate limit") {
			return &RateLimitError{
				Authenticated: true,
				Limit:         rl.Limit,
				Remaining:     rl.Remaining,
				ResetAt:       rl.ResetAt,
			}
		}
		if strings.EqualFold(e.Type, "NOT_FOUND") {
			return fmt.Errorf("%w: %s", ErrAccountNotFound, e.Message)
		}
	}
	return fmt.Errorf("github GraphQL error: %s", errs[0].Message)
}

func normaliseAccountType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "organization", "org":
		return "organization"
	default:
		return "user"
	}
}

func normaliseCloneURL(cloneURL, htmlURL string) string {
	raw := strings.TrimSpace(cloneURL)
	if raw == "" {
		raw = strings.TrimSpace(htmlURL)
	}
	if raw == "" {
		return ""
	}
	raw = strings.TrimRight(raw, "/")
	if !strings.HasSuffix(strings.ToLower(raw), ".git") {
		raw += ".git"
	}
	return raw
}

func parseRESTRateLimit(h http.Header) RateLimitStatus {
	var rl RateLimitStatus
	if v, err := strconv.Atoi(strings.TrimSpace(h.Get("X-RateLimit-Limit"))); err == nil {
		rl.Limit = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(h.Get("X-RateLimit-Remaining"))); err == nil {
		rl.Remaining = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && v > 0 {
		rl.ResetAt = time.Unix(v, 0).UTC()
	}
	return rl
}

func isRateLimitedHTTP(statusCode int, rl RateLimitStatus, h http.Header) bool {
	if statusCode == http.StatusTooManyRequests {
		return true
	}
	if statusCode == http.StatusForbidden {
		if strings.TrimSpace(h.Get("X-RateLimit-Remaining")) == "0" || strings.TrimSpace(h.Get("Retry-After")) != "" {
			return true
		}
	}
	return false
}

func makeRateLimitError(authenticated bool, rl RateLimitStatus, h http.Header) error {
	var retryAfter time.Duration
	if ra := strings.TrimSpace(h.Get("Retry-After")); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			retryAfter = time.Duration(secs) * time.Second
		}
	}
	return &RateLimitError{
		Authenticated: authenticated,
		Limit:         rl.Limit,
		Remaining:     rl.Remaining,
		ResetAt:       rl.ResetAt,
		RetryAfter:    retryAfter,
	}
}

// parseLinkNext extracts the rel="next" URL from an RFC 5988 Link header.
func parseLinkNext(header string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		sections := strings.Split(strings.TrimSpace(part), ";")
		if len(sections) < 2 {
			continue
		}
		target := strings.TrimSpace(sections[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, param := range sections[1:] {
			p := strings.TrimSpace(param)
			if p == `rel="next"` || p == "rel=next" {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}
