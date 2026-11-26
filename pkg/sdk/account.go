package sdk

import (
	"context"
	"path/filepath"
	"strings"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/gitservice/account"
	homedir "github.com/mitchellh/go-homedir"
)

// Account resolution types exported by the SDK. Provider-neutral by contract:
// no provider-specific types appear in the SDK surface.
type (
	AccountRef         = account.AccountRef
	AccountFilter      = account.AccountFilter
	ResolvedRepository = account.ResolvedRepository
	RateLimitStatus    = account.RateLimitStatus
	AccountResolution  = account.AccountResolution
)

// Typed account resolution errors.
var (
	ErrNotAnAccount        = account.ErrNotAnAccount
	ErrAccountNotFound     = account.ErrAccountNotFound
	ErrTooManyRepositories = account.ErrTooManyRepositories
	ErrRateLimited         = account.ErrRateLimited
	ErrAmbiguousService    = account.ErrAmbiguousService
	ErrInvalidCredential   = account.ErrInvalidCredential
)

// ParseAccountRef parses an account URL (for example "https://github.com/adedayo"),
// provider-qualified shorthand ("github:adedayo"), or login. Repository URLs
// are rejected with ErrNotAnAccount.
func ParseAccountRef(s string) (AccountRef, error) {
	return account.ParseAccountRef(s)
}

// DefaultAccountFilter returns the documented default repository filter
// (excludes archived, disabled, and fork repositories; includes private
// repositories where credentials can see them).
//
// IMPORTANT: The zero value AccountFilter{} is NOT equivalent to the defaults
// because IncludePrivate defaults to true while its zero value is false.
func DefaultAccountFilter() AccountFilter {
	return account.DefaultAccountFilter()
}

// ResolveAccount resolves a hosting account into a canonically sorted list of
// repositories without requiring an HTTP server, subprocess, or credentials.
// Anonymous resolution succeeds with zero configuration, returning public
// repositories with Authenticated: false and PotentiallyIncomplete: true.
func ResolveAccount(ctx context.Context, ref AccountRef, f AccountFilter) (AccountResolution, error) {
	return resolveAccountWithOptions(ctx, ref, f, account.ResolveOptions{
		ConfigManager: defaultSDKConfigManager(),
	})
}

// ResolveAccount resolves an account using the Scanner's configured GitAuth
// credential (if provided) and falls back to default environment/config or
// anonymous resolution.
func (s *Scanner) ResolveAccount(ctx context.Context, ref AccountRef, f AccountFilter) (AccountResolution, error) {
	opts := account.ResolveOptions{
		ConfigManager: defaultSDKConfigManager(),
	}
	if s != nil && s.opts.GitAuth != nil && strings.TrimSpace(s.opts.GitAuth.Credential) != "" {
		opts.Token = strings.TrimSpace(s.opts.GitAuth.Credential)
	}
	return resolveAccountWithOptions(ctx, ref, f, opts)
}

func resolveAccountWithOptions(ctx context.Context, ref AccountRef, f AccountFilter, opts account.ResolveOptions) (AccountResolution, error) {
	return account.NewResolver(opts).Resolve(ctx, ref, f)
}

func defaultSDKConfigManager() gitutils.GitConfigManager {
	if home, err := homedir.Dir(); err == nil && home != "" {
		return gitutils.NewGitConfigManager(filepath.Join(home, ".checkmate"))
	}
	return nil
}
