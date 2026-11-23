package gitutils

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

// ErrServiceNotFound is returned when an explicit GitServiceID does not exist
// in the configured GitServiceConfig.
var ErrServiceNotFound = errors.New("git service not found")

// AuthResolver resolves transport authentication for a Git repository URL and
// optional GitServiceID. Returning (nil, nil) indicates anonymous access.
type AuthResolver interface {
	Resolve(repoURL string, serviceID string) (transport.AuthMethod, error)
}

// AuthResolverFunc adapts a plain function to AuthResolver.
type AuthResolverFunc func(repoURL string, serviceID string) (transport.AuthMethod, error)

// Resolve invokes the wrapped resolver function.
func (f AuthResolverFunc) Resolve(repoURL string, serviceID string) (transport.AuthMethod, error) {
	return f(repoURL, serviceID)
}

// ChainedAuthResolver resolves Git credentials in deterministic precedence order:
//  1. Explicit serviceID lookup in GitServiceConfig (hard error if missing).
//  2. Host-matched GitService in GitServiceConfig.
//  3. Explicit caller override (ExplicitAuth / ExplicitSSH).
//  4. Environment fallback (CHECKMATE_GIT_TOKEN, GITHUB_TOKEN, GITLAB_TOKEN,
//     CHECKMATE_SSH_KEY_PATH, SSH_AUTH_SOCK).
//  5. Anonymous (nil, nil).
type ChainedAuthResolver struct {
	ConfigManager  GitConfigManager
	Config         *GitServiceConfig
	RepoServiceIDs map[string]string
	ExplicitAuth   *GitAuth
	ExplicitSSH    *SSHAuthConfig
	DisableEnv     bool
}

// NewEnvAuthResolver builds an AuthResolver that checks environment variables
// and ssh-agent, falling back to anonymous access.
func NewEnvAuthResolver() *ChainedAuthResolver {
	return &ChainedAuthResolver{}
}

// Resolve implements AuthResolver.
func (r *ChainedAuthResolver) Resolve(repoURL string, serviceID string) (transport.AuthMethod, error) {
	if r == nil {
		return nil, nil
	}

	if serviceID == "" && len(r.RepoServiceIDs) > 0 {
		if sid, ok := r.RepoServiceIDs[repoURL]; ok {
			serviceID = sid
		} else if sid, ok := r.RepoServiceIDs[SanitiseRepoURL(repoURL)]; ok {
			serviceID = sid
		}
	}

	isSSH := IsSSHURL(repoURL)
	cfg := r.loadConfig()

	// 1. Explicit serviceID lookup. Must fail hard if not found.
	if serviceID != "" {
		if cfg == nil {
			return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, serviceID)
		}
		svc, err := cfg.FindService(serviceID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, serviceID)
		}
		if !isSSH && svc.API_Key != "" {
			return MakeHTTPAuth(svc.MakeAuth()), nil
		}
		if isSSH {
			return r.resolveSSH(repoURL)
		}
		return nil, nil
	}

	// 2. Host-matched GitService in GitServiceConfig (HTTP/HTTPS only).
	if !isSSH && cfg != nil {
		if svc := matchServiceByHost(cfg, repoURL); svc != nil && svc.API_Key != "" {
			return MakeHTTPAuth(svc.MakeAuth()), nil
		}
	}

	// 3. Explicit caller override.
	if isSSH {
		if r.ExplicitSSH != nil && (r.ExplicitSSH.PrivateKeyPath != "" || r.ExplicitSSH.UseAgent) {
			return MakeSSHAuth(ExtractSSHUser(repoURL), r.ExplicitSSH)
		}
	} else if r.ExplicitAuth != nil && (r.ExplicitAuth.Credential != "" || r.ExplicitAuth.User != "") {
		return MakeHTTPAuth(r.ExplicitAuth), nil
	}

	// 4. Environment fallback.
	if !r.DisableEnv {
		if isSSH {
			return ResolveSSHFromEnv(repoURL)
		}
		if auth := resolveHTTPFromEnv(repoURL); auth != nil {
			return auth, nil
		}
	}

	// 5. Anonymous access.
	return nil, nil
}

// ResolveInsecureSkipTLS reports whether any matching GitService explicitly
// enables InsecureSkipTLS for repoURL / serviceID.
func (r *ChainedAuthResolver) ResolveInsecureSkipTLS(repoURL, serviceID string) bool {
	if r == nil {
		return false
	}
	if serviceID == "" && len(r.RepoServiceIDs) > 0 {
		if sid, ok := r.RepoServiceIDs[repoURL]; ok {
			serviceID = sid
		} else if sid, ok := r.RepoServiceIDs[SanitiseRepoURL(repoURL)]; ok {
			serviceID = sid
		}
	}
	cfg := r.loadConfig()
	if cfg == nil {
		return false
	}
	if serviceID != "" {
		if svc, err := cfg.FindService(serviceID); err == nil {
			return svc.InsecureSkipTLS
		}
		return false
	}
	if svc := matchServiceByHost(cfg, repoURL); svc != nil {
		return svc.InsecureSkipTLS
	}
	return false
}

func (r *ChainedAuthResolver) loadConfig() *GitServiceConfig {
	if r.Config != nil {
		return r.Config
	}
	if r.ConfigManager != nil {
		if cfg, err := r.ConfigManager.GetConfig(); err == nil {
			return cfg
		}
	}
	return nil
}

func (r *ChainedAuthResolver) resolveSSH(repoURL string) (transport.AuthMethod, error) {
	if r.ExplicitSSH != nil && (r.ExplicitSSH.PrivateKeyPath != "" || r.ExplicitSSH.UseAgent) {
		return MakeSSHAuth(ExtractSSHUser(repoURL), r.ExplicitSSH)
	}
	if !r.DisableEnv {
		return ResolveSSHFromEnv(repoURL)
	}
	return nil, nil
}

// MakeHTTPAuth constructs go-git HTTP BasicAuth from a GitAuth value.
func MakeHTTPAuth(auth *GitAuth) transport.AuthMethod {
	if auth == nil {
		return nil
	}
	user := auth.User
	if user == "" {
		user = CHECKMATE_USER
	}
	return &http.BasicAuth{
		Username: user,
		Password: auth.Credential,
	}
}

// MakeSSHAuth constructs go-git SSH transport authentication from an explicit
// key file or ssh-agent.
func MakeSSHAuth(defaultUser string, cfg *SSHAuthConfig) (transport.AuthMethod, error) {
	if cfg == nil {
		return nil, nil
	}
	user := cfg.User
	if user == "" {
		user = defaultUser
	}
	if user == "" {
		user = "git"
	}
	if cfg.PrivateKeyPath != "" {
		pemBytes, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh key %s: %w", cfg.PrivateKeyPath, err)
		}
		auth, err := gitssh.NewPublicKeys(user, pemBytes, cfg.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("parse ssh key %s: %w", cfg.PrivateKeyPath, err)
		}
		return auth, nil
	}
	if cfg.UseAgent {
		auth, err := gitssh.NewSSHAgentAuth(user)
		if err != nil {
			return nil, fmt.Errorf("ssh-agent auth: %w", err)
		}
		return auth, nil
	}
	return nil, nil
}

// ResolveSSHFromEnv builds SSH transport auth from CHECKMATE_SSH_KEY_PATH (with
// optional CHECKMATE_SSH_KEY_PASSPHRASE) or falls back to ssh-agent when
// SSH_AUTH_SOCK is set.
func ResolveSSHFromEnv(repoURL string) (transport.AuthMethod, error) {
	user := ExtractSSHUser(repoURL)
	if keyPath := strings.TrimSpace(os.Getenv("CHECKMATE_SSH_KEY_PATH")); keyPath != "" {
		return MakeSSHAuth(user, &SSHAuthConfig{
			PrivateKeyPath: keyPath,
			Passphrase:     os.Getenv("CHECKMATE_SSH_KEY_PASSPHRASE"),
			User:           user,
		})
	}
	if strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")) != "" {
		return gitssh.NewSSHAgentAuth(user)
	}
	return nil, nil
}

func resolveHTTPFromEnv(repoURL string) transport.AuthMethod {
	if tok := strings.TrimSpace(os.Getenv("CHECKMATE_GIT_TOKEN")); tok != "" {
		return MakeHTTPAuth(&GitAuth{User: CHECKMATE_USER, Credential: tok})
	}
	host := strings.ToLower(ExtractRepoHost(repoURL))
	if host == "" {
		return nil
	}
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		ghHost := strings.ToLower(strings.TrimSpace(os.Getenv("GITHUB_HOST")))
		if host == "github.com" || (ghHost != "" && host == ghHost) {
			return MakeHTTPAuth(&GitAuth{User: CHECKMATE_USER, Credential: tok})
		}
	}
	if tok := strings.TrimSpace(os.Getenv("GITLAB_TOKEN")); tok != "" {
		glHost := strings.ToLower(strings.TrimSpace(os.Getenv("GITLAB_HOST")))
		if host == "gitlab.com" || (glHost != "" && host == glHost) {
			return MakeHTTPAuth(&GitAuth{User: "oauth2", Credential: tok})
		}
	}
	return nil
}

func matchServiceByHost(cfg *GitServiceConfig, repoURL string) *GitService {
	if cfg == nil || len(cfg.GitServices) == 0 {
		return nil
	}
	targetHost := strings.ToLower(ExtractRepoHost(repoURL))
	if targetHost == "" {
		return nil
	}
	// Deterministic lookup order: GitHub then GitLab, sorted by service ID.
	for _, svcType := range []GitServiceType{GitHub, GitLab} {
		services := cfg.GitServices[svcType]
		if len(services) == 0 {
			continue
		}
		var best *GitService
		for _, svc := range services {
			if svc == nil || svc.API_Key == "" {
				continue
			}
			svcHost := serviceHost(svc, svcType)
			if svcHost != "" && strings.EqualFold(svcHost, targetHost) {
				if best == nil || svc.ID < best.ID {
					best = svc
				}
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}

func serviceHost(svc *GitService, svcType GitServiceType) string {
	for _, candidate := range []string{svc.InstanceURL, svc.APIEndPoint, svc.GraphQLEndPoint} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if !strings.Contains(candidate, "://") {
			candidate = "https://" + candidate
		}
		if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	switch svcType {
	case GitHub:
		return "github.com"
	case GitLab:
		return "gitlab.com"
	default:
		return ""
	}
}

// IsSSHURL reports whether rawURL uses an SSH transport (ssh://, git+ssh://,
// or scp-style user@host:path).
func IsSSHURL(rawURL string) bool {
	s := strings.TrimSpace(rawURL)
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "ssh://") || strings.HasPrefix(lower, "git+ssh://") {
		return true
	}
	if strings.Contains(s, "://") {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") {
		return false
	}
	at := strings.Index(s, "@")
	if at <= 0 {
		return false
	}
	rest := s[at+1:]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return false
	}
	// Reject paths containing "/" before ":" (not an scp-style host).
	if strings.Contains(rest[:colon], "/") {
		return false
	}
	return true
}

// ExtractSSHUser returns the username embedded in an SSH URL, defaulting to "git".
func ExtractSSHUser(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.User != nil && u.User.Username() != "" {
			return u.User.Username()
		}
		return "git"
	}
	if at := strings.Index(s, "@"); at > 0 {
		return s[:at]
	}
	return "git"
}

// ExtractRepoHost returns the hostname component of an HTTP(S), git://, ssh://,
// or scp-style git URL.
func ExtractRepoHost(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if IsSSHURL(s) {
		at := strings.Index(s, "@")
		rest := s[at+1:]
		if colon := strings.Index(rest, ":"); colon > 0 {
			return rest[:colon]
		}
	}
	return ""
}

// SanitiseRepoURL strips embedded userinfo credentials (e.g. user:token@) from
// URLs before logging, tagging, or persisting. SCP-style git@host:path URLs
// (which carry no secret credential) and local filesystem paths are preserved.
func SanitiseRepoURL(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return s
	}
	if !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.User != nil {
		// Preserve non-secret username for ssh:// URLs if no password is set,
		// otherwise strip all userinfo so tokens/passwords can never leak.
		lowerScheme := strings.ToLower(u.Scheme)
		if (lowerScheme == "ssh" || lowerScheme == "git+ssh") {
			if _, hasPass := u.User.Password(); !hasPass {
				return u.String()
			}
			u.User = url.User(u.User.Username())
			return u.String()
		}
		u.User = nil
		return u.String()
	}
	return u.String()
}
