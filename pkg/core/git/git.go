package gitutils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// Clone clones or updates a repository, returning the location on disk where
// the checkout is placed. Any embedded credentials in repository are redacted
// from CloneDetail.Repository and log output.
func Clone(ctx context.Context, repository string, options *GitCloneOptions) (CloneDetail, error) {
	if options == nil {
		options = &GitCloneOptions{}
	}

	repoURL := strings.TrimSpace(repository)
	safeURL := SanitiseRepoURL(repoURL)

	dir, err := GetCheckoutLocation(repoURL, options.BaseDir)

	out := CloneDetail{
		Location:   dir,
		Repository: safeURL,
	}

	defer func() {
		if err != nil {
			log.Printf("Clone error (%s): %v, %s\n", safeURL, redactURLSecrets(err.Error(), repoURL, safeURL), dir)
		}
	}()

	if err != nil {
		return out, err
	}

	if err = ctx.Err(); err != nil {
		return out, err
	}

	auth, err := resolveCloneAuth(repoURL, options)
	if err != nil {
		return out, err
	}

	dirExisted := !dirDoesNotExist(dir)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return out, err
	}
	_ = os.Chmod(dir, 0700)

	insecureSkipTLS := options.InsecureSkipTLS
	if !insecureSkipTLS {
		if chained, ok := options.AuthResolver.(*ChainedAuthResolver); ok {
			insecureSkipTLS = chained.ResolveInsecureSkipTLS(repoURL, options.ServiceID)
		}
	}

	var repo *git.Repository

	if directoryIsEmpty(dir) {
		repo, err = cloneFresh(ctx, dir, repoURL, auth, options.Depth, insecureSkipTLS, options.CommitHash != "")
		if err != nil {
			if !dirExisted {
				_ = os.RemoveAll(dir)
			}
			return out, err
		}
	} else {
		repo, err = openAndRefresh(ctx, dir, repoURL, auth, options.Depth, insecureSkipTLS, options.CommitHash != "")
		if err != nil {
			return out, err
		}
	}

	if head, e := repo.Head(); e == nil {
		branch := head.Name().Short()
		out.Branch = &branch
	}

	if options.CommitHash != "" {
		var w *git.Worktree
		w, err = repo.Worktree()
		if err != nil {
			return out, err
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash:  plumbing.NewHash(options.CommitHash),
			Force: true,
		})
		if err != nil {
			return out, err
		}
	}

	return out, nil
}

func resolveCloneAuth(repoURL string, options *GitCloneOptions) (transport.AuthMethod, error) {
	if options.AuthMethod != nil {
		return options.AuthMethod, nil
	}
	if options.AuthResolver != nil {
		return options.AuthResolver.Resolve(repoURL, options.ServiceID)
	}
	if options.Auth != nil {
		return MakeHTTPAuth(options.Auth), nil
	}
	if IsSSHURL(repoURL) {
		return ResolveSSHFromEnv(repoURL)
	}
	return nil, nil
}

func cloneFresh(ctx context.Context, dir, repoURL string, auth transport.AuthMethod, depth int, insecureSkipTLS, noCheckout bool) (*git.Repository, error) {
	return git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:             repoURL,
		Auth:            auth,
		Depth:           depth,
		InsecureSkipTLS: insecureSkipTLS,
		NoCheckout:      noCheckout,
	})
}

// openAndRefresh fetches updates into an existing checkout directory and resets
// the working tree to the fetched remote HEAD so retained checkouts never scan
// stale files. If the directory is corrupt or cannot be refreshed cleanly, it
// is wiped and freshly cloned.
func openAndRefresh(ctx context.Context, dir, repoURL string, auth transport.AuthMethod, depth int, insecureSkipTLS, noCheckout bool) (*git.Repository, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		if rmErr := resetDirForReclone(dir); rmErr != nil {
			return nil, rmErr
		}
		return cloneFresh(ctx, dir, repoURL, auth, depth, insecureSkipTLS, noCheckout)
	}

	fetchErr := repo.FetchContext(ctx, &git.FetchOptions{
		Auth:            auth,
		Depth:           depth,
		InsecureSkipTLS: insecureSkipTLS,
		Force:           true,
		RefSpecs:        []config.RefSpec{"+refs/heads/*:refs/remotes/origin/*"},
	})
	if fetchErr != nil && fetchErr != git.NoErrAlreadyUpToDate {
		// Propagate auth/network/TLS errors rather than masking them with a reclone.
		kind := ClassifyCloneError(fetchErr)
		if kind == AcqErrAuth || kind == AcqErrNotFound || kind == AcqErrTLS || kind == AcqErrNetwork {
			return nil, fetchErr
		}
		if rmErr := resetDirForReclone(dir); rmErr != nil {
			return nil, rmErr
		}
		return cloneFresh(ctx, dir, repoURL, auth, depth, insecureSkipTLS, noCheckout)
	}

	if !noCheckout {
		targetHash, resolveErr := resolveRemoteHeadHash(repo)
		if resolveErr == nil && !targetHash.IsZero() {
			w, wtErr := repo.Worktree()
			if wtErr == nil {
				if resetErr := w.Reset(&git.ResetOptions{
					Mode:   git.HardReset,
					Commit: targetHash,
				}); resetErr != nil {
					if rmErr := resetDirForReclone(dir); rmErr != nil {
						return nil, rmErr
					}
					return cloneFresh(ctx, dir, repoURL, auth, depth, insecureSkipTLS, noCheckout)
				}
			}
		}
	}

	return repo, nil
}

func resetDirForReclone(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

func resolveRemoteHeadHash(repo *git.Repository) (plumbing.Hash, error) {
	if head, err := repo.Head(); err == nil && head.Name().IsBranch() {
		remoteRefName := plumbing.NewRemoteReferenceName("origin", head.Name().Short())
		if ref, err := repo.Reference(remoteRefName, true); err == nil {
			return ref.Hash(), nil
		}
	}
	if ref, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", "HEAD"), true); err == nil {
		return ref.Hash(), nil
	}
	for _, fallback := range []string{"main", "master"} {
		if ref, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", fallback), true); err == nil {
			return ref.Hash(), nil
		}
	}
	if head, err := repo.Head(); err == nil {
		return head.Hash(), nil
	}
	return plumbing.ZeroHash, fmt.Errorf("cannot resolve remote HEAD")
}

func redactURLSecrets(msg, rawURL, safeURL string) string {
	if rawURL != safeURL && rawURL != "" {
		msg = strings.ReplaceAll(msg, rawURL, safeURL)
	}
	if strings.Contains(rawURL, "://") {
		if u, err := url.Parse(rawURL); err == nil && u.User != nil {
			if pass, ok := u.User.Password(); ok && pass != "" {
				msg = strings.ReplaceAll(msg, pass, "***")
			}
		}
	}
	return msg
}

// GetCheckoutLocation returns a deterministic, collision-free checkout path on
// disk for the specified git repository under baseDirectory. Incorporating a
// short hash of the canonical sanitised URL guarantees that repositories with
// the same basename under different owners or hosts (e.g. orgA/api vs orgB/api)
// never overwrite each other.
func GetCheckoutLocation(repository, baseDirectory string) (string, error) {
	canonical := canonicalRepoKey(repository)
	repoName := extractRepoBaseName(canonical)
	if repoName == "" {
		repoName = "repo"
	}
	sum := sha256.Sum256([]byte(canonical))
	suffix := hex.EncodeToString(sum[:4]) // 8 hex chars
	dirName := fmt.Sprintf("%s-%s", repoName, suffix)
	return filepath.Abs(filepath.Clean(filepath.Join(baseDirectory, dirName)))
}

func canonicalRepoKey(repository string) string {
	s := SanitiseRepoURL(strings.TrimSpace(repository))
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return s
}

func extractRepoBaseName(canonical string) string {
	s := strings.TrimSpace(canonical)
	if IsSSHURL(s) && !strings.Contains(s, "://") {
		if colon := strings.Index(s, ":"); colon >= 0 && colon+1 < len(s) {
			s = s[colon+1:]
		}
	} else if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Path != "" {
			s = u.Path
		}
	}
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimRight(s, "/")
	base := path.Base(s)
	base = strings.TrimSuffix(base, ".git")
	if base == "." || base == "/" {
		return ""
	}
	return base
}

// GitToHTTPS replaces scp-style git@host:owner/repo URLs with https://host/owner/repo.
// Retained for compatibility with legacy callers; Clone no longer rewrites SSH URLs.
func GitToHTTPS(repository string) string {
	repository = strings.TrimSpace(repository)
	if strings.HasPrefix(strings.ToLower(repository), "git@") {
		repository = strings.Replace(repository, ":", "/", 1)
		repository = repository[4:]
		repository = fmt.Sprintf("https://%s", repository)
	}
	return repository
}

func dirDoesNotExist(dir string) bool {
	_, err := os.Stat(dir)
	return os.IsNotExist(err)
}

func directoryIsEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()

	_, err = f.Readdirnames(1)
	return err == io.EOF
}

