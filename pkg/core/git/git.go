package gitutils

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Clone a repository,returning the location on disk where the clone is placed
func Clone(ctx context.Context, repository string, options *GitCloneOptions) (CloneDetail, error) {

	dir, err := GetCheckoutLocation(repository, options.BaseDir)

	out := CloneDetail{
		Location:   dir,
		Repository: repository,
	}

	defer func() {
		if err != nil {
			log.Printf("Clone error: %v, %s\n", err, dir)
		}
	}()

	if err != nil {
		return out, err
	}

	if err = os.MkdirAll(dir, 0755); err != nil {
		return out, err
	}

	var repo *git.Repository

	var auth *http.BasicAuth
	if options.Auth != nil {
		auth = &http.BasicAuth{
			Username: options.Auth.User,
			Password: options.Auth.Credential,
		}
	}

	if directoryIsEmpty(dir) {

		repo, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL: repository,
			// Progress: os.Stdout,
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem Git servers TODO: make configurable
			NoCheckout:      options.CommitHash != "",
		})
		if err != nil {
			return out, err
		}

		//record the branch
		if head, e := repo.Head(); e == nil {
			branch := head.Name().Short()
			out.Branch = &branch
		}

	} else {
		//the directory already exists, so, simply fetch if possible
		repo, err = git.PlainOpen(dir)

		if err != nil {
			return out, err
		}

		//record the branch
		if head, e := repo.Head(); e == nil {
			branch := head.Name().Short()
			out.Branch = &branch
		}

		err = repo.FetchContext(ctx, &git.FetchOptions{
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem Git servers TODO: make configurable
			Force:           true,
		})

		if err != nil && err != git.NoErrAlreadyUpToDate {
			return out, err
		}

		err = nil
	}

	if options.CommitHash != "" {
		w, err := repo.Worktree()
		if err != nil {
			return out, err
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(options.CommitHash),
		})

		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// returns the checkout location on disk for the specified git repository, given a base directory
// The pattern for base directory is baseDirectory := path.Join(pm.GetCodeBaseDir(), projectID)
func GetCheckoutLocation(repository, baseDirectory string) (string, error) {
	repository = GitToHTTPS(repository)
	return filepath.Abs(path.Clean(path.Join(baseDirectory, strings.TrimSuffix(path.Base(repository), ".git"))))
}

// replaces git@ with https:// in repository URL
func GitToHTTPS(repository string) string {
	//git@ is not supported, replace with https://
	repository = strings.TrimSpace(repository)
	if strings.HasPrefix(strings.ToLower(repository), "git@") {
		repository = strings.Replace(repository, ":", "/", 1) //replace the : in e.g. git@github.com:adedayo/checkmate.git with a /
		repository = repository[4:]                           //cut out git@
		repository = fmt.Sprintf("https://%s", repository)
	}
	return repository
}

// // returns the checkout location on disk for the specified file, given a base directory
// // The pattern for base directory is baseDirectory := path.Join(pm.GetCodeBaseDir(), projectID)
// func GetRepositoryLocation(repository, baseDirectory string) (string, error) {
// 	repository = normaliseRepository(repository)
// 	return filepath.Abs(path.Clean(path.Join(baseDirectory, path.Base(strings.Split(repository, ".git")[0]))))

// }

func directoryIsEmpty(dir string) bool {

	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	return err == io.EOF

}
