package gitutils

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/src-d/go-git.v4"
)

//Clone a repository,returning the location on disk where the clone is placed
func Clone(repository string) (string, error) {
	repository = strings.ToLower(repository)
	//git@ is not supported, replace with https://
	if strings.HasPrefix(repository, "git@") {
		repository = strings.Replace(strings.Replace(repository, ":", "/", 1), "git@", "https://", 1)
	}

	dir, err := ioutil.TempDir("", "checkmate")
	if err != nil {
		return dir, err
	}
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL: repository,
		// Progress: os.Stdout,
	})

	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func getGithubDetail(repo string) (githubRepo, error) {
	var detail githubRepo
	repURL, err := url.Parse(repo)
	if err != nil {
		return detail, err
	}
	api := strings.Replace(strings.TrimSuffix(repURL.String(), ".git"), "//github.com", "//api.github.com/repos", 1)
	response, err := http.Get(api)
	if err != nil {
		return detail, err
	}
	err = json.NewDecoder(response.Body).Decode(&detail)
	return detail, err
}

type githubRepo struct {
	Size int64
}
