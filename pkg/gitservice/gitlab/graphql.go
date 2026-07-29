package gitlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"golang.org/x/net/context/ctxhttp"
)

func queryProjects(ctx context.Context, query string, gitService *gitutils.GitService) (projects projectsQueryResult, err error) {
	in := struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables,omitempty"`
	}{
		Query:     query,
		Variables: map[string]interface{}{},
	}
	var buff bytes.Buffer
	err = json.NewEncoder(&buff).Encode(in)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", gitService.GraphQLEndPoint, &buff)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", gitService.API_Key))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ctxhttp.Do(ctx, &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //support self-signed GitLab servers. TODO: make configurable
		},
	}}, req)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var out struct {
		Data struct {
			Projects projectsQueryResult
		}
	}

	err = json.NewDecoder(resp.Body).Decode(&out)
	if err == nil {
		projects = out.Data.Projects
	}
	return
}

// retrieve the repository name from the url e.g. https://gitlab.com/adedayo/checkmate.git returns checkmate
func getRepositoryName(url string) string {
	tokens := strings.Split(url, "/")

	if len(tokens) > 0 {
		name := strings.TrimSuffix(tokens[len(tokens)-1], ".git")
		return name
	}
	return url
}
