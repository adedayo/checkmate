package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/util"
	"github.com/adedayo/checkmate/pkg/gitservice/gitlab"
)

func discoverGitLab(w http.ResponseWriter, r *http.Request) {

	config, err := configManager.GetConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var pagedSearch gitlab.GitLabPagedSearch

	if err := json.NewDecoder(r.Body).Decode(&pagedSearch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	gitService, err := config.FindService(pagedSearch.ServiceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proj, loc, err := gitlab.GetRepositories(r.Context(), gitService, &pagedSearch)

	if err != nil {
		log.Printf("Error: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(gitlab.GitLabProjectSearchResult{
		InstanceID:             gitService.ID,
		Projects:               proj,
		EndCursor:              loc.EndCursor,
		HasNextPage:            loc.HasNextPage,
		RemainingProjectsCount: getCount(loc),
	}); err != nil {
		log.Printf("Error encoding response: %v\n", err)
	}
}

func getCount(loc gitlab.GitLabCursorLocation) int64 {
	if loc.HasNextPage {
		if x, err := base64.RawStdEncoding.DecodeString(loc.EndCursor); err == nil {
			var out struct {
				ID string `json:"id"`
			}
			if e := json.Unmarshal(x, &out); e == nil {
				n, err := strconv.ParseInt(out.ID, 10, 0)
				if err != nil {
					log.Printf("%v", e)
					return 0
				}
				return n
			} else {
				log.Printf("%v", e)
			}
		} else {
			log.Printf("%v", err)
		}
	}
	return 0
}

func integrateGitLab(w http.ResponseWriter, r *http.Request) {
	var detail gitutils.GitService
	if err := json.NewDecoder(r.Body).Decode(&detail); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	detail.InstanceURL = strings.TrimSuffix(strings.TrimSpace(detail.InstanceURL), "/")
	detail.GraphQLEndPoint = detail.InstanceURL + "/api/graphql"
	detail.APIEndPoint = detail.InstanceURL + "/api"
	detail.ID = util.NewRandomUUID().String()
	detail.Type = gitutils.GitLab
	config, err := configManager.GetConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := config.AddService(&detail); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(listIntegrations(gitutils.GitLab))
}

func deleteGitLabIntegration(w http.ResponseWriter, r *http.Request) {
	var id struct {
		ID string
	}
	if err := json.NewDecoder(r.Body).Decode(&id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config, err := configManager.GetConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	delete(config.GitServices[gitutils.GitLab], id.ID)
	_ = configManager.SaveConfig(config)
	json.NewEncoder(w).Encode(listIntegrations(gitutils.GitLab))
}

func getGitLabIntegrations(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(listIntegrations(gitutils.GitLab))
}
