package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var (
	routes         = mux.NewRouter()
	apiVersion     = "0.0.0"
	pm             = projects.MakeSimpleProjectManager()
	allowedOrigins = []string{
		"localhost:17283",
		"http://localhost:4200",
		"localhost:4200",
	}
	corsOptions = []handlers.CORSOption{
		handlers.AllowedMethods([]string{"GET", "HEAD", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Accept", "Accept-Language", "Origin"}),
		handlers.AllowCredentials(),
	}

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			for _, origin := range allowedOrigins {
				if origin == r.Host {
					return true
				}
			}
			return strings.Split(r.Host, ":")[0] == "localhost" //allow localhost independent of port
		},
	}
)

func init() {
	addRoutes()
}

func addRoutes() {
	routes.HandleFunc("/api/findsecrets", findSecrets).Methods("POST")
	routes.HandleFunc("/api/secrets/scan", scanSecrets).Methods("GET")
	routes.HandleFunc("/api/version", version).Methods("GET")
	routes.HandleFunc("/api/secrets/defaultpolicy", defaultPolicy).Methods("GET")
	routes.HandleFunc("/api/projectsummaries", projectSummaries).Methods("GET")
	routes.HandleFunc("/api/projectsummary/{projectID}", getProjectSummary).Methods("GET")
	routes.HandleFunc("/api/project/{projectID}", getProject).Methods("GET")
	routes.HandleFunc("/api/project/issues", getIssues).Methods("POST")
	routes.HandleFunc("/api/project/issues/fix", fixIssue).Methods("POST")
	routes.HandleFunc("/api/createproject", createProject).Methods("POST")

}

func version(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(apiVersion)
}

func defaultPolicy(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(diagnostics.GenerateSampleExclusion())
}

func getProjectSummary(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	summary := pm.GetProjectSummary(projID)
	json.NewEncoder(w).Encode(summary)
}

func getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	project := pm.GetProject(projID)
	json.NewEncoder(w).Encode(project)
}

func projectSummaries(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(pm.ListProjectSummaries())
}

func getIssues(w http.ResponseWriter, r *http.Request) {
	var search projects.PaginatedIssueSearch
	if err := json.NewDecoder(r.Body).Decode(&search); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(pm.GetIssues(search))
}

func fixIssue(w http.ResponseWriter, r *http.Request) {
	var fix diagnostics.ExcludeRequirement
	if err := json.NewDecoder(r.Body).Decode(&fix); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(pm.RemediateIssue(fix))
}

func createProject(w http.ResponseWriter, r *http.Request) {
	var projDesc projects.ProjectDescriptionWire
	if err := json.NewDecoder(r.Body).Decode(&projDesc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	proj := pm.CreateProject(projDesc.ToProjectDescription())
	json.NewEncoder(w).Encode(pm.GetProjectSummary(proj.ID))
}

func findSecrets(w http.ResponseWriter, r *http.Request) {
	var data common.DataToScan
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if data.Base64 {
		b, err := base64.StdEncoding.DecodeString(data.Source)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data.Source = string(b)
	}

	path := "" //dummy path
	options := secrets.SecretSearchOptions{
		Exclusions: diagnostics.MakeEmptyExcludes(),
	}
	finder := secrets.GetFinderForFileType(data.SourceType, path, options)
	diagnostics := []*diagnostics.SecurityDiagnostic{}
	for diagnostic := range secrets.FindSecret(path, strings.NewReader(data.Source), finder, true) {
		diagnostics = append(diagnostics, diagnostic)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diagnostics)
}

func scanSecrets(w http.ResponseWriter, r *http.Request) {
	var options ProjectScanOptions

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading websocket connection %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = ws.ReadJSON(&options)
	if err != nil {
		log.Printf("Error deserialising scan options %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	runSecretScan(options, ws)

}

//ServeAPI serves the analysis service on the specified port
func ServeAPI(config Config) {
	hostPort := "localhost:%d"
	if config.Local {
		//localhost electron app
		corsOptions = append(corsOptions, handlers.AllowedOrigins(allowedOrigins))
	} else {
		hostPort = ":%d"
	}
	apiVersion = config.AppVersion
	log.Fatal(http.ListenAndServe(fmt.Sprintf(hostPort, config.ApiPort), handlers.CORS(corsOptions...)(routes)))
}
