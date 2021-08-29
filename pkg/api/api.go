package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
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
	routes.HandleFunc("/api/workspaces", getWorkspaces).Methods("GET")
	routes.HandleFunc("/api/workspacenames", getWorkspaceNames).Methods("GET")
	routes.HandleFunc("/api/version", version).Methods("GET")
	routes.HandleFunc("/api/secrets/defaultpolicy", defaultPolicy).Methods("GET")
	routes.HandleFunc("/api/projectsummaries", projectSummaries).Methods("GET")
	routes.HandleFunc("/api/projectsummary/{projectID}", getProjectSummary).Methods("GET")
	routes.HandleFunc("/api/scansummary/{projectID}/{scanID}", getScanSummary).Methods("GET")
	routes.HandleFunc("/api/scanreport/{projectID}/{scanID}", getScanReport).Methods("GET")
	routes.HandleFunc("/api/project/{projectID}", getProject).Methods("GET")
	routes.HandleFunc("/api/project/issues", getIssues).Methods("POST")
	routes.HandleFunc("/api/project/issues/fix", fixIssue).Methods("POST")
	routes.HandleFunc("/api/createproject", createProject).Methods("POST")
	routes.HandleFunc("/api/updateproject/{projectID}", updateProject).Methods("POST")
}

func getWorkspaces(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(pm.GetWorkspaces())
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

func getScanSummary(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	scanID := vars["scanID"]
	summary, err := pm.GetScanResultSummary(projID, scanID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(summary)
}

func getScanReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	scanID := vars["scanID"]

	loc := pm.GetScanLocation(projID, scanID)
	scanReport := path.Join(loc, fmt.Sprintf("%s.pdf", scanID))

	//check if report already exists and send, otherwise generate and store
	_, err := os.Stat(scanReport)

	if !os.IsNotExist(err) {
		//report already exists
		json.NewEncoder(w).Encode(scanReport)
		return
	}

	summary, err := pm.GetScanResultSummary(projID, scanID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	info, ok := summary.AdditionalInfo.(map[string]interface{})
	if !ok {
		http.Error(w, "Unable to generate report", http.StatusBadRequest)
		return
	}

	showSource, ok := info["showSource"].(bool)
	if !ok {
		showSource = false
	}
	fileCount, ok := info["fileCount"].(int)
	if !ok {
		fileCount = 0
	}

	fileName, err := asciidoc.GenerateReport(showSource, fileCount, pm.GetScanResults(projID, scanID)...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//move report into the scan directory
	err = os.Rename(fileName, scanReport)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(scanReport)
}

func getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	project := pm.GetProject(projID)
	json.NewEncoder(w).Encode(project)
}

func projectSummaries(w http.ResponseWriter, r *http.Request) {
	summaries := pm.ListProjectSummaries()
	// log.Printf("Summaries: %#v\n", summaries)
	// for _, sum := range summaries {
	// 	err := json.NewEncoder(w).Encode(sum)

	// 	if err != nil {
	// 		fmt.Printf("%s:\n%#v\n", err.Error(), sum)
	// 	}
	// }
	err := json.NewEncoder(w).Encode(summaries)
	if err != nil {
		log.Printf("%s\n", err.Error())
	}
}

func getWorkspaceNames(w http.ResponseWriter, r *http.Request) {
	out := []string{}
	m := make(map[string]bool)
	for _, p := range pm.ListProjectSummaries() {
		m[p.Workspace] = true
	}
	for k := range m {
		out = append(out, k)
	}
	json.NewEncoder(w).Encode(out)
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
	desc, err := projDesc.ToProjectDescription()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	proj := pm.CreateProject(desc)
	json.NewEncoder(w).Encode(pm.GetProjectSummary(proj.ID))
}

func updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]

	var projDesc projects.ProjectDescriptionWire
	if err := json.NewDecoder(r.Body).Decode(&projDesc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	desc, err := projDesc.ToProjectDescription()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	proj := pm.UpdateProject(projID, desc, workspaceSummariser)
	json.NewEncoder(w).Encode(proj)
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
