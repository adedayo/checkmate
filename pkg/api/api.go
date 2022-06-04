package api

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v3"

	// intel "github.com/adedayo/code-intel-service/pkg/api"
	git "github.com/adedayo/git-service-driver/pkg/api"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	gitutils "github.com/adedayo/checkmate-core/pkg/git"
	"github.com/adedayo/checkmate-core/pkg/plugins"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
	csvreport "github.com/adedayo/checkmate/pkg/reports/csv"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var (
	routes     = mux.NewRouter()
	apiVersion = "0.0.0"
	caps       capabilities
	//used to validate UUID strings used for various (project,scan) IDs
	idRegX = regexp.MustCompile(`[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}`) //see util.UUID.String()

	pm             projects.ProjectManager
	allowedOrigins = []string{
		"localhost",
		"checkmate-app",
		"checkmate-api",
	}
	corsOptions = []handlers.CORSOption{
		handlers.AllowedMethods([]string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Accept", "Accept-Language", "Origin"}),
		handlers.AllowCredentials(),
		handlers.AllowedOriginValidator(allowedOriginValidator),
	}

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return allowedOriginValidator(r.Host)
		},
	}

	// handshakeConfig = plugin.HandshakeConfig{
	// 	ProtocolVersion:  1,
	// 	MagicCookieKey:   "CHECKMATE_PLUGIN",
	// 	MagicCookieValue: "transform",
	// }

	// pluginMap = map[string]plugin.Plugin{
	// 	"transformer": &plugins.TransformerPlugin{},
	// }
)

func init() {
	addRoutes()
	addAdditionalCORSOrigin()
}

type corsConfig struct {
	CORSAllowlist []string `yaml:"cors_hostname_allowlist"`
}

func addAdditionalCORSOrigin() {
	cors_config := "cors_config.yaml"
	if _, err := os.Stat(cors_config); err == nil {
		if file, err := os.Open(cors_config); err == nil {
			var cors corsConfig
			if err = yaml.NewDecoder(file).Decode(&cors); err == nil {
				allowedOrigins = append(sanitizeCORS(cors.CORSAllowlist), allowedOrigins...)
			} else {
				log.Printf("Error decoding cors-config.yaml %v", err)
			}
		} else {
			log.Printf("Error loading cors-config.yaml %v", err)
		}
	}
}

func sanitizeCORS(cors []string) (out []string) {
	for _, c := range cors {
		host := strings.Split(
			strings.TrimPrefix(strings.TrimPrefix(c, "http://"), "https://"), ":")[0]
		out = append(out, host)
	}
	return
}

func allowedOriginValidator(origin string) bool {
	originHost := strings.Split(strings.TrimPrefix(origin, "http://"), ":")[0]
	for _, allowed := range allowedOrigins {
		if allowed == originHost {
			return true
		}
	}

	host := strings.Split(strings.TrimPrefix(origin, "http://"), ":")[0]
	passCORS := host == "checkmate-app" || host == "localhost" //allow docker's checkmate-app or localhost independent of port
	if !passCORS {
		fmt.Printf("Host %s fails CORS.", origin)
	}
	return passCORS
}

type capabilities struct {
	GitServiceEnabled, GitLabEnabled, GitHubEnabled bool
}

func addRoutes() {
	routes.HandleFunc("/api/secrets/scan", scanSecrets).Methods("GET")
	routes.HandleFunc("/api/monitor/projectscan", monitorProjectScan).Methods("GET")
	routes.HandleFunc("/api/workspaces", getWorkspaces).Methods("GET")
	routes.HandleFunc("/api/version", version).Methods("GET")
	routes.HandleFunc("/api/git/capabilities", getCapabilities).Methods("GET")
	routes.HandleFunc("/api/secrets/defaultpolicy", defaultPolicy).Methods("GET")
	routes.HandleFunc("/api/projectsummaries", projectSummaries).Methods("GET")
	routes.HandleFunc("/api/projectsummariesreport/{workspace}", getWorkspaceReportPath).Methods("GET")
	routes.HandleFunc("/api/downloadworkspacereport/{workspace}", downloadWorkspaceReport).Methods("GET")
	routes.HandleFunc("/api/projectsummary/{projectID}", getProjectSummary).Methods("GET")
	routes.HandleFunc("/api/scansummary/{projectID}/{scanID}", getScanSummary).Methods("GET")
	routes.HandleFunc("/api/scanreport/{projectID}/{scanID}", getPDFScanReportPath).Methods("GET")
	routes.HandleFunc("/api/csvscanreport/{projectID}/{scanID}", getCSVScanReport).Methods("GET")
	routes.HandleFunc("/api/downloadscanreport/{projectID}/{scanID}", downloadPDFReport).Methods("GET")
	routes.HandleFunc("/api/downloadcsvscanreport/{projectID}/{scanID}", downloadCSVReport).Methods("GET")
	routes.HandleFunc("/api/project/{projectID}", getProject).Methods("GET")
	routes.HandleFunc("/api/deleteproject", deleteProject).Methods("POST")
	routes.HandleFunc("/api/project/issues", getIssues).Methods("POST")
	routes.HandleFunc("/api/project/issues/fix", fixIssue).Methods("POST")
	routes.HandleFunc("/api/project/issues/codecontext", getCodeContext).Methods("POST")
	routes.HandleFunc("/api/createproject", createProject).Methods("POST")
	routes.HandleFunc("/api/updateproject/{projectID}", updateProject).Methods("POST")
	routes.HandleFunc("/api/findsecrets", findSecrets).Methods("POST")

}

func getWorkspaces(w http.ResponseWriter, r *http.Request) {
	wss, err := pm.GetWorkspaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(wss)
}

func version(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(apiVersion)
}

func getCapabilities(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(caps)
}
func defaultPolicy(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(diagnostics.GenerateSampleExclusion())
}

func getProjectSummary(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	summary, err := pm.GetProjectSummary(projID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func getCSVScanReport(w http.ResponseWriter, r *http.Request) {
	scanReport, err := createCSVReport(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(scanReport)
}

func getPDFScanReportPath(w http.ResponseWriter, r *http.Request) {
	scanReport, err := createPDFReport(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(scanReport)
}

func downloadReport(w http.ResponseWriter, r *http.Request, path string) {
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	attachment := fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(file.Name()))
	w.Header().Set("Content-Disposition", attachment)
	cType := mime.TypeByExtension(filepath.Ext(file.Name()))
	if cType == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", cType)
	}
	if stat, err := file.Stat(); err == nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	}
	io.Copy(w, file)
}

func createCSVReport(w http.ResponseWriter, r *http.Request) (scanReport string, err error) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	scanID := vars["scanID"]

	if !(validateID(projID) && validateID(scanID)) {
		err = errors.New("Invalid Project or Scan ID")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reports_dir := path.Join(pm.GetBaseDir(), "reports", projID)
	// create the reports directory if it doesn't exist
	os.MkdirAll(reports_dir, 0755)
	scanReport = path.Join(reports_dir, fmt.Sprintf("%s.csv", scanID))

	//check if report already exists and send, otherwise generate and store
	_, err = os.Stat(scanReport)

	if !errors.Is(err, fs.ErrNotExist) {
		//report already exists
		// json.NewEncoder(w).Encode(scanReport)
		return scanReport, nil
	}

	results, err := pm.GetScanResults(projID, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = csvreport.Generate(scanReport, results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func downloadCSVReport(w http.ResponseWriter, r *http.Request) {
	scanReport, err := createCSVReport(w, r)
	if err != nil {
		return
	}
	downloadReport(w, r, scanReport)
}

func downloadPDFReport(w http.ResponseWriter, r *http.Request) {
	scanReport, err := createPDFReport(w, r)
	if err != nil {
		return
	}
	downloadReport(w, r, scanReport)
}

func createPDFReport(w http.ResponseWriter, r *http.Request) (scanReport string, err error) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	scanID := vars["scanID"]
	if !(validateID(projID) && validateID(scanID)) {
		err = errors.New("Invalid Project or Scan ID")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reports_dir := path.Join(pm.GetBaseDir(), "reports", projID)
	// create the project reports directory if it doesn't exist
	os.MkdirAll(reports_dir, 0755)
	scanReport = path.Join(reports_dir, fmt.Sprintf("%s.pdf", scanID))

	//check if report already exists and send, otherwise generate and store
	_, err = os.Stat(scanReport)

	if !errors.Is(err, fs.ErrNotExist) {
		//report already exists
		// json.NewEncoder(w).Encode(scanReport)
		return scanReport, nil
	}

	summary, err := pm.GetScanResultSummary(projID, scanID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// info, ok := summary.AdditionalInfo.(map[string]interface{})
	// if !ok {
	// 	http.Error(w, "Unable to generate report", http.StatusBadRequest)
	// 	return
	// }

	if summary.AdditionalInfo == nil {
		http.Error(w, "Unable to generate report", http.StatusBadRequest)
		return
	}

	info := summary.AdditionalInfo

	// showSource, ok := info["showSource"].(bool)
	// if !ok {
	// 	showSource = false
	// }
	// fileCount, ok := info["fileCount"].(int)
	// if !ok {
	// 	fileCount = 0
	// }

	results, err := pm.GetScanResults(projID, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fileName, err := asciidoc.GenerateReport(reports_dir, info.ShowSource, info.FileCount, results...)
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

	return
}

//ensure that the ID rougly looks like a UUID
func validateID(id string) bool {
	return idRegX.MatchString(id)
}

func getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projID := vars["projectID"]
	project, err := pm.GetProject(projID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(project)
}

func projectSummaries(w http.ResponseWriter, r *http.Request) {
	summaries := pm.ListProjectSummaries()
	err := json.NewEncoder(w).Encode(summaries)
	if err != nil {
		log.Printf("%s\n", err.Error())
	}
}

func generateWorkspaceReport(w http.ResponseWriter, r *http.Request) (reportLocation string, err error) {
	vars := mux.Vars(r)
	workspace := vars["workspace"]
	filtered := true
	if workspace == "__cm_all" { //sent from web app to print project summaries for all workspaces
		filtered = false
	}

	reports_dir := path.Join(pm.GetBaseDir(), "reports", "workspace")
	// create the reports directory if it doesn't exist
	os.MkdirAll(reports_dir, 0755)
	reportLocation = path.Join(reports_dir, "ProjectSummaries.csv")
	file, err := os.Create(reportLocation)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer file.Close()
	writer := csv.NewWriter(file)

	projectSummaries := pm.ListProjectSummaries()

	//write summaries for each project in workspace
	writer.Write((&projects.ProjectSummary{}).CSVHeaders())
	for _, summary := range projectSummaries {
		if !filtered || (filtered && workspace == summary.Workspace) {
			writer.Write(summary.CSVValues())
		}
	}

	writer.Write([]string{}) //NL :-)
	writer.Write([]string{"Project Details"})

	writer.Flush()
	err = writer.Error()

	transformers := loadReportPlugins()
	log.Printf("Found %d report plugins", len(transformers))
	//write each project's detailed results
	for _, pSum := range projectSummaries {
		// initialiser := plugins.PluginInitialiser{
		// 	ProjectManager: pm,
		// 	ProjectID:      pSum.ID,
		// }
		// for _, dt := range transformers {
		// 	dt.Plugin.Init(&initialiser)
		// 	defer dt.Kill()
		// }
		if !filtered || (filtered && workspace == pSum.Workspace) {
			projectID := pSum.ID
			scanID := pSum.LastScanID
			writer.Write([]string{}) //NL :-)
			writer.Write([]string{fmt.Sprintf("Project: %s", pSum.Name)})
			writer.Flush()
			e := writer.Error()
			if e != nil {
				multierror.Append(err, e)
				continue
			}
			results, e := pm.GetScanResults(projectID, scanID)
			if e != nil {
				multierror.Append(err, e)
				continue
			}
			config := &plugins.Config{
				ProjectID:   projectID,
				CodeBaseDir: pm.GetCodeBaseDir(),
			}
			for _, dt := range transformers {
				results = dt.Plugin.Transform(config, results...)
			}
			e = csvreport.WriteSecurityDiagnosticCSVReport(file, results)
			if e != nil {
				multierror.Append(err, e)
				continue
			}
		}
	}

	return

}

func loadReportPlugins() (out []closableTransformer) {
	cwd := ""
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	pluginsDir := path.Join(cwd, "plugins")
	log.Printf("Searching for report plugins at %s", pluginsDir)
	// logger := hclog.New(&hclog.LoggerOptions{
	// 	Name:   "checkmate_plugin",
	// 	Output: os.Stdout,
	// 	Level:  hclog.Debug,
	// })
	_ = filepath.WalkDir(pluginsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if match, err := filepath.Match("*_plugin", d.Name()); err == nil && match {
			log.Printf("Found a plugin file: %s", path)

			// client := plugin.NewClient(&plugin.ClientConfig{
			// 	HandshakeConfig: handshakeConfig,
			// 	Plugins:         pluginMap,
			// 	Cmd:             exec.Command(path),
			// 	Logger:          logger,
			// })

			// rpcClient, err := client.Client()
			// if err != nil {
			// 	logger.Debug("%v", err)
			// 	client.Kill()
			// 	return nil
			// }

			// raw, err := rpcClient.Dispense("transformer")
			// if err != nil {
			// 	logger.Debug("%v", err)
			// 	client.Kill()
			// 	return nil
			// }

			// plug := raw.(plugins.DiagnosticTransformer)

			plug, err := plugins.NewDiagnosticTransformerPlugin(path)

			if err != nil {
				log.Printf("Error instantiating plugin: %v", err)
				return nil
			}
			out = append(out, closableTransformer{
				// client: client,
				Plugin: plug,
			})
			// plug, err := plugin.Open(path)
			// if err != nil {
			// 	log.Printf("Plugin error 1: %v", err)
			// 	return nil
			// } else {
			// 	symbol, err := plug.Lookup("ReportPlugin")
			// 	if err != nil {
			// 		log.Printf("Plugin error 2: %v", err)
			// 		return nil
			// 	}
			// 	transformer, ok := symbol.(plugins.DiagnosticTransformer)
			// 	if ok {
			// 		out = append(out, transformer)
			// 	} else {
			// 		log.Printf("%s does not conform to the plugins.DiagnosticTransformer interface", path)
			// 	}
			// }
		}
		return nil
	})

	return
}

type closableTransformer struct {
	// client *plugin.Client
	Plugin plugins.DiagnosticTransformer
}

// func (ct closableTransformer) Kill() {
// 	ct.client.Kill()
// }

func downloadWorkspaceReport(w http.ResponseWriter, r *http.Request) {
	reportLocation, err := generateWorkspaceReport(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	downloadReport(w, r, reportLocation)
}

func getWorkspaceReportPath(w http.ResponseWriter, r *http.Request) {
	reportLocation, err := generateWorkspaceReport(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(reportLocation)

}
func deleteProject(w http.ResponseWriter, r *http.Request) {
	var id struct {
		ProjectID string
	}
	if err := json.NewDecoder(r.Body).Decode(&id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := pm.DeleteProject(id.ProjectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(id.ProjectID)
}

func getIssues(w http.ResponseWriter, r *http.Request) {
	var search projects.PaginatedIssueSearch
	if err := json.NewDecoder(r.Body).Decode(&search); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	issues, err := pm.GetIssues(search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(issues)
}

func fixIssue(w http.ResponseWriter, r *http.Request) {
	var fix diagnostics.ExcludeRequirement
	if err := json.NewDecoder(r.Body).Decode(&fix); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(pm.RemediateIssue(fix))
}

func getCodeContext(w http.ResponseWriter, r *http.Request) {
	var cnt common.CodeContext
	if err := json.NewDecoder(r.Body).Decode(&cnt); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(pm.GetCodeContext(cnt))
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
	proj, err := pm.CreateProject(desc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	summary, err := pm.GetProjectSummary(proj.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(summary)
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
	proj, err := pm.UpdateProject(projID, desc, projects.SimpleWorkspaceSummariser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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

	runSecretScan(r.Context(), options, ws)

}

func monitorProjectScan(w http.ResponseWriter, r *http.Request) {
	var options MonitorOptions

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// log.Printf("Error upgrading websocket connection %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = ws.ReadJSON(&options)
	if err != nil {
		// log.Printf("Error deserialising scan options %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addLongLivedSocket(r.Context(), options, ws)

}

//ServeAPI serves the analysis service on the specified port
func ServeAPI(config Config) {
	hostPort := "localhost:%d"
	if !config.Local {
		// not localhost electron app
		hostPort = ":%d"
	}
	corsOptions = append(corsOptions, handlers.AllowedOrigins(allowedOrigins))
	apiVersion = config.AppVersion

	pm = config.ProjectManager
	if config.ServeGitService {
		caps.GitServiceEnabled = true
		gitConfManager, err := pm.GetGitConfigManager()
		if err != nil {
			log.Printf("No Git config manager %v", err)
		}
		if err == nil {
			if conf, err := gitConfManager.GetConfig(); err == nil {
				caps.GitHubEnabled = conf.IsServiceConfigured(gitutils.GitHub)
				caps.GitLabEnabled = conf.IsServiceConfigured(gitutils.GitLab)

				//add git service driver APIs
				for _, rs := range git.GetRoutes(pm) {
					routes.HandleFunc(rs.Path, rs.Handler).Methods(rs.Methods...)
				}
			} else {
				log.Printf("No Git config %v", err)
			}

		}

		//add code intel services APIs
		// for _, rs := range intel.GetRoutes() {
		// 	routes.HandleFunc(rs.Path, rs.Handler).Methods(rs.Methods...)
		// }
	}
	log.Fatal(http.ListenAndServe(fmt.Sprintf(hostPort, config.ApiPort), handlers.CORS(corsOptions...)(routes)))
}
