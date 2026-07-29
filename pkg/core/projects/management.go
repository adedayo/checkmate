package projects

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"gopkg.in/yaml.v3"
)

var (
	defaultProjectFile        = "project.yaml"
	defaultWorkspacesFile     = "workspaces.json"
	defaultYAMLWorkspacesFile = "workspaces.yaml"
	projectSummaryFile        = "project-summary.yaml"
	defaultScanFile           = "scanConfig.yaml"
	defaultScanResultsFile    = "scanResults.json"
	defaultCodeDirPrefix      = "code"
	defaultScanSummaryFile    = "scan-summary.yaml"
	rxFix                     = map[string]string{
		`.`: `[.]`,
		`$`: `[$]`,
		`^`: `[^]`,
		`\`: `[\]`,
	}
)

type ProjectManager interface {
	GetWorkspaces() (*Workspace, error)
	SaveWorkspaces(*Workspace) error
	SaveProjectSummary(*ProjectSummary) error
	ListProjectSummaries() []*ProjectSummary
	GetProjectSummary(projectID string) (*ProjectSummary, error)
	GetProject(id string) (Project, error)
	DeleteProject(id string) error
	GetScanConfig(projectID, scanID string) (*ScanPolicy, error)
	GetScanResults(projectID, scanID string) ([]*diagnostics.SecurityDiagnostic, error)
	GetScanResultSummary(projectID, scanID string) (ScanSummary, error)
	// SummariseScanResults(projectID, scanID string, summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary) error
	RunScan(ctx context.Context, projectID string, scanPolicy ScanPolicy, scanner SecurityScanner,
		scanIDCallback func(string), repoStatusChecker RepositoryStatusChecker,
		progressMonitor func(diagnostics.Progress),
		summariser ScanSummariser, wsSummariser WorkspaceSummariser,
		consumers ...diagnostics.SecurityDiagnosticsConsumer)

	CreateProject(projectDescription ProjectDescription) (*Project, error)
	UpdateProject(projectID string, projectDescription ProjectDescription,
		wsSummariser WorkspaceSummariser) (*Project, error)
	GetIssues(paginated PaginatedIssueSearch) (*PagedResult, error)
	RemediateIssue(exclude diagnostics.ExcludeRequirement) diagnostics.PolicyUpdateResult
	GetCodeContext(cnt common.CodeContext) string
	GetProjectLocation(projID string) string
	GetGitConfigManager() (gitutils.GitConfigManager, error)
	//CheckMate base directory
	GetBaseDir() string
	//Base directory for code checkout
	GetCodeBaseDir() string
	//Release resources if necessary
	Close() error
}

type WorkspaceSummariser func(pm ProjectManager, workspacesToUpdate []string) (*Workspace, error)
type ScanSummariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary

func MakeSimpleProjectManager(checkMateBaseDir string) ProjectManager {

	pm := simpleProjectManager{
		baseDir:                checkMateBaseDir,
		projectsLocation:       path.Join(checkMateBaseDir, "projects"),
		codeBaseDir:            path.Join(checkMateBaseDir, defaultCodeDirPrefix),
		workspaceFileMutex:     &sync.RWMutex{},
		scanSummaryFileMutexes: make(map[string]*sync.RWMutex),
	}

	//attempt to create the project location if it doesn't exist
	_ = os.MkdirAll(pm.projectsLocation, 0755)
	//create workspace file if it doesn't exist
	if _, err := os.Stat(path.Join(pm.projectsLocation, defaultWorkspacesFile)); errors.Is(err, fs.ErrNotExist) {
		_ = pm.SaveWorkspaces(&Workspace{})
	}

	//create empty repo commits file if it doesn't exist
	// InitialiseCommitDB(pm)

	//migrate old yaml workspace format
	// MigrateYAMLWorkspace(&pm)
	return pm
}

// func InitialiseCommitDB(pm ProjectManager) {
// 	//create repo commits file if it doesn't exist
// 	commitsLoc := path.Join(pm.GetBaseDir(), "repo_commits")
// 	commitsPath := path.Join(commitsLoc, "RepositoryCommits.json")
// 	if _, err := os.Stat(commitsPath); os.IsNotExist(err) {

// 		if err := os.MkdirAll(commitsLoc, 0755); err != nil {
// 			log.Printf("Error: %v", err)
// 		}

// 		//important to truncate the file, as opening for read-write leads to errors in both yaml and json encoders
// 		comFile, err := os.Create(commitsPath)
// 		if err != nil {
// 			log.Printf("Error: %v", err)
// 		}
// 		defer comFile.Close()

// 		json.NewEncoder(comFile).Encode(&gitutils.RepositoryCommitCollection{
// 			Repositories: make(map[string]gitutils.AnnotatedCommits),
// 		})

// 	}
// }

// utility to migate YAML format workspace
func MigrateYAMLWorkspace(spm *simpleProjectManager) {
	spm.workspaceFileMutex.Lock()
	var ws Workspace
	workspacesFile := path.Join(spm.projectsLocation, defaultYAMLWorkspacesFile)
	data, err := os.ReadFile(workspacesFile)
	if err == nil {
		if e := yaml.Unmarshal(data, &ws); e != nil {
			log.Printf("GetWorkspaces YAML Unmarshal: %v", e)
			return
		}
		log.Printf("Migrating %v", ws)
		spm.workspaceFileMutex.Unlock()
		_ = spm.SaveWorkspaces(&ws)
	} else {
		log.Printf("GetWorkspaces YAML ReadFile: %v", err)
		spm.workspaceFileMutex.Unlock()
		return
	}
}

type simpleProjectManager struct {
	baseDir, projectsLocation, codeBaseDir string
	workspaceFileMutex                     *sync.RWMutex
	scanSummaryFileMutexes                 map[string]*sync.RWMutex //scanID -> file mutex
}

// DeleteProject implements ProjectManager
func (pm simpleProjectManager) DeleteProject(id string) error {
	proj, err := pm.GetProjectSummary(id)
	if err != nil {
		return err
	}

	//remove project from workspaces
	if ws, err := pm.GetWorkspaces(); err == nil {
		_ = ws.RemoveProjectSummary(proj, pm)
	}
	//delete project metadata
	_ = os.RemoveAll(pm.GetProjectLocation(id))
	//delete checked out code
	for _, r := range proj.Repositories {
		if r.IsGit() {
			_ = os.RemoveAll(r.GetCodeLocation(pm, id))
		}
	}
	return nil
}

// GetGitConfigManager implements ProjectManager
func (spm simpleProjectManager) GetGitConfigManager() (gitutils.GitConfigManager, error) {
	return gitutils.NewGitConfigManager(spm.GetBaseDir()), nil
}

func (spm simpleProjectManager) GetBaseDir() string {
	return spm.baseDir
}

func (spm simpleProjectManager) GetCodeBaseDir() string {
	return spm.codeBaseDir
}

func (spm simpleProjectManager) GetProjectLocation(projID string) string {
	return path.Join(spm.projectsLocation, projID)
}

// func (spm simpleProjectManager) GetScanLocation(projID, scanID string) string {
// 	return path.Join(spm.projectsLocation, projID, scanID)
// }

func (spm simpleProjectManager) Close() error {
	//Nothing to do
	return nil
}

func (spm simpleProjectManager) GetCodeContext(cnt common.CodeContext) string {
	return GetCodeContext(spm.baseDir, cnt)
}

func GetCodeContext(codeBaseDir string, cnt common.CodeContext) (out string) {
	if !strings.Contains(cnt.Location, ".git/") {
		//Filesystem location
		file, err := os.Open(cnt.Location)
		if err != nil {
			return
		}
		if x, err := io.ReadAll(file); err == nil {
			out = string(x)
			return out
		}
	} else {
		//likely a git checkout, try and open it if the codebase is still there
		z := strings.Split(cnt.Location, ".git/")
		if len(z) == 2 {
			clonePath := path.Base(z[0]) // we don't lowercase this anymore
			location := path.Join(codeBaseDir, cnt.ProjectID, clonePath, z[1])
			file, err := os.Open(location)
			if err != nil {
				return
			}
			if x, err := io.ReadAll(file); err == nil {
				out = string(x)
				return out
			}
		}

	}

	return
}

func UpdatePolicy(exclude diagnostics.ExcludeRequirement, pm ProjectManager) (result diagnostics.PolicyUpdateResult) {
	projectID := exclude.ProjectID
	issue := exclude.Issue
	project, err := pm.GetProject(projectID)
	if err != nil {
		result.Status = "fail - no such project"
		return
	}

	updatePolicy := func() {

		policy, err := yaml.Marshal(project.ScanPolicy.Policy)
		if err != nil {
			result.Status = fmt.Sprintf("fail = error marshalling new policy: %s", err.Error())
			return
		}

		_ = pm.UpdateProject(project.ID, ProjectDescription{
			Name:         project.Name,
			Workspace:    project.Workspace,
			Repositories: project.Repositories,
			ScanPolicy:   project.ScanPolicy,
		}, nil)
		result.Status = "success"
		result.NewPolicy = string(policy)
	}

	getFPString := func() (string, error) {
		return issue.GetValue(), nil
	}

	getCanonicalPath := func(path string) string {
		for _, base := range project.Repositories {
			if strings.HasPrefix(path, base.Location) {
				return strings.TrimPrefix(path, base.Location)
			}
		}
		return path
	}

	switch exclude.What {
	case "ignore_here":
		data, err := getFPString()
		if err != nil {
			result.Status = err.Error()
			return
		}
		data, err = encode(data)
		if err != nil {
			result.Status = err.Error()
			return
		}
		file := getCanonicalPath(*issue.Location)
		if project.ScanPolicy.Policy.PerFileExcludedStrings == nil {
			project.ScanPolicy.Policy.PerFileExcludedStrings = make(map[string][]string)
		}
		if x, present := project.ScanPolicy.Policy.PerFileExcludedStrings[file]; present {
			project.ScanPolicy.Policy.PerFileExcludedStrings[file] = appendUnique(x, data)
		} else {
			project.ScanPolicy.Policy.PerFileExcludedStrings[file] = []string{data}
		}
		updatePolicy()
	case "ignore_sha2_here":
		data := issue.SHA256
		if data == nil {
			result.Status = "Cannot exclude SHA256 when it is not computed in the first instance"
			return
		}
		file := getCanonicalPath(*issue.Location)
		if project.ScanPolicy.Policy.PerFileExcludedHashes == nil {
			project.ScanPolicy.Policy.PerFileExcludedHashes = make(map[string][]string)
		}

		if x, present := project.ScanPolicy.Policy.PerFileExcludedHashes[file]; present {
			project.ScanPolicy.Policy.PerFileExcludedHashes[file] = appendUnique(x, *data)
		} else {
			project.ScanPolicy.Policy.PerFileExcludedHashes[file] = []string{*data}
		}
		updatePolicy()
	case "ignore_everywhere":
		data, err := getFPString()
		if err != nil {
			result.Status = err.Error()
			return
		}
		data, err = encode(data)
		if err != nil {
			result.Status = err.Error()
			return
		}
		project.ScanPolicy.Policy.GloballyExcludedStrings = appendUnique(project.ScanPolicy.Policy.GloballyExcludedStrings, data)
		updatePolicy()
	case "ignore_sha2_everywhere":
		data := issue.SHA256
		if data == nil {
			result.Status = "Cannot exclude SHA256 when it is not computed in the first instance"
			return
		}
		project.ScanPolicy.Policy.GloballyExcludedHashes = appendUnique(project.ScanPolicy.Policy.GloballyExcludedHashes, *data)
		updatePolicy()
	case "ignore_file":
		if issue.Location == nil {
			result.Status = "fail - file to exclude not supplied"
			return
		}
		loc := fmt.Sprintf(".*%s", fixPathRegex(getCanonicalPath(*issue.Location)))
		project.ScanPolicy.Policy.PathExclusionRegExs = appendUnique(project.ScanPolicy.Policy.PathExclusionRegExs, loc)
		updatePolicy()
	default:
		result.Status = "fail"
	}
	return
}

func (spm simpleProjectManager) RemediateIssue(exclude diagnostics.ExcludeRequirement) (result diagnostics.PolicyUpdateResult) {
	return UpdatePolicy(exclude, spm)
}

func encode(data string) (out string, err error) {
	var dec string
	out = data
	mustEncode := false
	if err = yaml.Unmarshal([]byte(data), &dec); err == nil {
		if dec != data {
			mustEncode = true
		}
	} else {
		mustEncode = true
	}

	if mustEncode {
		b, e := yaml.Marshal(data)
		if e != nil {
			err = e
			return
		}
		out = string(b)
	}
	return
}

func fixPathRegex(rx string) string {
	for k, v := range rxFix {
		rx = strings.ReplaceAll(rx, k, v)
	}
	return rx
}

func appendUnique(xs []string, x string) []string {
	m := make(map[string]struct{})
	nothing := struct{}{}
	m[x] = nothing
	for _, y := range xs {
		m[y] = nothing
	}
	out := make([]string, 0, len(m))
	for z := range m {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

func (spm simpleProjectManager) GetWorkspaces() (*Workspace, error) {
	spm.workspaceFileMutex.Lock()
	defer spm.workspaceFileMutex.Unlock()

	var ws Workspace
	workspacesFile := path.Join(spm.projectsLocation, defaultWorkspacesFile)
	data, err := os.ReadFile(workspacesFile)
	if err == nil {
		if e := json.Unmarshal(data, &ws); e != nil {
			log.Printf("GetWorkspaces Unmarshal: %v", e)
			return &Workspace{}, e
		}
	} else {
		log.Printf("GetWorkspaces ReadFile: %v", err)
		return &Workspace{}, err
	}
	return &ws, nil
}

func (spm simpleProjectManager) SaveWorkspaces(ws *Workspace) error {

	spm.workspaceFileMutex.Lock()
	defer spm.workspaceFileMutex.Unlock()

	projectLoc := spm.projectsLocation
	if err := os.MkdirAll(projectLoc, 0755); err != nil {
		log.Printf("SaveWorkspaces: %v\n", err)
		return err
	}

	wsPath := path.Join(projectLoc, defaultWorkspacesFile)
	//important to truncate the file, as opening for read-write leads to errors in both yaml and json encoders
	wsFile, err := os.Create(wsPath)
	if err != nil {
		log.Printf("SaveWorkspaces: %v\n", err)
		return err
	}
	defer func() {
		_ = wsFile.Close()
	}()

	err = json.NewEncoder(wsFile).Encode(ws)
	if err != nil {
		log.Printf("SaveWorkspaces (encoding error): %v\n", err)
		return err
	}

	return nil
}

// GetIssues returns issues page-by-page according to specified page size. A page
// size of 0 returns all issues
func (spm simpleProjectManager) GetIssues(paginated PaginatedIssueSearch) (pr *PagedResult, err error) {

	results, err := spm.GetScanResults(paginated.ProjectID, paginated.ScanID)

	if err != nil {
		return
	}

	return PageIssues(paginated, results), nil
}

func PageIssues(paginated PaginatedIssueSearch, results []*diagnostics.SecurityDiagnostic) *PagedResult {

	if paginated.PageSize == 0 {
		return &PagedResult{
			Total:       len(results),
			Page:        0,
			Diagnostics: results,
		}
	}

	filterConfidence := false
	confidenceValues := map[string]bool{}
	if len(paginated.Filter.Confidence) > 0 {
		filterConfidence = true
		for _, c := range paginated.Filter.Confidence {
			c = strings.ToLower(c)
			if c == "med" {
				c = "medium" //medium is not abbreviated in the GoString value of confidence
			}
			confidenceValues[c] = true
		}
	}

	includeTest := false
	includeProd := false
	confidentialFilesOnly := false
	showUnique := false
	if len(paginated.Filter.Tags) > 0 {
		for _, tag := range paginated.Filter.Tags {
			if strings.ToLower(tag) == "test" {
				includeTest = true
			}
			if strings.ToLower(tag) == "prod" {
				includeProd = true
			}
			if strings.ToLower(tag) == "confidential" {
				confidentialFilesOnly = true
			}
			if strings.ToLower(tag) == "unique" {
				showUnique = true
			}
		}
	} else {
		includeTest = true
		includeProd = true
	}

	location := paginated.Page * paginated.PageSize
	length := len(results)
	issues := make([]*diagnostics.SecurityDiagnostic, 0)

	//Collect a sample of each unique secret
	if showUnique {
		sameSha := make(map[string][]*diagnostics.SecurityDiagnostic)

		for _, issue := range results {
			if issue.SHA256 != nil {
				sha := *issue.SHA256
				if shas, present := sameSha[sha]; present {
					sameSha[sha] = append(shas, issue)
				} else {
					sameSha[sha] = []*diagnostics.SecurityDiagnostic{issue}
				}
			}
		}

		out := []*diagnostics.SecurityDiagnostic{}
		for _, v := range sameSha {
			out = append(out, v[0]) //take only one sample
		}

		return &PagedResult{
			Total:       len(results),
			Page:        paginated.Page,
			Diagnostics: out,
		}

	}

	//we could have simply calculated the required range and taken the slice out of results
	//however in anticipation of filters e.g. only get "High" confidence results, the iteration
	//approach seems reasonable
	for {
		if length > location && len(issues) < paginated.PageSize {
			issue := results[location]
			isTest := issue.HasTag("test")
			if filterConfidence {
				conf := strings.ToLower(issue.Justification.Headline.Confidence.GoString())
				if _, present := confidenceValues[conf]; present {
					if (includeTest && isTest) || (includeProd && !isTest) {
						if !confidentialFilesOnly ||
							(confidentialFilesOnly && issue.HasTag("confidential")) {
							issues = append(issues, issue)
						}
					}
				}
			} else {
				if (includeTest && isTest) || (includeProd && !isTest) {
					if !confidentialFilesOnly ||
						(confidentialFilesOnly && issue.HasTag("confidential")) {
						issues = append(issues, issue)
					}
				}
			}
			location++
		} else {
			break
		}
	}

	return &PagedResult{
		Total:       len(results),
		Page:        paginated.Page,
		Diagnostics: issues,
	}

}

func (spm simpleProjectManager) CreateProject(projectDescription ProjectDescription) (project *Project, err error) {
	proj := ProjectFromDescription(projectDescription)

	return spm.saveProject(proj, projectStatus{created: true, creationTime: time.Now()})
}

func ProjectFromDescription(projectDescription ProjectDescription) Project {
	projectID := util.NewRandomUUID().String()
	policy := ScanPolicy{
		ID:     util.NewRandomUUID().String(),
		Policy: projectDescription.ScanPolicy.Policy,
	}

	proj := Project{
		ID:           projectID,
		Name:         projectDescription.Name,
		Workspace:    projectDescription.Workspace,
		Repositories: projectDescription.Repositories,
		ScanPolicy:   policy,
	}
	return proj
}

func (spm simpleProjectManager) GetProject(id string) (project Project, err error) {
	if dirs, err := os.ReadDir(spm.projectsLocation); err == nil {
		for _, dir := range dirs {
			if dir.IsDir() && dir.Name() == id {
				return spm.loadProject(dir.Name())
			}
		}
	}
	return
}

func (spm simpleProjectManager) GetScanResults(projID, scanID string) (results []*diagnostics.SecurityDiagnostic, err error) {
	scanResultsLocation := path.Join(spm.projectsLocation, projID, scanID, defaultScanResultsFile)
	file, err := os.Open(scanResultsLocation)
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	for {
		if e := decoder.Decode(&results); e == io.EOF {
			break
		} else if e != nil {
			err = e
			return
		}
	}
	return results, nil
}

// side effect of saving the scan summary in a file
func (spm simpleProjectManager) summariseScanResults(projectID, scanID string, summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary) (*ScanSummary, error) {
	spm.scanSummaryFileMutexes[scanID] = &sync.RWMutex{}
	spm.scanSummaryFileMutexes[scanID].Lock()
	defer func() {
		spm.scanSummaryFileMutexes[scanID].Unlock()
	}()

	results, err := spm.GetScanResults(projectID, scanID)
	if err != nil {
		return nil, err
	}
	out := summariser(projectID, scanID, results)
	scanSummaryFile, err := os.Create(path.Join(spm.projectsLocation, projectID, scanID, defaultScanSummaryFile))
	if err != nil {
		return out, err
	}
	defer func() {
		_ = scanSummaryFile.Close()
	}()
	return out, yaml.NewEncoder(scanSummaryFile).Encode(out)
}

func (spm simpleProjectManager) GetScanResultSummary(projectID, scanID string) (ScanSummary, error) {
	if lock, exists := spm.scanSummaryFileMutexes[scanID]; exists {
		lock.Lock()
		defer func() {
			lock.Unlock()
			delete(spm.scanSummaryFileMutexes, scanID)
		}()
	}

	var summary ScanSummary
	file, err := os.Open(path.Join(spm.projectsLocation, projectID, scanID, defaultScanSummaryFile))
	if err != nil {
		//sometimes the scan has not been run/completed. This is not unusual
		// log.Printf("Error loading scan summary: %s", err.Error())
		return summary, err
	}
	defer file.Close()

	yaml.NewDecoder(file).Decode(&summary)
	return summary, nil
}

func (spm simpleProjectManager) GetScanConfig(projID, scanID string) (config *ScanPolicy, err error) {
	data, err := os.ReadFile(path.Join(spm.projectsLocation, projID, scanID, defaultScanFile))
	if err == nil {
		if yaml.Unmarshal(data, &config) != nil {
			return &ScanPolicy{}, err
		}
	}
	return
}

func (spm simpleProjectManager) loadProject(projID string) (proj Project, err error) {
	data, err := os.ReadFile(path.Join(spm.projectsLocation, projID, defaultProjectFile))
	if err == nil {
		if err = yaml.Unmarshal(data, &proj); err != nil {
			log.Printf("%v", err)
			return Project{}, err
		}
	}
	return
}

func (spm simpleProjectManager) GetProjectSummary(projID string) (*ProjectSummary, error) {
	projPath := path.Join(spm.projectsLocation, projID)
	data, err := os.ReadFile(path.Join(projPath, projectSummaryFile))
	summary := &ProjectSummary{}
	if err != nil {
		return summary, err
	}

	if err = yaml.Unmarshal(data, &summary); err != nil {
		return summary, err
	}
	//if everything goes well. Load the retrieve the scan results series
	// summary.LastScore.SubMetrics = loadHistoricalScores(projID, spm)
	summary.LastScanSummary = spm.loadLastScanSummary(projID)
	return summary, nil
}

type data struct {
	timeStamp time.Time
	scanID    string
	score     float32
}

type dataSlice []data

func (t dataSlice) Len() int {
	return len(t)
}

func (t dataSlice) Less(i, j int) bool {
	return t[i].timeStamp.Before(t[j].timeStamp)
}

func (t dataSlice) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func LoadHistoricalScores(projID string, pm ProjectManager) map[string]float32 {
	out := make(map[string]float32)
	sortedData := make(dataSlice, 0)
	proj, err := pm.GetProject(projID)
	if err != nil {
		return out
	}
	scanIDs := proj.ScanIDs
	for _, scanID := range scanIDs {
		summary, err := pm.GetScanResultSummary(projID, scanID)
		if err == nil {
			sortedData = append(sortedData, data{
				timeStamp: summary.Score.TimeStamp,
				scanID:    scanID,
				score:     summary.Score.Metric,
			})
		}
	}

	sort.Sort(sortedData)

	for _, d := range sortedData {
		out[trendIndex(d.scanID, d.timeStamp)] = d.score
	}

	return out
}

func trendIndex(scanID string, timeStamp time.Time) string {
	return fmt.Sprintf("%s;%s", scanID, timeStamp.Format(time.RFC3339))
}

func (spm simpleProjectManager) loadLastScanSummary(projID string) (summary ScanSummary) {
	if project, err := spm.loadProject(projID); err == nil {

		if len(project.ScanIDs) > 0 {
			scanID := project.ScanIDs[len(project.ScanIDs)-1]
			if s, err := spm.GetScanResultSummary(projID, scanID); err == nil {
				summary = s
			}
			// else {
			//sometimes the scan has not been run/completed. This is not unusual
			// log.Printf("Error loading scan summary: %s", err.Error())
			// }
		}
	}
	return
}

type ProjectSummarySlice []*ProjectSummary

func (t ProjectSummarySlice) Len() int {
	return len(t)
}

func (t ProjectSummarySlice) Less(i, j int) bool {
	return t[i].LastScan.After(t[j].LastScan)
}

func (t ProjectSummarySlice) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func (spm simpleProjectManager) ListProjectSummaries() (summaries []*ProjectSummary) {

	wss, err := spm.GetWorkspaces()

	if err != nil {
		log.Printf("ListProjectSummaries: %v\n", err)
		return
	}
	for _, wd := range wss.Details {
		summaries = append(summaries, wd.ProjectSummaries...)
	}
	sorted := make(ProjectSummarySlice, 0)
	sorted = append(sorted, summaries...)
	sort.Sort(sorted)
	return sorted
}

func (spm simpleProjectManager) RunScan(ctx context.Context, projectID string,
	scanPolicy ScanPolicy,
	scanner SecurityScanner,
	scanIDCallback func(string),
	repoStatusChecker RepositoryStatusChecker,
	progressMonitor func(diagnostics.Progress),
	summariser ScanSummariser,
	wsSummariser WorkspaceSummariser,
	consumers ...diagnostics.SecurityDiagnosticsConsumer) {
	scanID := spm.createScan(projectID, scanPolicy)
	scanIDCallback(scanID)
	sdc := createDiagnosticConsumer(spm.projectsLocation, projectID, scanID)
	consumers = append(consumers, sdc)
	scannedCommits := RetrieveCommitsToBeScanned(projectID, scanID, spm, progressMonitor)
	scanStartTime := time.Now()
	//set "being-scanned" flag
	if summary, err := spm.GetProjectSummary(projectID); err == nil {
		summary.IsBeingScanned = true
		spm.SaveProjectSummary(summary)
	}
	progressMonitor(diagnostics.Progress{
		ProjectID:   projectID,
		ScanID:      scanID,
		Position:    0,
		Total:       1,
		CurrentFile: "starting scan ...",
	})
	scanner.Scan(ctx, projectID, scanID, spm, repoStatusChecker, progressMonitor, consumers...)
	scanEndTime := time.Now()
	sdc.close(scanStartTime, scanEndTime)
	if out, err := spm.summariseScanResults(projectID, scanID, summariser); err == nil {
		spm.updateScanHistory(projectID, scanID, out, scannedCommits)
		if project, e := spm.GetProject(projectID); e == nil {
			spm.saveProject(project, projectStatus{scanned: true, scanID: scanID, scanTime: out.Score.TimeStamp})
			if wsSummariser != nil {
				wss, err := wsSummariser(spm, []string{project.Workspace})
				if err == nil {
					go spm.SaveWorkspaces(wss)
				} else {
					log.Printf("UpdateProject: %v", err)
				}
			}
		}
	}
}

// retrieve the git commits (HEAD) of the repositories about to be scanned. repoLocation -> scannedCommit
func RetrieveCommitsToBeScanned(projectID, scanID string, pm ProjectManager, progressMonitor func(diagnostics.Progress)) map[string]ScannedCommit {
	out := make(map[string]ScannedCommit)
	if proj, err := pm.GetProject(projectID); err == nil {
		repoCount := int64(len(proj.Repositories))
		for i, repo := range proj.Repositories {
			if repo.LocationType == "git" {
				progressMonitor(diagnostics.Progress{
					ProjectID:   projectID,
					ScanID:      scanID,
					Position:    int64(i),
					Total:       repoCount,
					CurrentFile: fmt.Sprintf("analysing branches of repository %s", repo.Location),
				})
				if dir, err := filepath.Abs(path.Clean(path.Join(pm.GetCodeBaseDir(), projectID,
					strings.TrimSuffix(path.Base(repo.Location), ".git")))); err == nil {
					if gitRepo, err := git.PlainOpen(dir); err == nil {
						var head, headBranch string
						if h, err := gitRepo.Head(); err == nil {
							head = h.Hash().String()
							headBranch = h.Name().Short()
						} else {
							progressMonitor(diagnostics.Progress{
								ProjectID:   projectID,
								ScanID:      scanID,
								Position:    int64(i),
								Total:       repoCount,
								CurrentFile: fmt.Sprintf("analysing branches of repository %s. Head discovery error: %v", repo.Location, err),
							})
						}

						if cIter, err := gitRepo.Log(&git.LogOptions{Order: git.LogOrderCommitterTime}); err == nil {
							cIter.ForEach(func(c *object.Commit) error {
								hash := c.Hash.String()
								progressMonitor(diagnostics.Progress{
									ProjectID:   projectID,
									ScanID:      scanID,
									Position:    int64(i),
									Total:       repoCount,
									CurrentFile: fmt.Sprintf("analysing branches of repository %s. Hash %s", repo.Location, hash),
								})
								out[repo.Location] = ScannedCommit{
									Repository: repo.Location,
									Commit: gitutils.Commit{
										Hash:   hash,
										Branch: headBranch,
										IsHead: head == hash,
										Time:   c.Author.When,
										Author: gitutils.Author{
											Name:  c.Author.Name,
											Email: c.Author.Email,
										},
									},
								}
								return errors.New("") // just take the HEAD and don't proceed further
							})
						} else {
							progressMonitor(diagnostics.Progress{
								ProjectID:   projectID,
								ScanID:      scanID,
								Position:    int64(i),
								Total:       repoCount,
								CurrentFile: fmt.Sprintf("analysing branches of repository %s. Error %v", repo.Location, err),
							})
						}
					} else {
						progressMonitor(diagnostics.Progress{
							ProjectID:   projectID,
							ScanID:      scanID,
							Position:    int64(i),
							Total:       repoCount,
							CurrentFile: fmt.Sprintf("analysing branches of repository %s. Error %v", repo.Location, err),
						})
					}
				} else {
					progressMonitor(diagnostics.Progress{
						ProjectID:   projectID,
						ScanID:      scanID,
						Position:    int64(i),
						Total:       repoCount,
						CurrentFile: fmt.Sprintf("analysing branches of repository %s. Error %v", repo.Location, err),
					})
				}
			}
		}
	}

	progressMonitor(diagnostics.Progress{
		ProjectID:   projectID,
		ScanID:      scanID,
		Position:    1,
		Total:       1,
		CurrentFile: "finished analysing repositories",
	})

	return out
}

// once the scan completes, store the scan ID, the git commit hash (HEAD) of the scanned repositories as well as the scan completion time
func (spm simpleProjectManager) updateScanHistory(projectID, scanID string, scanSummary *ScanSummary, scannedCommits map[string]ScannedCommit) (*ProjectSummary, error) {
	pSum, err := spm.GetProjectSummary(projectID)
	if err != nil {
		return pSum, err
	}
	UpdateScanHistoryAtEndOfScan(pSum, scannedCommits, scanID, scanSummary, spm)
	return pSum, spm.SaveProjectSummary(pSum)
}

func UpdateScanHistoryAtEndOfScan(pSum *ProjectSummary, scannedCommits map[string]ScannedCommit, scanID string, scanSummary *ScanSummary, pm ProjectManager) {

	//clear "being-scanned" flag
	pSum.IsBeingScanned = false

	//add scan result
	pSum.LastScanID = scanID
	score := scanSummary.Score
	pSum.LastScan = score.TimeStamp
	// pSum.LastScore.SubMetrics = loadHistoricalScores(pSum.ID, pm)

	// scanSummary, err := pm.GetScanResultSummary(pSum.ID, scanID)
	// if err == nil {
	// if scanSummary.Score.TimeStamp.Equal(scanTime) { //use this to gate errors in (de)serialisation

	pSum.LastScore = score
	pSum.LastScanSummary = *scanSummary
	if pSum.ScoreTrend == nil {
		pSum.ScoreTrend = map[string]float32{trendIndex(scanID, score.TimeStamp): score.Metric}
	} else {
		pSum.ScoreTrend[trendIndex(scanID, score.TimeStamp)] = score.Metric
	}

	// }
	// else {
	// 	log.Printf("unable to load last score, %s, %s\n", scanSummary.Score.TimeStamp, scanTime)
	// }
	// }

	for _, r := range pSum.Repositories {
		if c, exists := scannedCommits[r.Location]; exists {
			scanHistory := ScanHistory{
				ScanID: scanID,
				Commit: c.Commit,
				Time:   score.TimeStamp,
			}
			branch := c.Commit.Branch
			if pSum.ScanAndCommitHistories == nil {
				pSum.ScanAndCommitHistories = make(map[string]map[string]RepositoryHistory)
			}
			if m, exists := pSum.ScanAndCommitHistories[r.Location]; exists {
				if history, exists := m[branch]; exists {
					history.ScanHistories = append(history.ScanHistories, scanHistory)
					m[branch] = history
				} else {
					m[branch] = RepositoryHistory{
						Repository:      r,
						ScanHistories:   []ScanHistory{scanHistory},
						CommitHistories: []gitutils.Commit{},
					}
				}
				pSum.ScanAndCommitHistories[r.Location] = m
			} else {
				pSum.ScanAndCommitHistories[r.Location] = map[string]RepositoryHistory{
					branch: {
						Repository:      r,
						ScanHistories:   []ScanHistory{scanHistory},
						CommitHistories: []gitutils.Commit{},
					},
				}
			}
		}
	}
}

func (spm simpleProjectManager) UpdateProject(projectID string, projectDescription ProjectDescription,
	wsSummariser WorkspaceSummariser) (project *Project, err error) {
	proj, err := spm.GetProject(projectID)
	if err != nil {
		return
	}
	if proj.ID == projectID {
		//found project, update
		proj.Name = projectDescription.Name
		wspaces := []string{proj.Workspace}
		wsChange := false
		if proj.Workspace != projectDescription.Workspace {
			//project workspace changing
			wsChange = true
			wspaces = append(wspaces, projectDescription.Workspace)
			proj.Workspace = projectDescription.Workspace
		}
		proj.Repositories = projectDescription.Repositories
		policy := ScanPolicy{
			ID:           util.NewRandomUUID().String(),
			Policy:       projectDescription.ScanPolicy.Policy,
			Config:       projectDescription.ScanPolicy.Config,
			PolicyString: projectDescription.ScanPolicy.PolicyString,
		}
		proj.ScanPolicy = policy
		if wsChange && wsSummariser != nil {
			wss, err := wsSummariser(spm, wspaces)
			if err == nil {
				go spm.SaveWorkspaces(wss)
			} else {
				log.Printf("UpdateProject: %v", err)
			}
		}
		return spm.saveProject(proj, projectStatus{modified: true, modifiedTime: time.Now()})
	}
	//project not found, create one with a new ID
	return spm.CreateProject(projectDescription)

}

func (spm simpleProjectManager) SaveProjectSummary(summary *ProjectSummary) error {
	projectLoc := path.Join(spm.projectsLocation, summary.ID)
	projSummaryFile, err := os.Create(path.Join(projectLoc, projectSummaryFile))
	if err != nil {
		log.Printf("saveProjectSummary1: %v", err)
		return err
	}
	defer projSummaryFile.Close()

	summaryData, err := yaml.Marshal(summary)
	if err != nil {
		log.Printf("saveProjectSummary2: %v", err)
		return err
	}
	if _, err = projSummaryFile.Write(summaryData); err != nil {
		log.Printf("saveProjectSummary3: %v", err)
		return err
	}

	//also update Workspaces with the new project summary
	wss, err := spm.GetWorkspaces()
	if err != nil {
		log.Printf("saveProjectSummary0: %v", err)
		return err
	}
	if wss == nil {
		wss = &Workspace{}
	}
	wss.SetProjectSummary(summary, spm)

	return nil
}

func (spm simpleProjectManager) saveProject(project Project, status projectStatus) (pp *Project, err error) {

	projectLoc := path.Join(spm.projectsLocation, project.ID)
	if e := os.MkdirAll(projectLoc, 0755); e != nil {
		return pp, e
	}

	data, err := yaml.Marshal(project)
	if err != nil {
		return
	}

	projFile, err := os.Create(path.Join(projectLoc, defaultProjectFile))
	if err != nil {
		return
	}

	defer projFile.Close()
	if _, err = projFile.Write(data); err != nil {
		return
	}

	//depending on project status, also update the project summary file
	if status.created {
		summary := &ProjectSummary{
			ID:                     project.ID,
			Name:                   project.Name,
			Workspace:              project.Workspace,
			CreationDate:           status.creationTime,
			Repositories:           project.Repositories,
			ScanAndCommitHistories: make(map[string]map[string]RepositoryHistory),
		}

		spm.SaveProjectSummary(summary)
	}

	//update project summary on a new scan or modification
	if status.scanned || status.modified || status.newScan {
		summary, err := spm.GetProjectSummary(project.ID)
		if err != nil {
			return &project, err
		}
		if summary.ID == project.ID {

			if status.scanned {
				summary.LastScanID = status.scanID
				summary.LastScan = status.scanTime
				//clear "being-scanned" flag
				summary.IsBeingScanned = false
				scanSummary, err := spm.GetScanResultSummary(project.ID, status.scanID)
				if err == nil {
					if scanSummary.Score.TimeStamp.Equal(status.scanTime) { //use this to gate errors in (de)serialisation
						summary.LastScore = scanSummary.Score
					} else {
						log.Printf("unable to load last score, %s, %s\n", scanSummary.Score.TimeStamp, status.scanTime)
					}
				}
			}

			if status.modified {
				summary.LastModification = status.modifiedTime
				summary.Repositories = project.Repositories
				summary.Workspace = project.Workspace
			}

			if status.newScan {
				summary.LastScanID = status.scanID
				summary.LastModification = status.modifiedTime
			}
			spm.SaveProjectSummary(summary)
		}
	}

	return &project, nil
}

func (spm simpleProjectManager) createScan(projectID string, scanPolicy ScanPolicy) (scanID string) {

	proj, err := spm.GetProject(projectID)
	if err != nil {
		//project does not exist
		return
	}

	scanID = util.NewRandomUUID().String()
	proj.ScanIDs = append(proj.ScanIDs, scanID)
	spm.saveProject(proj, projectStatus{newScan: true, scanID: scanID, modifiedTime: time.Now()})

	policy := ScanPolicy{
		ID:     scanID,
		Policy: scanPolicy.Policy,
	}

	if err := spm.saveScan(projectID, scanID, policy); err != nil {
		return ""
	}

	return
}

func (spm simpleProjectManager) saveScan(projID, scanID string, policy ScanPolicy) error {

	scanLoc := path.Join(spm.projectsLocation, projID, scanID)
	if err := os.MkdirAll(scanLoc, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(policy)
	if err != nil {
		return err
	}

	scanConfigFile, err := os.Create(path.Join(scanLoc, defaultScanFile))
	if err != nil {
		return err
	}
	defer scanConfigFile.Close()

	if _, err = scanConfigFile.Write(data); err != nil {
		return err
	}

	return nil
}

type simpleDiagnosticConsumer struct {
	scanLocation string
	diagnostics  []*diagnostics.SecurityDiagnostic
}

func (sdc *simpleDiagnosticConsumer) ReceiveDiagnostic(diag *diagnostics.SecurityDiagnostic) {
	sdc.diagnostics = append(sdc.diagnostics, diag)
}

func (sdc *simpleDiagnosticConsumer) close(start, end time.Time) error {
	//write the collected diagnostics to file
	filePath := path.Join(sdc.scanLocation, defaultScanResultsFile)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(sdc.diagnostics); err != nil {
		return err
	}
	return nil
}

func createDiagnosticConsumer(projectLocation, projectID, scanID string) *simpleDiagnosticConsumer {
	sdc := simpleDiagnosticConsumer{
		scanLocation: path.Join(projectLocation, projectID, scanID),
		diagnostics:  []*diagnostics.SecurityDiagnostic{},
	}

	return &sdc
}

type projectStatus struct {
	created, scanned, modified bool
	newScan/**create scan without actually running it*/ bool
	creationTime, scanTime, modifiedTime time.Time
	scanID                               string
}
