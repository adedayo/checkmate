package projects

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	"github.com/adedayo/checkmate/pkg/core/util"
	"gopkg.in/yaml.v3"
)

type Workspace struct {
	Details map[string]*WorkspaceDetail `json:"Details" yaml:"Details"`
}

func (wss *Workspace) SetProjectSummary(ps *ProjectSummary, pm ProjectManager) {
	defer pm.SaveWorkspaces(wss)
	workspace := ps.Workspace
	if wss.Details == nil {
		wss.Details = make(map[string]*WorkspaceDetail)
	}
	if ws, exist := wss.Details[workspace]; exist {
		for i, p := range ws.ProjectSummaries {
			if p.ID == ps.ID {
				ws.ProjectSummaries[i] = ps
				wss.Details[workspace] = ws
				return
			}
		}
		ws.ProjectSummaries = append(ws.ProjectSummaries, ps)
		wss.Details[workspace] = ws
	} else {
		wss.Details[workspace] = &WorkspaceDetail{
			Summary:          &ScanSummary{},
			ProjectSummaries: []*ProjectSummary{ps},
		}
	}
}

func (wss *Workspace) RemoveProjectSummary(ps *ProjectSummary, pm ProjectManager) error {

	workspace := ps.Workspace
	if wss.Details == nil {
		wss.Details = make(map[string]*WorkspaceDetail)
	}
	if ws, exist := wss.Details[workspace]; exist {
		newSummaries := []*ProjectSummary{}
		for _, p := range ws.ProjectSummaries {
			if p.ID != ps.ID {
				newSummaries = append(newSummaries, p)
			}
		}
		ws.ProjectSummaries = newSummaries
		wss.Details[workspace] = ws
	}

	return pm.SaveWorkspaces(wss)
}

type WorkspaceDetail struct {
	Summary          *ScanSummary      `json:"Summary" yaml:"Summary"`
	ProjectSummaries []*ProjectSummary `json:"ProjectSummaries" yaml:"ProjectSummaries"`
}

type Project struct {
	ID                   string       `yaml:"ID"`                   //unique
	Name                 string       `yaml:"Name"`                 //human-friendly
	Workspace            string       `yaml:"Workspace"`            //Used to group related projects
	DeleteCheckedOutCode bool         `yaml:"DeleteCheckedOutCode"` //whether to delete code checked out after scan is complete
	Repositories         []Repository `yaml:"Repositories,omitempty"`
	ScanIDs              []string     `yaml:"ScanIDs"`
	ScanPolicy           ScanPolicy   `yaml:"ScanPolicy"`
}

// ProjectDescription used to create new/update projects
type ProjectDescription struct {
	Name         string       `yaml:"Name"` //human-friendly
	Repositories []Repository `yaml:"Repositories,omitempty"`
	Workspace    string       `yaml:"Workspace"` //Used to group related projects
	ScanPolicy   ScanPolicy   `yaml:"ScanPolicy"`
}

// ProjectDescriptionWire used to create new/update projects (wire representation)
type ProjectDescriptionWire struct {
	Name         string         `yaml:"Name"` //human-friendly
	Repositories []Repository   `yaml:"Repositories,omitempty"`
	Workspace    string         `yaml:"Workspace"` //Used to group related projects
	ScanPolicy   ScanPolicyWire `yaml:"ScanPolicy"`
}

func (desc ProjectDescriptionWire) ToProjectDescription() (ProjectDescription, error) {

	desc.Repositories = sanitiseRepositories(desc.Repositories)
	var policy diagnostics.ExcludeDefinition = diagnostics.DefaultExclusion()
	policyID := desc.ScanPolicy.ID
	if policyID == "" {
		policyID = util.NewRandomUUID().String()
	}
	pDesc := ProjectDescription{
		Name:         desc.Name,
		Repositories: desc.Repositories,
		Workspace:    desc.Workspace,
		ScanPolicy: ScanPolicy{
			ID:     policyID,
			Config: desc.ScanPolicy.Config,
			Policy: policy,
		}}

	if desc.ScanPolicy.PolicyString == "" {
		return pDesc, nil
	}

	if err := yaml.Unmarshal([]byte(desc.ScanPolicy.PolicyString), &policy); err != nil {
		log.Printf("Error parsing scan exclusion, reverting to default: %s", err.Error())
		return ProjectDescription{
			Name:         desc.Name,
			Repositories: desc.Repositories,
			Workspace:    desc.Workspace,
			ScanPolicy: ScanPolicy{
				ID:           desc.ScanPolicy.ID,
				Config:       desc.ScanPolicy.Config,
				Policy:       policy,
				PolicyString: desc.ScanPolicy.PolicyString,
			}}, fmt.Errorf("error parsing scan exclusion, reverting to default: %s", err.Error())
	}
	//if all good, assign parsed policy
	pDesc.ScanPolicy.Policy = policy
	return pDesc, nil
}

func sanitiseRepositories(repository []Repository) []Repository {
	for i, r := range repository {
		r.Location = gitutils.GitToHTTPS(r.Location)
		repository[i] = r
	}

	return repository
}

// Intended to be used to check the status of a Git repository, such as "Archived", just before checkout
// Results are stored in the Attributes map of the returned repository
type RepositoryStatusChecker func(context.Context, ProjectManager, *Repository) (*Repository, error)

type Repository struct {
	Location     string `yaml:"Location"`
	LocationType string `yaml:"LocationType"` //filesystem, git, svn etc.
	GitServiceID string `yaml:"GitServiceID"` /*if this repository is from a "private" on-prem instance,
	the service ID is used to locate the instance and associated API keys etc*/
	Monitor    bool                    `yaml:"Monitor"`              //If this repository is continuously monitored for changes
	Attributes *map[string]interface{} `yaml:"Attributes,omitempty"` //track any additional metadata about the repo, e.g. "archived"
}

func (repo Repository) IsGit() bool {
	return repo.LocationType == "git"
}

func (repo Repository) IsFileSystem() bool {
	return repo.LocationType == "filesystem"
}

func (repo Repository) GetCodeLocation(pm ProjectManager, projectID string) string {
	if repo.IsGit() {
		baseDir := path.Join(pm.GetCodeBaseDir(), projectID)
		dir, err := gitutils.GetCheckoutLocation(repo.Location, baseDir)
		if err == nil {
			return dir
		}
		return repo.Location
	}
	return repo.Location
}

type ScanHistory struct {
	Time   time.Time
	ScanID string
	Commit gitutils.Commit
}

type ScannedCommit struct {
	Repository string
	Commit     gitutils.Commit
}

type Scan struct {
	ID         string
	Score      Score
	Start, End time.Time
	Issues     []diagnostics.SecurityDiagnostic
	Policy     ScanPolicy
}

type ScanPolicyWire struct {
	ID           string `yaml:"ID"`
	Policy       string `yaml:"Policy,omitempty"`
	PolicyString string
	Config       map[string]interface{} //indexes to scan configurations, key secrets for secret finder
}
type ScanPolicy struct {
	ID           string                        `yaml:"ID"`
	Policy       diagnostics.ExcludeDefinition `yaml:"Policy,omitempty"`
	PolicyString string                        `yaml:"-"`
	Config       map[string]interface{}        //indexes to scan configurations, use the key "secrets" for secret finder
}

func (sp ScanPolicy) MarshalJSON() ([]byte, error) {
	type Alias ScanPolicy
	policy, err := yaml.Marshal(sp.Policy)
	if err != nil {
		return []byte(err.Error()), err
	}
	pol := ""
	if len(policy) == 0 {
		pol = diagnostics.GenerateSampleExclusion()
	} else {
		pol = string(policy)
	}
	return json.Marshal(&struct {
		*Alias
		PolicyString string
	}{
		Alias:        (*Alias)(&sp),
		PolicyString: pol,
	})
}

// Scan and Commit history of a repository branch
type RepositoryHistory struct {
	Repository      Repository
	ScanHistories   []ScanHistory
	CommitHistories []gitutils.Commit
}

type ProjectSummary struct {
	ID           string       `yaml:"ID" json:"ID"`
	Name         string       `yaml:"Name" json:"Name"`
	Workspace    string       `yaml:"Workspace" json:"Workspace"` //Used to group related projects
	Repositories []Repository `yaml:"Repositories,omitempty" json:"Repositories,omitempty"`
	//From RepoLocation -> branch -> RepoHistory
	ScanAndCommitHistories map[string]map[string]RepositoryHistory `yaml:"ScanAndCommitHistories,omitempty" json:"ScanAndCommitHistories,omitempty"`
	LastScanID             string                                  `yaml:"LastScanID" json:"LastScanID"`
	ScanIDs                []string                                `yaml:"ScanIDs" json:"ScanIDs"`
	ScanPolicy             ScanPolicy                              `yaml:"ScanPolicy" json:"ScanPolicy"`
	ScoreTrend             map[string]float32                      `yaml:"ScoreTrend,omitempty" json:"ScoreTrend,omitempty"` // use this to record arbitrary numeric scores, even time series of trends etc.
	LastScanSummary        ScanSummary                             `yaml:"LastScanSummary" json:"LastScanSummary"`
	LastScore              Score                                   `yaml:"LastScore" json:"LastScore"`
	IsBeingScanned         bool                                    `yaml:"IsBeingScanned" json:"IsBeingScanned"`
	CreationDate           time.Time                               `yaml:"CreationDate" json:"CreationDate"`
	LastModification       time.Time                               `yaml:"LastModification" json:"LastModification"`
	LastScan               time.Time                               `yaml:"LastScan" json:"LastScan"`
}

func (p ProjectSummary) ToProject() Project {
	return Project{
		ID:           p.ID,
		Name:         p.Name,
		Workspace:    p.Workspace,
		Repositories: p.Repositories,
		ScanIDs:      p.ScanIDs,
		ScanPolicy:   p.ScanPolicy,
	}
}

func (ps *ProjectSummary) GetCommitsByBranch(location string) map[string][]gitutils.Commit {
	br := make(map[string][]gitutils.Commit)

	if ps.ScanAndCommitHistories == nil {
		ps.ScanAndCommitHistories = make(map[string]map[string]RepositoryHistory)
	}
	if repoHistory, exists := ps.ScanAndCommitHistories[location]; exists {
		for branch, rh := range repoHistory {
			br[branch] = rh.CommitHistories
		}
	}

	return br
}

func (ps ProjectSummary) GetLastCommitByBranch(location string) map[string][]gitutils.Commit {
	out := make(map[string][]gitutils.Commit)

	for branch, commits := range ps.GetCommitsByBranch(location) {
		out[branch] = []gitutils.Commit{}
		if len(commits) > 0 {
			sort.SliceStable(commits, func(i, j int) bool {
				a := commits[i].Time
				b := commits[j].Time
				return a.After(b) || a.Equal(b)
			})
			out[branch] = []gitutils.Commit{commits[0]}
		}
	}
	return out
}

func (ps *ProjectSummary) GetScansByBranch(location string) map[string][]gitutils.Commit {
	out := make(map[string][]gitutils.Commit)

	if ps.ScanAndCommitHistories == nil {
		ps.ScanAndCommitHistories = make(map[string]map[string]RepositoryHistory)
	}

	if repoHistory, exists := ps.ScanAndCommitHistories[location]; exists {
		for branch, rh := range repoHistory {
			out[branch] = []gitutils.Commit{}
			for _, sh := range rh.ScanHistories {
				out[branch] = append(out[branch], sh.Commit)
			}

		}
	}
	return out
}

func (ps ProjectSummary) CSVHeaders() []string {
	return []string{
		`Project Name`,
		`Grade (A-F)`,
		`Metric (Score out of 100)`,
		`Production Secrets Count`,
		`Critical Issues Count`,
		`High Issues Count`,
		`Medium Issues Count`,
		`Low Issues Count`,
		`Informational Issues Count`,
		`Workspace`,
		`Repositories`,
		`ID`,
	}
}

func (ps *ProjectSummary) CSVValues() []string {
	reps := []string{}
	for _, r := range ps.Repositories {
		reps = append(reps, r.Location)
	}

	csvs := []string{
		ps.Name,
		ps.LastScanSummary.Score.Grade,
		roundDown(ps.LastScanSummary.Score.Metric),
	}
	csvs = append(csvs, severityCounts(ps)...)
	// getSeverity(ps, `criticalCount`),
	// getSeverity(ps, `highCount`),
	// getSeverity(ps, `mediumCount`),
	// getSeverity(ps, `lowCount`),
	// getSeverity(ps, `informationalCount`),
	csvs = append(csvs, []string{ps.Workspace,
		strings.Join(reps, "; "),
		ps.ID,
	}...)
	return csvs
}

func severityCounts(ps *ProjectSummary) []string {
	if ps.LastScanSummary.AdditionalInfo == nil {
		return []string{"-", "-", "-", "-", "-", "-"}
	}
	return []string{
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.ProductionSecretsCount),
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.CriticalCount),
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.HighCount),
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.MediumCount),
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.LowCount),
		fmt.Sprintf("%d", ps.LastScanSummary.AdditionalInfo.InformationalCount),
	}
}

// func getSeverity(ps *ProjectSummary, criticality string) string {
// 	if info, ok := ps.LastScanSummary.AdditionalInfo.(map[string]interface{}); ok {
// 		if val, ok2 := info[criticality].(int); ok2 {
// 			return fmt.Sprintf("%d", val)
// 		}
// 	}
// 	return ""
// }

func roundDown(num float32) string {
	return fmt.Sprintf("%d", int64(num))
}

func (ps *ProjectSummary) MarshalJSON() ([]byte, error) {
	type Alias ProjectSummary
	return json.Marshal(&struct {
		*Alias
		CreationDate     string
		LastModification string
		LastScan         string
	}{
		Alias:            (*Alias)(ps),
		CreationDate:     ps.CreationDate.Format(time.RFC3339),
		LastModification: ps.LastModification.Format(time.RFC3339),
		LastScan:         ps.LastScan.Format(time.RFC3339),
	})
}

type ScanSummary struct {
	Score          Score
	CommitHash     string
	AdditionalInfo *Model
}

type PaginatedIssueSearch struct {
	ProjectID string
	ScanID    string
	PageSize  int
	Page      int
	Filter    IssueFilter
}

type IssueFilter struct {
	Confidence []string //high, med, low, info
	Tags       []string //test, prod
}

func empty(data []string) bool {
	return len(data) == 0
}

func (filter IssueFilter) Filter(in []*diagnostics.SecurityDiagnostic) (out []*diagnostics.SecurityDiagnostic) {

	if empty(filter.Confidence) && empty(filter.Tags) {
		//do nothing
		return in
	}
	for _, sd := range in {

		if !empty(filter.Confidence) && empty(filter.Tags) {
			for _, v := range filter.Confidence {
				if sd.Justification.Headline.Confidence.String() == v {
					out = append(out, sd)
					break
				}
			}
		} else if !empty(filter.Tags) && empty(filter.Confidence) {
			for _, v := range filter.Tags {
				if sd.HasTag(v) {
					out = append(out, sd)
					break
				}
			}
		} else { //neither tags nor confidence is empty
			for _, c := range filter.Confidence {
				if sd.Justification.Headline.Confidence.String() == c {
					for _, t := range filter.Tags {
						if sd.HasTag(t) {
							out = append(out, sd)
							goto next
						}
					}
				}
			}
		}

	next:
	}

	return
}

type PagedResult struct {
	Total       int
	Page        int
	Diagnostics []*diagnostics.SecurityDiagnostic
}
