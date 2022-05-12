package main

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

func main() {

	// pm := projects.MakeSimpleProjectManager("~/.checkmate")

	// project, _ := pm.GetProject("0b57cd1d-726d-457c-ba1a-435cca48bd26")

	// summary, err := pm.GetScanResultSummary("0b57cd1d-726d-457c-ba1a-435cca48bd26", "ed9a6605-4d60-4346-989c-12bb24bd899a")
	// // fmt.Printf("Additional Info: %#v\n", summary.AdditionalInfo)

	// if err == nil {
	// 	mapp, ok := summary.AdditionalInfo.(map[string]interface{})

	// 	if ok {
	// 		fmt.Printf("Map: %#v\n", mapp)
	// 	}

	// 	fmt.Printf("Got project %#v\n", project.ID)

	// 	println(mapp["showsource"].(bool))
	// }

	// b, err := json.MarshalIndent(project, " ", " ")
	// if err == nil {
	// 	println("\n\nStringified: ", string(b))
	// } else {
	// 	fmt.Printf("Error: %e\n", err)
	// }

	// b2, err := json.MarshalIndent(project.ScanPolicy.Policy, " ", " ")

	// if err == nil {
	// 	println("\n\nStringified: ", string(b2))
	// } else {
	// 	fmt.Printf("Error: %e\n", err)
	// }

	// p2 := pm.UpdateProject("0b57cd1d-726d-457c-ba1a-435cca48bd26", projects.ProjectDescription{
	// 	Name:         project.Name,
	// 	Repositories: project.Repositories,
	// 	ScanPolicy:   project.ScanPolicy,
	// })

	// fmt.Printf("Original: %#v\n Modified: %#v\n", project, p2)

	// results := pm.GetIssues(projects.PaginatedIssueSearch{
	// 	ProjectID: "0b57cd1d-726d-457c-ba1a-435cca48bd26",
	// 	ScanID:    "db559f54-c8e0-4acc-a212-840bd6caa41c",
	// 	PageSize:  10,
	// 	Page:      0,
	// })

	// rr := pm.RemediateIssue(diagnostics.ExcludeRequirement{
	// 	What:      "ignore_here",
	// 	ProjectID: "0b57cd1d-726d-457c-ba1a-435cca48bd26",
	// 	Issue:     *results.Diagnostics[3],
	// })

	// fmt.Printf("%#v\n", rr)

	return

	// project := pm.CreateProject(projects.ProjectDescription{
	// 	Name: "Another New Project",
	// 	Repositories: []projects.Repository{
	// 		{
	// 			Location:     "/Users/dayo/softdev/opensrc/go/src/github.com/adedayo/static-analysis-test-code",
	// 			LocationType: "filesystem",
	// 		},
	// 	},
	// })

	// fmt.Printf("Created Project %#v\n", project)
	// var scanID string
	// scanIDC := func(sID string) {
	// 	scanID = sID
	// 	println("Got scanID ", scanID)
	// }

	// paths := []string{}
	// progressM := func(progress diagnostics.Progress) {
	// 	paths = append(paths, progress.CurrentFile)
	// 	// fmt.Printf("Progress %#v\n", progress)
	// }

	// diagConsumers := []diagnostics.SecurityDiagnosticsConsumer{outConsumer{}}

	// var excludeDefinitions diagnostics.ExcludeDefinition = secrets.MakeCommonExclusions()

	// exclusions, _ := diagnostics.CompileExcludes(&excludeDefinitions)
	// options := secrets.SecretSearchOptions{
	// 	ShowSource:            true,
	// 	Exclusions:            exclusions,
	// 	ConfidentialFilesOnly: false,
	// 	CalculateChecksum:     true,
	// 	Verbose:               false,
	// 	ReportIgnored:         false,
	// 	ExcludeTestFiles:      false,
	// }

	// policy := projects.ScanPolicy{
	// 	Config: map[string]interface{}{"secret-search-options": options},
	// 	ID:     util.NewRandomUUID().String(),
	// 	Policy: excludeDefinitions,
	// }

	// summariser := func(projID, sID string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {
	// 	model, err := asciidoc.ComputeMetrics(paths, options, issues)
	// 	if err != nil {
	// 		return &projects.ScanSummary{}
	// 	}
	// 	return model.Summarise()
	// }

	// pm.RunScan(project.ID, policy, secrets.MakeSecretScanner(options),
	// 	scanIDC, progressM, summariser, diagConsumers...)

	// println("Project Summaries:")
	// for _, sum := range pm.ListProjectSummaries() {
	// 	fmt.Printf("%#v\n", sum)
	// }

}

type outConsumer struct {
}

func (outConsumer) ReceiveDiagnostic(diag *diagnostics.SecurityDiagnostic) {
	// fmt.Printf("Diag: %v\n", diag)
}
