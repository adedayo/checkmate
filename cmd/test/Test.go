package main

import (
	"fmt"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate-core/pkg/util"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
)

func main() {
	pm := projects.MakeSimpleProjectManager()
	project := pm.CreateProject(projects.ProjectDescription{
		Name: "Another New Project",
		Repositories: []projects.Repository{
			{
				Location:     "/Users/dayo/softdev/opensrc/go/src/github.com/adedayo/static-analysis-test-code",
				LocationType: "filesystem",
			},
		},
	})

	fmt.Printf("Created Project %#v\n", project)
	var scanID string
	scanIDC := func(sID string) {
		scanID = sID
		println("Got scanID ", scanID)
	}

	paths := []string{}
	progressM := func(progress diagnostics.Progress) {
		paths = append(paths, progress.CurrentFile)
		// fmt.Printf("Progress %#v\n", progress)
	}

	diagConsumers := []diagnostics.SecurityDiagnosticsConsumer{outConsumer{}}

	var excludeDefinitions diagnostics.ExcludeDefinition = secrets.MakeCommonExclusions()

	exclusions, _ := diagnostics.CompileExcludes(&excludeDefinitions)
	options := secrets.SecretSearchOptions{
		ShowSource:            true,
		Exclusions:            exclusions,
		ConfidentialFilesOnly: false,
		CalculateChecksum:     true,
		Verbose:               false,
		ReportIgnored:         false,
		ExcludeTestFiles:      false,
	}

	policy := projects.ScanPolicy{
		Config: map[string]interface{}{"secret-search-options": options},
		ID:     util.NewRandomUUID().String(),
		Policy: excludeDefinitions,
	}

	summariser := func(projID, sID string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {
		model, err := asciidoc.ComputeMetrics(paths, options, issues)
		if err != nil {
			return &projects.ScanSummary{}
		}
		return model.Summarise()
	}

	pm.RunScan(project.ID, policy, secrets.MakeSecretScanner(options),
		scanIDC, progressM, summariser, diagConsumers...)

	println("Project Summaries:")
	for _, sum := range pm.ListProjectSummaries() {
		fmt.Printf("%#v\n", sum)
	}

}

type outConsumer struct {
}

func (outConsumer) ReceiveDiagnostic(diag *diagnostics.SecurityDiagnostic) {
	// fmt.Printf("Diag: %v\n", diag)
}
