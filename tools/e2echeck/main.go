// Command e2echeck drives the same scan path the Wails desktop app uses —
// the sqlite PlatformStore's RunScan with a SecretScanner — against a large
// project, so that the app's end-to-end behaviour is exercised without a
// display.
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/gitservice/utils"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
)

type consumer struct{ n int }

func (c *consumer) ReceiveDiagnostic(d *diagnostics.SecurityDiagnostic) { c.n++ }

func main() {
	dataDir, target := os.Args[1], os.Args[2]

	db, err := sqlite.New(dataDir)
	if err != nil {
		panic(err)
	}

	proj, err := db.CreateProject(projects.ProjectDescription{
		Name:      "wails-e2e",
		Workspace: "default",
		Repositories: []projects.Repository{
			{Location: target, LocationType: "filesystem"},
		},
		ScanPolicy: projects.ScanPolicy{Policy: diagnostics.DefaultExclusion()},
	})
	if err != nil {
		panic(err)
	}

	summary, err := db.GetProjectSummary(proj.ID)
	if err != nil {
		panic(err)
	}

	exProvider, err := db.BuildExclusionProvider(proj.ID)
	if err != nil || exProvider == nil {
		exProvider = diagnostics.MakeEmptyExcludes()
	}

	secOptions := secrets.SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        exProvider,
	}

	// The app subscribes to the SSE broker and re-emits each finding over the
	// Wails bridge. Subscribing here proves the broker still delivers under
	// the parallel pipeline.
	var streamed int
	streamDone := make(chan struct{})
	scanIDC := func(id string) {
		ch, cleanup := db.GetBroker().Subscribe(id)
		go func() {
			defer close(streamDone)
			defer cleanup()
			for ev := range ch {
				if ev.Type == store.EventFinding {
					streamed++
				}
			}
		}()
	}

	var scanSummary *projects.ScanSummary
	summariser := func(_, _ string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {
		m := projects.GenerateModel(len(summary.Repositories), secOptions.ShowSource, issues)
		scanSummary = m.Summarise()
		return scanSummary
	}

	c := &consumer{}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()

	db.RunScan(context.Background(), proj.ID, summary.ScanPolicy,
		secrets.MakeSecretScanner(secOptions), scanIDC,
		utils.GitRepositoryStatusChecker, func(diagnostics.Progress) {},
		summariser, projects.SimpleWorkspaceSummariser, c)

	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	fmt.Printf("elapsed=%s findings=%s streamedToUI=%d peakHeap=%.1fMB\n",
		elapsed.Round(time.Millisecond), fmtInt(c.n), streamed,
		float64(after.HeapSys)/(1<<20))

	if scanSummary != nil && scanSummary.AdditionalInfo != nil {
		i := scanSummary.AdditionalInfo
		fmt.Printf("grade=%s critical=%d high=%d medium=%d low=%d\n",
			scanSummary.Score.Grade, i.CriticalCount, i.HighCount,
			i.MediumCount, i.LowCount)
	}

	// The app reads findings back out of the store to render the table.
	issues, err := db.GetIssues(projects.PaginatedIssueSearch{
		ProjectID: proj.ID, PageSize: 5, Page: 0,
	})
	if err != nil {
		fmt.Println("GetIssues error:", err)
	} else {
		fmt.Printf("readBackFromStore total=%d page=%d\n",
			issues.Total, len(issues.Diagnostics))
	}
}

func fmtInt(n int) string { return fmt.Sprintf("%d", n) }
