package projects

import (
	"context"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

type SecurityScanner interface {
	//runs a scan over a project, with a specific scanID, project manager provides infrastructure for interrogating
	//the project such as code repositories or locations, a prorgress callback provides indication of how the scan is progressing
	//and consumers receive the results of scan
	Scan(ctx context.Context, projectID string, scanID string, pm ProjectManager, repoStatusChecker RepositoryStatusChecker,
		callback func(diagnostics.Progress), consumers ...diagnostics.SecurityDiagnosticsConsumer)
}
