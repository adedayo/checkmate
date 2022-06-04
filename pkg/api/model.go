package api

import (
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
)

type Config struct {
	AppName, AppVersion string
	ApiPort             int
	Local               bool //if set, to bind the api to localhost:port (electron) or simply :port (web service) instead
	ServeGitService     bool
	CheckMateDataPath   string
	ReportPlugins       []string
	ProjectManager      projects.ProjectManager
}

type ProjectScanOptions struct {
	ProjectID, ScanID   string
	SecretSearchOptions secrets.SecretSearchOptions
}

type MonitorOptions struct {
	ProjectIDs []string
}

// type SocketEndMessage struct {
// 	Message string
// }
