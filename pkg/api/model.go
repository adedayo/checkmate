package api

import (
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
)

type Config struct {
	AppName, AppVersion string
	ApiPort             int
	Local               bool //if set, to bind the api to localhost:port (electron) or simply :port (web service) instead
	ServeGitService     bool
	CheckMateDataPath   string
	ReportPlugins       []string
	Store               store.PlatformStore
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
