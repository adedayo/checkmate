package api

import (
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
)

type Config struct {
	AppName, AppVersion string
	ApiPort             int
	Local               bool //if set, to bind the api to localhost:port (electron) or simply :port (web service) instead
}

type ProjectScanOptions struct {
	ProjectID, ScanID   string
	SecretSearchOptions secrets.SecretSearchOptions
}

type SocketEndMessage struct {
	Message string
}
