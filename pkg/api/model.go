package api

import secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"

type Config struct {
	AppName, AppVersion string
	ApiPort             int
	Local               bool //if to bind the api to localhost:port (electron) or simply :port (web app) instead
}

type ProjectScanOptions struct {
	ProjectID, ScanID   string
	SecretSearchOptions secrets.SecretSearchOptions
}

type SocketEndMessage struct {
	Message string
}
