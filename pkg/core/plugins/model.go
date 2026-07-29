package plugins

import (
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

type DiagnosticTransformer interface {
	Transform(*Config, ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic
}

type DiagnosticTransformerPlugin interface {
	DiagnosticTransformer
	ShutDown() error
}

type Config struct {
	CodeBaseDir string // code base directory
	ProjectID   string
}

type ConfigDiagnostics struct {
	Config      *Config                           `json:"Config,omitempty"`
	Diagnostics []*diagnostics.SecurityDiagnostic `json:"Diagnostics,omitempty"`
}
