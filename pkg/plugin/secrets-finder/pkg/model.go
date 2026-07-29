package secrets

import "github.com/adedayo/checkmate/pkg/core/diagnostics"

//SecretSearchOptions search options for the secret finder plugin
type SecretSearchOptions struct {
	ShowSource            bool                          `json:"ShowSource" yaml:"ShowSource"`
	Exclusions            diagnostics.ExclusionProvider `json:"-" yaml:"-"`
	ConfidentialFilesOnly bool                          `json:"ConfidentialFilesOnly" yaml:"ConfidentialFilesOnly"`
	CalculateChecksum     bool                          `json:"CalculateChecksum" yaml:"CalculateChecksum"`
	Verbose               bool                          `json:"Verbose" yaml:"Verbose"`                   //Verbose logging of file paths about to be scanned
	ReportIgnored         bool                          `json:"ReportIgnored" yaml:"ReportIgnored"`       //if set, generate diagnostics for excluded files/paths and values
	ExcludeTestFiles      bool                          `json:"ExcludeTestFiles" yaml:"ExcludeTestFiles"` //if set, excludes suspected Test Files
}
