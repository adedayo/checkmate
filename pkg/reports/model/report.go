package report

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

// Model models the generated report
type Model struct {
	Logo                                                   string
	SALLogo                                                string
	Grade                                                  string
	GradeLogo                                              string
	Chart                                                  string
	HighCount, MediumCount, LowCount, InformationalCount   int
	FileCount, SkippedCount, IssuesPerType, AveragePerFile int
	Issues                                                 []diagnostics.SecurityDiagnostic
	TimeStamp                                              string
	ShowSource                                             bool
}
