package report

import (
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
)

type ReportModel struct {
	Logo                                                   string
	SALLogo                                                string
	Grade                                                  string
	Chart                                                  string
	HighCount, MediumCount, LowCount, InformationalCount   int
	FileCount, SkippedCount, IssuesPerType, AveragePerFile int
	Issues                                                 []diagnostics.SecurityDiagnostic
	TimeStamp                                              string
}
