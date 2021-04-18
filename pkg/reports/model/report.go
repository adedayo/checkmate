package report

import (
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate-core/pkg/scores"
)

// Model models the generated report
type Model struct {
	Grade                string
	Logo                 string `yaml:"-"`
	SALLogo              string `yaml:"-"`
	GradeLogo            string `yaml:"-"`
	Chart                string `yaml:"-"`
	HighCount            int
	MediumCount          int
	LowCount             int
	InformationalCount   int
	FileCount            int
	SkippedCount         int
	IssuesPerType        int
	AveragePerFile       float32
	Issues               []*diagnostics.SecurityDiagnostic `yaml:"-"`
	TimeStamp            string
	ShowSource           bool
	ReusedSecretsCount   int
	NumberOfSecretsReuse int
	ReusedSecrets        map[string][]*diagnostics.SecurityDiagnostic `yaml:"-"`
}

//Summarise converts model to a ScanSummary, attaching the model to AdditionalInfo
func (m *Model) Summarise() *projects.ScanSummary {

	return &projects.ScanSummary{
		Score: scores.Score{
			Grade:     m.Grade,
			Metric:    0.5,
			TimeStamp: time.Now(),
		},
		AdditionalInfo: m,
	}
}
