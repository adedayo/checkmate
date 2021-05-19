package report

import (
	"math"
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
			Grade: m.Grade,
			Metric: (0.3*m.calculateProductionVsTestSecretReuse() +
				0.3*m.calculateSensitiveFilesPenalty() + 0.1*m.calculateSecretsReuse() +
				0.3*m.calculateHigherConfidencePenalties()) / 100,
			TimeStamp: time.Now(),
		},
		AdditionalInfo: m,
	}
}

func hasTag(tag string, diag *diagnostics.SecurityDiagnostic) bool {
	if diag.Tags == nil {
		return false
	}

	for _, t := range *diag.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// tests whether secrets are reused in test vs non-test contexts
func (m Model) calculateProductionVsTestSecretReuse() (score float32) {
	for _, v := range m.ReusedSecrets {
		var prod, test bool
		for _, diag := range v {
			if hasTag("test", diag) {
				if prod {
					return 0
				}
			} else {
				if test {
					return 0
				}
			}
		}
	}
	return 100
}

//penalises the use of sensitive files (e.g. certificates, key stores etc) in non-test.
//If all instances are in a test context, then only 30% mark is returned instead of 100% max score
func (m Model) calculateSensitiveFilesPenalty() (score float32) {
	var test bool
	for _, issue := range m.Issues {
		if hasTag("confidential", issue) {
			if !hasTag("test", issue) {
				return 0
			}
			test = true
		}
	}
	if test {
		return 30
	}
	return 100
}

//penalise for the number of reuse
func (m Model) calculateSecretsReuse() (score float32) {
	reuseCount := float64(0)
	reuseEntropy := float64(0)
	for _, v := range m.ReusedSecrets {
		n := float64(len(v))
		reuseCount += n
		ent := math.Log2(n) / n
		reuseEntropy += ent
		// log.Printf("Ent: %f = %f/%f, sum = %f\n", ent, math.Log2(n), n, reuseEntropy)
	}

	if reuseCount == 0 {
		return 100
	}

	// the max "entropy" is log2(reuseCount), we use that to calculate how close the reuse is to the max
	//i.e  100 * reuseEntropy/maxEntropy
	score = float32((100 * reuseEntropy) / math.Log2(reuseCount))
	// log.Printf("Got reuse score of %f. = 100 * %f * %f / %f\n", score, reuseEntropy, reuseCount, math.Log2(reuseCount))
	return score

}

func (m Model) calculateHigherConfidencePenalties() float32 {

	score := float32(100)

	if m.LowCount > 0 {
		score = capScore(score, 90)
	}
	if m.MediumCount > 0 {
		score = capScore(score, 60)
	}

	if m.HighCount > 0 {
		score = capScore(score, 10)
	}

	return score
}

func capScore(score, cap float32) float32 {
	if score > cap {
		return cap
	}
	return score
}
