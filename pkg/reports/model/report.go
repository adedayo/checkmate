package report

import (
	"math"
	"time"

	"github.com/adedayo/checkmate-core/pkg/code"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate-core/pkg/scores"
)

// Model models the generated report
type Model struct {
	Grade                     string
	Logo                      string                                       `yaml:"-"`
	SALLogo                   string                                       `yaml:"-"`
	GradeLogo                 string                                       `yaml:"-"`
	Chart                     string                                       `yaml:"-"`
	HighCount                 int                                          `json:"highCount"`
	MediumCount               int                                          `json:"mediumCount"`
	LowCount                  int                                          `json:"lowCount"`
	InformationalCount        int                                          `json:"informationalCount"`
	FileCount                 int                                          `json:"fileCount"`
	SkippedCount              int                                          `json:"skippedCount"`
	IssuesPerType             int                                          `json:"issuesPerType"`
	AveragePerFile            float32                                      `json:"averagePerFile"`
	Issues                    []*diagnostics.SecurityDiagnostic            `yaml:"-"`
	TimeStamp                 string                                       `json:"timeStamp"`
	ShowSource                bool                                         `json:"showSource"`
	ReusedSecretsCount        int                                          `json:"reusedSecretsCount"`
	NumberOfSecretsReuse      int                                          `json:"numberOfSecretsReuse"`
	ReusedSecrets             map[string][]*diagnostics.SecurityDiagnostic `yaml:"-"`
	ProdAndNonProdSecretReuse []ReusedSecret                               `json:"prodAndNonProdSecretReuse"`
}

type ReusedSecret struct {
	Secret                 string
	ProductionLocations    []SecretLocation `json:"productionLocations"`
	NonProductionLocations []SecretLocation `json:"nonProductionLocations"`
}

type SecretLocation struct {
	Location       string
	HighlightRange code.Range `json:"highLightRange"`
}

//Summarise converts model to a ScanSummary, attaching the model to AdditionalInfo
func (m *Model) Summarise() *projects.ScanSummary {

	rus := []ReusedSecret{}
	for k, dd := range m.ReusedSecrets {
		prod := []SecretLocation{}
		dev := []SecretLocation{}
		for _, d := range dd {
			if hasTag("test", d) {
				dev = append(dev, SecretLocation{
					Location:       *d.Location,
					HighlightRange: d.HighlightRange,
				})
			} else {
				prod = append(prod, SecretLocation{
					Location:       *d.Location,
					HighlightRange: d.HighlightRange,
				})
			}
		}
		if len(prod)*len(dev) > 0 { //only record secrets that are reused across both production and non-production
			rus = append(rus, ReusedSecret{
				Secret:                 k,
				ProductionLocations:    prod,
				NonProductionLocations: dev,
			})
		}

	}

	m.ProdAndNonProdSecretReuse = rus

	//100% basis metric
	metric := (0.3*m.calculateProductionVsTestSecretReuse() +
		0.4*m.calculateSensitiveFilesPenalty() + 0.1*m.calculateSecretsReuse() +
		0.2*m.calculateHigherConfidencePenalties())

	grade := metricToGrade(metric)
	m.Grade = grade

	return &projects.ScanSummary{
		Score: scores.Score{
			Grade:     grade,
			Metric:    metric,
			TimeStamp: time.Now(),
		},
		AdditionalInfo: m,
	}
}

func metricToGrade(metric float32) string {
	if metric > 95 {
		return "A+"
	}
	if metric > 85 {
		return "A"
	}
	if metric > 70 {
		return "B"
	}
	if metric > 60 {
		return "C"
	}
	if metric > 50 {
		return "D"
	}
	if metric > 40 {
		return "E"
	}
	return "F"
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
				test = true
				if prod {
					return 0
				}
			} else {
				prod = true
				if test {
					return 0
				}
			}
		}
	}
	return 100
}

//penalises the use of sensitive files (e.g. certificates, key stores etc) in non-test.
//If all instances are in a test context, then a 70% mark is returned instead of 100% max score
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
		return 70
	}
	return 100
}

//penalise for the number of reuse
func (m Model) calculateSecretsReuse() (score float32) {
	reuseCount := float64(0)
	reuseEntropy := float64(0)
	sizes := []float64{}
	for _, v := range m.ReusedSecrets {
		n := float64(len(v))
		sizes = append(sizes, n)
		reuseCount += n
		// log.Printf("Ent: %f = %f/%f, sum = %f\n", ent, math.Log2(n), n, reuseEntropy)
	}

	if reuseCount == 0 {
		return 100
	}

	for _, size := range sizes {
		p := size / reuseCount
		reuseEntropy -= p * math.Log2(p)
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
