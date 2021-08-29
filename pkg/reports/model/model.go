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
	Grade                            string
	Logo                             string                                       `yaml:"-" json:"-"`
	SALLogo                          string                                       `yaml:"-" json:"-"`
	GradeLogo                        string                                       `yaml:"-" json:"-"`
	Chart                            string                                       `yaml:"-" json:"-"`
	CriticalCount                    int                                          `json:"criticalCount" yaml:"criticalCount"`
	HighCount                        int                                          `json:"highCount" yaml:"highCount"`
	MediumCount                      int                                          `json:"mediumCount" yaml:"mediumCount"`
	LowCount                         int                                          `json:"lowCount" yaml:"lowCount"`
	InformationalCount               int                                          `json:"informationalCount" yaml:"informationalCount"`
	ProductionConfidentialFilesCount int                                          `json:"productionConfidentialFilesCount" yaml:"productionConfidentialFilesCount"`
	FileCount                        int                                          `json:"fileCount" yaml:"fileCount"`
	SkippedCount                     int                                          `json:"skippedCount" yaml:"skippedCount"`
	IssuesPerType                    int                                          `json:"issuesPerType" yaml:"issuesPerType"`
	AveragePerFile                   float32                                      `json:"averagePerFile" yaml:"averagePerFile"`
	Issues                           []*diagnostics.SecurityDiagnostic            `yaml:"-" json:"-"`
	TimeStamp                        string                                       `json:"timeStamp" yaml:"timeStamp"`
	ShowSource                       bool                                         `json:"showSource" yaml:"showSource"`
	ReusedSecretsCount               int                                          `json:"reusedSecretsCount" yaml:"reusedSecretsCount"`
	NumberOfSecretsReuse             int                                          `json:"numberOfSecretsReuse" yaml:"numberOfSecretsReuse"`
	ReusedSecrets                    map[string][]*diagnostics.SecurityDiagnostic `yaml:"-" json:"-"`
	ProdAndNonProdSecretReuse        []ReusedSecret                               `json:"prodAndNonProdSecretReuse" yaml:"prodAndNonProdSecretReuse"`
	CriticalProdUsedInNonProdCount   int                                          `yaml:"criticalProdUsedInNonProdCount" json:"criticalProdUsedInNonProdCount"`
	HighProdUsedInNonProdCount       int                                          `yaml:"highProdUsedInNonProdCount" json:"highProdUsedInNonProdCount"`
	MediumProdUsedInNonProdCount     int                                          `yaml:"mediumProdUsedInNonProdCount" json:"mediumProdUsedInNonProdCount"`
	LowProdUsedInNonProdCount        int                                          `yaml:"lowProdUsedInNonProdCount" json:"lowProdUsedInNonProdCount"`
	InfoProdUsedInNonProdCount       int                                          `yaml:"infoProdUsedInNonProdCount" json:"infoProdUsedInNonProdCount"`
	CriticalSensitiveFileCount       int                                          `yaml:"criticalSensitiveFileCount" json:"criticalSensitiveFileCount"`
	HighSensitiveFileCount           int                                          `yaml:"highSensitiveFileCount" json:"highSensitiveFileCount"`
	MediumSensitiveFileCount         int                                          `yaml:"mediumSensitiveFileCount" json:"mediumSensitiveFileCount"`
	LowSensitiveFileCount            int                                          `yaml:"lowSensitiveFileCount" json:"lowSensitiveFileCount"`
	InfoSensitiveFileCount           int                                          `yaml:"infoSensitiveFileCount" json:"infoSensitiveFileCount"`
	NonProdSensitiveFileCount        int                                          `yaml:"nonProdSensitiveFileCount" json:"nonProdSensitiveFileCount"`
	SecretReuseCountBuckets          []int                                        `yaml:"secretReuseCountBuckets" json:"secretReuseCountBuckets"`
}

type ModelCounts struct {
	CriticalCount                    int     `json:"criticalCount" yaml:"criticalCount"`
	HighCount                        int     `json:"highCount" yaml:"highCount"`
	MediumCount                      int     `json:"mediumCount" yaml:"mediumCount"`
	LowCount                         int     `json:"lowCount" yaml:"lowCount"`
	InformationalCount               int     `json:"informationalCount" yaml:"informationalCount"`
	ProductionConfidentialFilesCount int     `json:"productionConfidentialFilesCount" yaml:"productionConfidentialFilesCount"`
	FileCount                        int     `json:"fileCount" yaml:"fileCount"`
	SkippedCount                     int     `json:"skippedCount" yaml:"skippedCount"`
	IssuesPerType                    int     `json:"issuesPerType" yaml:"issuesPerType"`
	AveragePerFile                   float32 `json:"averagePerFile" yaml:"averagePerFile"`
	ReusedSecretsCount               int     `json:"reusedSecretsCount" yaml:"reusedSecretsCount"`
	NumberOfSecretsReuse             int     `json:"numberOfSecretsReuse" yaml:"numberOfSecretsReuse"`
	CriticalProdUsedInNonProdCount   int     `yaml:"criticalProdUsedInNonProdCount" json:"criticalProdUsedInNonProdCount"`
	HighProdUsedInNonProdCount       int     `yaml:"highProdUsedInNonProdCount" json:"highProdUsedInNonProdCount"`
	MediumProdUsedInNonProdCount     int     `yaml:"mediumProdUsedInNonProdCount" json:"mediumProdUsedInNonProdCount"`
	LowProdUsedInNonProdCount        int     `yaml:"lowProdUsedInNonProdCount" json:"lowProdUsedInNonProdCount"`
	InfoProdUsedInNonProdCount       int     `yaml:"infoProdUsedInNonProdCount" json:"infoProdUsedInNonProdCount"`
	CriticalSensitiveFileCount       int     `yaml:"criticalSensitiveFileCount" json:"criticalSensitiveFileCount"`
	HighSensitiveFileCount           int     `yaml:"highSensitiveFileCount" json:"highSensitiveFileCount"`
	MediumSensitiveFileCount         int     `yaml:"mediumSensitiveFileCount" json:"mediumSensitiveFileCount"`
	LowSensitiveFileCount            int     `yaml:"lowSensitiveFileCount" json:"lowSensitiveFileCount"`
	InfoSensitiveFileCount           int     `yaml:"infoSensitiveFileCount" json:"infoSensitiveFileCount"`
	NonProdSensitiveFileCount        int     `yaml:"nonProdSensitiveFileCount" json:"nonProdSensitiveFileCount"`
	SecretReuseCountBuckets          []int   `yaml:"secretReuseCountBuckets" json:"secretReuseCountBuckets"`
}

//100% basis metric
func (mc ModelCounts) scoreMetrics() float32 {

	pvt := mc.calculateProductionVsTestSecretReuse()
	sfp := mc.calculateSensitiveFilesPenalty()
	srm := mc.collectSecretsReuseMetrics()
	hcp := mc.calculateHigherConfidencePenalties()

	metrics := 0.3*pvt +
		0.4*sfp + 0.1*srm +
		0.2*hcp

	// log.Printf("metric = %f, prodVsTest = %f, sensitiveFile = %f, secretReuse = %f, higherConfidencePenalty = %f",
	// 	metrics, pvt, sfp, srm, hcp)
	return metrics
}

//penalises the use of sensitive files (e.g. certificates, key stores etc) in non-test (critical = 0%).
//If all instances are in a test context, then a 70% mark is returned instead of 100% max score
func (mc ModelCounts) calculateSensitiveFilesPenalty() (score float32) {

	if mc.CriticalSensitiveFileCount > 0 {
		return 0
	}
	if mc.HighSensitiveFileCount > 0 {
		return 20
	}
	if mc.MediumSensitiveFileCount > 0 {
		return 30
	}
	if mc.LowSensitiveFileCount > 0 {
		return 50
	}
	if mc.InfoSensitiveFileCount > 0 {
		return 60
	}
	if mc.NonProdSensitiveFileCount > 0 {
		return 70
	}

	return 100
}

// tests whether secrets are reused in test vs non-test contexts
// scores zero for critical, and increases through info, 100% score for no reuse
func (mc ModelCounts) calculateProductionVsTestSecretReuse() (score float32) {
	score = 100
	if mc.CriticalProdUsedInNonProdCount > 0 {
		score = capScore(score, 0)
	}
	if mc.HighProdUsedInNonProdCount > 0 {
		score = capScore(score, 20)
	}
	if mc.MediumProdUsedInNonProdCount > 0 {
		score = capScore(score, 40)
	}
	if mc.LowProdUsedInNonProdCount > 0 {
		score = capScore(score, 70)
	}
	if mc.InfoProdUsedInNonProdCount > 0 {
		score = capScore(score, 90)
	}

	return
}

func (mc ModelCounts) calculateHigherConfidencePenalties() float32 {

	score := float32(100)

	if mc.InformationalCount > 0 {
		score = capScore(score, 95)
	}

	if mc.LowCount > 0 {
		score = capScore(score, 90)
	}

	if mc.MediumCount > 0 {
		score = capScore(score, 80)
	}

	if mc.HighCount > 0 {
		score = capScore(score, 70)
	}

	if mc.CriticalCount > 0 {
		score = capScore(score, 40)
	}

	return score
}

//penalise for the number of reuse
func (mc *ModelCounts) collectSecretsReuseMetrics() (score float32) {
	reuseCount := 0
	reuseEntropy := float64(0)
	for _, v := range mc.SecretReuseCountBuckets {
		reuseCount += v
	}

	if reuseCount == 0 {
		return 100
	}

	for _, size := range mc.SecretReuseCountBuckets {
		p := float64(size) / float64(reuseCount)
		reuseEntropy -= p * math.Log2(p)
	}

	// the max "entropy" is log2(reuseCount), we use that to calculate how close the reuse is to the max
	//i.e  100 * reuseEntropy/maxEntropy
	score = float32((100 * reuseEntropy) / math.Log2(float64(reuseCount)))
	// log.Printf("Got reuse score of %f. = 100 * %f * %f / %f\n", score, reuseEntropy, reuseCount, math.Log2(reuseCount))
	return score

}

func GenerateModel(fileCount int, showSource bool, issues []*diagnostics.SecurityDiagnostic) *Model {

	var average float32
	if fileCount > 0 {
		average = float32(len(issues)) / float32(fileCount)
	}
	model := Model{
		FileCount:      fileCount,
		Issues:         issues,
		TimeStamp:      time.Now().UTC().Format(time.RFC1123),
		AveragePerFile: average,
		ShowSource:     showSource,
	}

	sameSha := make(map[string][]*diagnostics.SecurityDiagnostic)

	for _, issue := range issues {
		if issue.SHA256 != nil {
			sha := *issue.SHA256
			if shas, present := sameSha[sha]; present {
				sameSha[sha] = append(shas, issue)
			} else {
				sameSha[sha] = []*diagnostics.SecurityDiagnostic{issue}
			}
		}
		switch issue.Justification.Headline.Confidence {
		case diagnostics.Critical:
			model.CriticalCount++
		case diagnostics.High:
			model.HighCount++
		case diagnostics.Medium:
			model.MediumCount++
		case diagnostics.Low:
			model.LowCount++
		default:
			model.InformationalCount++
		}

		if issue.HasTag("confidential") && !issue.HasTag("test") {
			//production certs and keystores etc.
			model.ProductionConfidentialFilesCount++
		}
	}

	model.ReusedSecrets = sameSha

	count := 0
	numberOfReuse := 0
	for hash := range model.ReusedSecrets {
		cc := len(model.ReusedSecrets[hash])
		if cc > 1 {
			count++
			numberOfReuse += cc
		}
	}
	model.ReusedSecretsCount = count
	model.NumberOfSecretsReuse = numberOfReuse

	///-------

	rus := []ReusedSecret{}
	for k, dd := range model.ReusedSecrets {
		prod := []SecretLocation{}
		dev := []SecretLocation{}
		for _, d := range dd {
			if d.HasTag("test") {
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

	model.ProdAndNonProdSecretReuse = rus

	return &model
}

func (m *Model) computeMetricBases() ModelCounts {

	//side effects
	m.calculateProductionVsTestSecretReuse()
	m.calculateSensitiveFilesPenalty()
	m.collectSecretsReuseMetrics()

	mCounts := ModelCounts{
		CriticalCount:                    m.CriticalCount,
		HighCount:                        m.HighCount,
		MediumCount:                      m.MediumCount,
		LowCount:                         m.LowCount,
		InformationalCount:               m.InformationalCount,
		ProductionConfidentialFilesCount: m.ProductionConfidentialFilesCount,
		FileCount:                        m.FileCount,
		SkippedCount:                     m.SkippedCount,
		IssuesPerType:                    m.IssuesPerType,
		AveragePerFile:                   m.AveragePerFile,
		ReusedSecretsCount:               m.ReusedSecretsCount,
		NumberOfSecretsReuse:             m.NumberOfSecretsReuse,
		CriticalProdUsedInNonProdCount:   m.CriticalProdUsedInNonProdCount,
		HighProdUsedInNonProdCount:       m.HighProdUsedInNonProdCount,
		MediumProdUsedInNonProdCount:     m.MediumProdUsedInNonProdCount,
		LowProdUsedInNonProdCount:        m.LowProdUsedInNonProdCount,
		InfoProdUsedInNonProdCount:       m.InfoProdUsedInNonProdCount,
		CriticalSensitiveFileCount:       m.CriticalSensitiveFileCount,
		HighSensitiveFileCount:           m.HighSensitiveFileCount,
		MediumSensitiveFileCount:         m.MediumSensitiveFileCount,
		LowSensitiveFileCount:            m.LowSensitiveFileCount,
		InfoSensitiveFileCount:           m.InfoSensitiveFileCount,
		NonProdSensitiveFileCount:        m.NonProdSensitiveFileCount,
		SecretReuseCountBuckets:          m.SecretReuseCountBuckets,
	}

	return mCounts
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

	modelCounts := m.computeMetricBases()

	metric := modelCounts.scoreMetrics()
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

// tests whether secrets are reused in test vs non-test contexts
func (m *Model) calculateProductionVsTestSecretReuse() {
	for _, v := range m.ReusedSecrets {
		var prod, test bool
		var cCount, hCount, mCount, lCount, iCount int
		for _, diag := range v {
			if diag.HasTag("test") {
				test = true
			} else {
				prod = true
				switch diag.Justification.Headline.Confidence {
				case diagnostics.Critical:
					cCount++
				case diagnostics.High:
					hCount++
				case diagnostics.Medium:
					mCount++
				case diagnostics.Low:
					lCount++
				case diagnostics.Info:
					iCount++
				}
			}

			//if this cluster of reuse involves BOTH test and non-test secrets, then add the counts
			if test && prod {
				m.CriticalProdUsedInNonProdCount += mCount
				m.HighProdUsedInNonProdCount += hCount
				m.MediumProdUsedInNonProdCount += mCount
				m.LowProdUsedInNonProdCount += lCount
				m.InfoProdUsedInNonProdCount += iCount
			}
		}
	}
}

func (m *Model) calculateSensitiveFilesPenalty() {
	for _, issue := range m.Issues {
		if issue.HasTag("confidential") {
			if !issue.HasTag("test") {
				switch issue.Justification.Headline.Confidence {
				case diagnostics.Critical:
					m.CriticalSensitiveFileCount++
				case diagnostics.High:
					m.HighSensitiveFileCount++
				case diagnostics.Medium:
					m.MediumSensitiveFileCount++
				case diagnostics.Low:
					m.LowSensitiveFileCount++
				case diagnostics.Info:
					m.InfoSensitiveFileCount++
				}
			} else {
				m.NonProdSensitiveFileCount++
			}
		}
	}
}

//penalise for the number of reuse
func (m *Model) collectSecretsReuseMetrics() {
	for _, v := range m.ReusedSecrets {
		m.SecretReuseCountBuckets = append(m.SecretReuseCountBuckets, len(v))
	}
}

func capScore(score, cap float32) float32 {
	if score > cap {
		return cap
	}
	return score
}
