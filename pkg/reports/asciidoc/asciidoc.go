package asciidoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate/pkg/assets"
	report "github.com/adedayo/checkmate/pkg/reports/model"
	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

var (
	asciidocExec = func() string {
		executable := "asciidoctor-pdf"
		switch runtime.GOOS {
		case "windows":
			return fmt.Sprintf("%s", executable)
		default:
			return executable
		}
	}()

	funcMap = template.FuncMap{
		"computeLanguage":     computeLanguage,
		"translateConfidence": translateConfidence,
		"increment":           increment,
		"deref":               deref,
	}

	rgbaFix   = regexp.MustCompile(`rgba\((\d+,\d+,\d+),1.0\)`)
	highStyle = chart.Style{
		FillColor:   drawing.ColorRed,
		StrokeColor: drawing.ColorRed,
		StrokeWidth: 0,
	}
	medStyle = chart.Style{
		FillColor:   drawing.ColorFromHex("ffbf00"), //Amber
		StrokeColor: drawing.ColorFromHex("ffbf00"),
		StrokeWidth: 0,
	}
	infoStyle = chart.Style{
		FillColor:   drawing.ColorGreen,
		StrokeColor: drawing.ColorGreen,
		StrokeWidth: 0,
	}
	lowStyle = chart.Style{
		FillColor:   drawing.ColorBlue,
		StrokeColor: drawing.ColorBlue,
		StrokeWidth: 0,
		FontColor:   drawing.ColorWhite,
	}
	invisibleStyle = chart.Style{
		FillColor:   drawing.ColorWhite,
		StrokeColor: drawing.ColorWhite,
		StrokeWidth: 0,
	}
)

//GenerateReport generates PDF report using asciidoc-pdf, if not found, returns the JSON-formatted results in the reportPath
func GenerateReport(showSource bool, fileCount int, issues ...*diagnostics.SecurityDiagnostic) (reportPath string, err error) {
	asciidocPath, err := exec.LookPath(asciidocExec)
	if err != nil {
		issuesJSON, e := json.MarshalIndent(issues, "", " ")
		error2 := ""
		if e != nil {
			error2 = fmt.Sprintf("\n%s", e.Error())
		} else {
			reportPath = fmt.Sprintf("\n\nPrinting JSON instead\n\n%s", string(issuesJSON))
		}
		return reportPath, fmt.Errorf("%s executable file not found in your $PATH. Install it and ensure that it is in your $PATH%s", asciidocExec, error2)
	}
	model, err := ComputeMetrics(fileCount, showSource, issues)
	if err != nil {
		return reportPath, err
	}
	return generateReportFromModel(model, asciidocPath)
}

func generateReportFromModel(model report.Model, asciidocPath string) (reportPath string, err error) {

	t, err := template.New("").Funcs(funcMap).Parse(assets.Report)
	if err != nil {
		return reportPath, err
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, model)
	if err != nil {
		return reportPath, err
	}

	aDoc, err := generateFile(buf.Bytes(), "report*.adoc")
	if err != nil {
		return reportPath, err
	}

	cmd := exec.Command(asciidocPath, aDoc)
	reportPath = strings.Replace(aDoc, ".adoc", ".pdf", -1)
	log.Printf("Generating report at %s\n", reportPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return reportPath, fmt.Errorf("%s%s", string(out), err.Error())
	}
	cleanAssets(model, aDoc)
	return
}

func ComputeMetrics(fileCount int, showSource bool, issues []*diagnostics.SecurityDiagnostic) (report.Model, error) {

	var average float32
	if fileCount > 0 {
		average = float32(len(issues)) / float32(fileCount)
	}
	model := report.Model{
		HighCount:      0,
		MediumCount:    0,
		LowCount:       0,
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
		case diagnostics.High:
			model.HighCount++
		case diagnostics.Medium:
			model.MediumCount++
		case diagnostics.Low:
			model.LowCount++
		default:
			model.InformationalCount++

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

	barWidth := 20
	issueCount := float64(model.HighCount + model.MediumCount + model.LowCount + model.InformationalCount)
	highPercent := 0.0
	mediumPercent := 0.0
	lowPercent := 0.0
	infoPercent := 0.0
	if issueCount > 0 {
		highPercent = 100.0 * float64(model.HighCount) / issueCount
		mediumPercent = 100.0 * float64(model.MediumCount) / issueCount
		lowPercent = 100.0 * float64(model.LowCount) / issueCount
		infoPercent = 100.0 * float64(model.InformationalCount) / issueCount
	}

	graph := chart.StackedBarChart{
		Width:        512,
		Height:       512,
		BarSpacing:   15,
		IsHorizontal: true,
		// Background: chart.Style{
		// 	Padding: chart.Box{
		// 		Top: 40,
		// 	},
		// },
		YAxis: chart.Style{
			TextHorizontalAlign: chart.TextHorizontalAlignRight,
		},
		XAxis: chart.Shown(),
		Bars: []chart.StackedBar{
			{
				Name:  "High",
				Width: barWidth,
				Values: []chart.Value{
					{
						Value: 100.0 - highPercent,
						Style: invisibleStyle,
					},
					{
						Value: highPercent,
						Label: fmt.Sprintf("%d", model.HighCount),
						Style: highStyle,
					},
				},
			},
			{
				Name:  "Medium",
				Width: barWidth,
				Values: []chart.Value{
					{
						Value: 100.0 - mediumPercent,
						Style: invisibleStyle,
					},
					{
						Value: mediumPercent,
						Label: fmt.Sprintf("%d", model.MediumCount),
						Style: medStyle,
					},
				},
			},
			{
				Name:  "Low",
				Width: barWidth,
				Values: []chart.Value{
					{
						Value: 100.0 - lowPercent,
						Style: invisibleStyle,
					},
					{
						Value: lowPercent,
						Label: fmt.Sprintf("%d", model.LowCount),
						Style: lowStyle,
					},
				},
			},
			{
				Name:  "Informational",
				Width: barWidth,
				Values: []chart.Value{
					{
						Value: 100.0 - infoPercent,
						Style: invisibleStyle,
					},
					{
						Value: infoPercent,
						Label: fmt.Sprintf("%d", model.InformationalCount),
						Style: infoStyle,
					},
				},
			},
		},
	}

	buffer := bytes.NewBuffer([]byte{})
	_ = graph.Render(chart.SVG, buffer)
	// grade := calculateGrade(highPercent, lowPercent, mediumPercent, infoPercent)
	//calculate grade
	model.Summarise()
	grade := model.Grade
	data, err := generateAssets(grade, fixSVGColour(buffer.String()))

	if err != nil {
		return report.Model{}, fmt.Errorf("problem generating assets: %s", err.Error())
	}

	// model.Grade = grade
	model.GradeLogo = data.grade
	model.Logo = data.checkMateLogo
	model.SALLogo = data.salLogo
	model.Chart = data.charts[0]

	return model, nil
}

func cleanAssets(assets report.Model, aDoc string) {
	_ = os.Remove(assets.Logo)
	_ = os.Remove(assets.SALLogo)
	_ = os.Remove(assets.Chart)
	_ = os.Remove(aDoc)
}

//Some rough and dirty grading
// func calculateGrade(high, med, low, info float64) string {
// 	grade := "A+"

// 	if high == 0.0 && med == 0.0 && low == 0.0 && info == 0.0 {
// 		return grade
// 	}

// 	if high == 0.0 && med == 0.0 && low == 0.0 && info > 0.0 {
// 		return "A"
// 	}

// 	if high == 0.0 && med == 0.0 && low > 0.0 {
// 		return "B"
// 	}

// 	if high == 0.0 && med > 0 {
// 		return "C"
// 	}

// 	if high > 0.0 {

// 		if high > 20.0 {
// 			return "F"
// 		}
// 		return "D"
// 	}
// 	return grade
// }

func fixSVGColour(svg string) string {
	return rgbaFix.ReplaceAllString(svg, "rgb($1)")
}

type assetFiles struct {
	checkMateLogo, salLogo, grade string
	charts                        []string
}

func generateAssets(grade string, charts ...string) (assetFiles, error) {
	files := []string{}
	cleanUp := func() {
		for _, file := range files {
			os.Remove(file)
		}
	}

	var axs assetFiles
	var gradeIcon string
	grade = strings.ToUpper(strings.TrimSpace(grade))
	if len(grade) == 1 {
		gradeIcon = fmt.Sprintf(assets.Grade, colourGrade(grade), grade)
	} else {
		gradeIcon = fmt.Sprintf(assets.Grade2, colourGrade(grade), grade)
	}
	grade, err := generateFile([]byte(gradeIcon), "sal_grade.*.svg")
	files = append(files, grade)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.grade = grade

	logo, err := generateFile([]byte(assets.Logo), "checkmate_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.checkMateLogo = logo

	logo, err = generateFile([]byte(assets.SALLogo), "sal_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.salLogo = logo

	for _, c := range charts {
		chart, err := generateFile([]byte(c), "chart.*.svg")
		files = append(files, chart)
		if err != nil {
			cleanUp()
			return axs, err
		}
		axs.charts = append(axs.charts, chart)
	}

	return axs, nil

}

func colourGrade(grade string) string {
	switch grade {
	case "A", "A+":
		return "green"
	case "B", "B+", "C":
		return "gold"
	default:
		return "red"
	}
}

func generateFile(data []byte, nameGlob string) (fileName string, err error) {
	file, err := ioutil.TempFile("", nameGlob)
	if err != nil {
		return
	}

	if _, err = file.Write(data); err != nil {
		file.Close()
		return
	}

	if err = file.Close(); err != nil {
		return
	}

	return file.Name(), nil
}

//see https://github.com/rouge-ruby/rouge/wiki/List-of-supported-languages-and-lexers
func computeLanguage(file string) string {
	ext := path.Ext(strings.ToLower(file))
	switch ext {
	case ".java", ".scala":
		return "java"
	case ".go":
		return "go"
	case ".rb", ".erb":
		return "ruby"
	case ".js":
		return "javascript"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".xml":
		return "xml"
	case ".html", ".htm":
		return "html"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}

func increment(i int64) int64 {
	return i + 1
}

func deref(s *string) string {
	return *s
}

func translateConfidence(conf diagnostics.Confidence) string {
	switch conf {
	case diagnostics.High:
		return "CAUTION:"
	case diagnostics.Medium:
		return "IMPORTANT:"
	case diagnostics.Low:
		return "WARNING:"
	default:
		return ""
	}
}
