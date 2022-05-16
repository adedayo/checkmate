package asciidoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"text/template"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate/pkg/assets"
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

	rgbaFix       = regexp.MustCompile(`rgba\((\d+,\d+,\d+),1.0\)`)
	criticalStyle = chart.Style{
		FillColor:   drawing.ColorFromHex("660099"), //Purple
		StrokeColor: drawing.ColorFromHex("660099"),
		StrokeWidth: 0,
	}
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

//Thank you https://blog.haroldadmin.com/finding-right-path/ for the solution
//https://github.com/haroldadmin/pathfix
func fixPath() {
	// Find the default shell
	defaultShell := os.Getenv("SHELL")
	// Prepare command to get all environment variables
	// eg. /bin/bash -ilc env
	envCommand := exec.Command(defaultShell, "-ilc", "env")
	allEnvVars, _ := envCommand.Output()

	// Find the PATH variable
	for _, envVar := range strings.Split(string(allEnvVars), "\n") {
		if strings.HasPrefix(envVar, "PATH") {
			currentPath := os.Getenv("PATH")
			// Append retrieved PATH to existing value, to get the complete PATH
			completePath := currentPath + string(os.PathListSeparator) + envVar
			// Set the current process's PATH to the complete PATH
			os.Setenv("PATH", completePath)
			return
		}
	}
}

//GenerateReport generates PDF report using asciidoc-pdf, if not found, returns the JSON-formatted results in the reportPath
func GenerateReport(baseDir string, showSource bool, fileCount int, issues ...*diagnostics.SecurityDiagnostic) (reportPath string, err error) {
	fixPath()
	asciidocPath, err := exec.LookPath(asciidocExec)
	if err != nil {
		issuesJSON, e := json.MarshalIndent(issues, "", " ")
		error2 := ""
		if e != nil {
			error2 = fmt.Sprintf("\n%s", e.Error())
		} else {
			reportPath = fmt.Sprintf("\n\nPrinting JSON instead\n\n%s", string(issuesJSON))
		}
		return reportPath, fmt.Errorf("%s executable file not found in your $PATH. Install it and ensure that it is in your $PATH:%s", asciidocExec, error2)
	}
	model, err := ComputeMetrics(baseDir, fileCount, showSource, issues)
	if err != nil {
		return reportPath, err
	}
	return generateReportFromModel(baseDir, model, asciidocPath)
}

func generateReportFromModel(baseDir string, model *projects.Model, asciidocPath string) (reportPath string, err error) {

	t, err := template.New("").Funcs(funcMap).Parse(assets.Report)
	if err != nil {
		return reportPath, err
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, model)
	if err != nil {
		return reportPath, err
	}

	aDoc, err := generateFile(baseDir, buf.Bytes(), "report*.adoc")
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

func ComputeMetrics(baseDir string, fileCount int, showSource bool, issues []*diagnostics.SecurityDiagnostic) (*projects.Model, error) {

	model := projects.GenerateModel(fileCount, showSource, issues)
	//calculate grade
	model.Summarise()
	barWidth := 20
	issueCount := float64(model.CriticalCount + model.HighCount + model.MediumCount + model.LowCount + model.InformationalCount)

	criticalPercent := 0.0
	highPercent := 0.0
	mediumPercent := 0.0
	lowPercent := 0.0
	infoPercent := 0.0
	if issueCount > 0 {
		criticalPercent = 100.0 * float64(model.CriticalCount) / issueCount
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
				Name:  "Critical",
				Width: barWidth,
				Values: []chart.Value{
					{
						Value: 100.0 - criticalPercent,
						Style: invisibleStyle,
					},
					{
						Value: criticalPercent,
						Label: fmt.Sprintf("%d", model.CriticalCount),
						Style: criticalStyle,
					},
				},
			},
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

	grade := model.Grade
	data, err := generateAssets(baseDir, grade, fixSVGColour(buffer.String()))

	if err != nil {
		return &projects.Model{}, fmt.Errorf("problem generating assets: %s", err.Error())
	}

	model.GradeLogo = data.grade
	model.Logo = data.checkMateLogo
	model.SALLogo = data.salLogo
	model.Chart = data.charts[0]

	return model, nil
}

func cleanAssets(assets *projects.Model, aDoc string) {
	_ = os.Remove(assets.Logo)
	_ = os.Remove(assets.SALLogo)
	_ = os.Remove(assets.Chart)
	_ = os.Remove(aDoc)
}

func fixSVGColour(svg string) string {
	return rgbaFix.ReplaceAllString(svg, "rgb($1)")
}

type assetFiles struct {
	checkMateLogo, salLogo, grade string
	charts                        []string
}

func generateAssets(baseDir, grade string, charts ...string) (assetFiles, error) {
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
	grade, err := generateFile(baseDir, []byte(gradeIcon), "sal_grade.*.svg")
	files = append(files, grade)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.grade = grade

	logo, err := generateFile(baseDir, []byte(assets.Logo), "checkmate_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.checkMateLogo = logo

	logo, err = generateFile(baseDir, []byte(assets.SALLogo), "sal_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.salLogo = logo

	for _, c := range charts {
		chart, err := generateFile(baseDir, []byte(c), "chart.*.svg")
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

func generateFile(baseDir string, data []byte, nameGlob string) (fileName string, err error) {
	file, err := os.CreateTemp(baseDir, nameGlob)
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
	case diagnostics.High, diagnostics.Critical:
		return "CAUTION:"
	case diagnostics.Medium:
		return "IMPORTANT:"
	case diagnostics.Low, diagnostics.Info:
		return "WARNING:"
	default:
		return ""
	}
}
