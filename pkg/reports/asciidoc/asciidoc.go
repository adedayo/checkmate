package asciidoc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/adedayo/checkmate/pkg/assets"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	report "github.com/adedayo/checkmate/pkg/reports/model"
	"github.com/wcharczuk/go-chart"
)

var (
	asciidocExec = func() string {
		executable := "asciidoctor-pdf"
		switch runtime.GOOS {
		case "windows":
			return fmt.Sprintf("%s.exe", executable)
		default:
			return executable
		}
	}()

	funcMap = template.FuncMap{
		"computeLanguage":     computeLanguage,
		"translateConfidence": translateConfidence,
	}

	rgbaFix = regexp.MustCompile(`rgba\((\d+,\d+,\d+),1.0\)`)
)

//GenerateReport x
func GenerateReport(paths []string, issues ...diagnostics.SecurityDiagnostic) (reportPath string, err error) {
	asciidocPath, err := exec.LookPath(asciidocExec)
	if err != nil {
		return reportPath, fmt.Errorf("%s executable file not found in your $PATH. Install it and ensure that it is in your $PATH", asciidocExec)
	}

	graph := chart.DonutChart{
		Width:  512,
		Height: 512,
		Values: []chart.Value{
			{Value: 5, Label: "Blue"},
			{Value: 5, Label: "Green"},
			{Value: 4, Label: "Gray"},
			{Value: 4, Label: "Orange"},
			{Value: 3, Label: "Deep Blue"},
			{Value: 3, Label: "test"},
		},
	}

	buffer := bytes.NewBuffer([]byte{})
	_ = graph.Render(chart.SVG, buffer)

	cc := buffer.String()
	ccFix := rgbaFix.ReplaceAllString(cc, "rgb($1)")

	println("Before: ", cc)
	println("After: ", ccFix)

	data, err := generateAssets(ccFix)
	
	if err != nil {
		return reportPath, fmt.Errorf("Problem generating assets: %s", err.Error())
	}
	// is := []diagnostics.SecurityDiagnostic{}
	model := report.ReportModel{
		Logo:        data.checkMateLogo,
		SALLogo:     data.salLogo,
		Grade:       "A+",
		Chart:       data.charts[0],
		HighCount:   0,
		MediumCount: 0,
		LowCount:    0,
		FileCount:   len(paths),
		Issues:      issues,
		TimeStamp:   time.Now().UTC().Format(time.RFC1123),
	}

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
	if out, err := cmd.CombinedOutput(); err != nil {
		return reportPath, fmt.Errorf("%s%s", string(out), err.Error())
	}
	return
}

type assetFiles struct {
	checkMateLogo, salLogo string
	charts                 []string
}

func generateAssets(charts ...string) (assetFiles, error) {
	files := []string{}
	cleanUp := func() {
		for _, file := range files {
			os.Remove(file)
		}
	}
	var axs assetFiles
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
