package csvreport

import (
	"encoding/csv"
	"io"
	"os"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

func Generate(reportLocation string, issues []*diagnostics.SecurityDiagnostic) error {

	file, err := os.Create(reportLocation)

	if err != nil {
		return err
	}

	defer file.Close()

	return WriteSecurityDiagnosticCSVReport(file, issues)
}

func WriteSecurityDiagnosticCSVReport(out io.Writer, issues []*diagnostics.SecurityDiagnostic) error {
	writer := csv.NewWriter(out)
	extraHeaders := diagnostics.GetExtraHeaders(issues)
	headers := append((&diagnostics.SecurityDiagnostic{}).CSVHeaders(), extraHeaders...)
	writer.Write(headers)
	for _, issue := range issues {
		writer.Write(issue.CSVValues(extraHeaders...))
	}
	writer.Flush()
	return writer.Error()
}
