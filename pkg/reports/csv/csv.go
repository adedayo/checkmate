package csvreport

import (
	"encoding/csv"
	"io"
	"os"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

func Generate(reportLocation string, issues []*diagnostics.SecurityDiagnostic) error {

	file, err := os.Create(reportLocation)

	if err != nil {
		return err
	}

	defer func() {
		_ = file.Close()
	}()

	return WriteSecurityDiagnosticCSVReport(file, issues)
}

func WriteSecurityDiagnosticCSVReport(out io.Writer, issues []*diagnostics.SecurityDiagnostic) error {
	writer := csv.NewWriter(out)
	extraHeaders := diagnostics.GetExtraHeaders(issues)
	headers := append((&diagnostics.SecurityDiagnostic{}).CSVHeaders(), extraHeaders...)
	_ = writer.Write(headers)
	for _, issue := range issues {
		_ = writer.Write(issue.CSVValues(extraHeaders...))
	}
	writer.Flush()
	return writer.Error()
}
