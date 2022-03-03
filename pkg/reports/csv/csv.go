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
	writer.Write((&diagnostics.SecurityDiagnostic{}).CSVHeaders())
	for _, issue := range issues {
		writer.Write(issue.CSVValues())
	}
	writer.Flush()
	return writer.Error()
}
