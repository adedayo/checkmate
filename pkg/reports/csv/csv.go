package csvreport

import (
	"encoding/csv"
	"os"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

func Generate(reportLocation string, issues []*diagnostics.SecurityDiagnostic) (err error) {

	file, err := os.Create(reportLocation)

	if err != nil {
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write((&diagnostics.SecurityDiagnostic{}).CSVHeaders())
	for _, issue := range issues {
		writer.Write(issue.CSVValues())
	}
	writer.Flush()

	return
}
