package main

import (
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
)

func main() {
	if p, err := asciidoc.GenerateReport(secrets.SecretSearchOptions{}, []string{}); err != nil {
		println(err.Error())
	} else {
		println(p)
	}
}
