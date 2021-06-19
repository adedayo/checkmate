package main

import (
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
)

func main() {
	if p, err := asciidoc.GenerateReport(false, 0); err != nil {
		println(err.Error())
	} else {
		println(p)
	}
}
