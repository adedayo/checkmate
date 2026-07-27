package main

import (
	"github.com/adedayo/checkmate/pkg/reports/pdf"
)

func main() {
	if p, err := pdf.GenerateReport("", false, 0); err != nil {
		println(err.Error())
	} else {
		println(p)
	}
}

