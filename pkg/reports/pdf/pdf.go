package pdf

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/page"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/breakline"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// GenerateReport creates an elegant PDF report natively using Maroto v2 (zero external dependencies).
func GenerateReport(outputDir string, showSource bool, fileCount int, issues ...*diagnostics.SecurityDiagnostic) (string, error) {
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithRightMargin(15).
		WithTopMargin(15).
		WithBottomMargin(15).
		Build()

	m := maroto.New(cfg)

	// Colors
	navyColor := &props.Color{Red: 15, Green: 23, Blue: 42}
	slateColor := &props.Color{Red: 100, Green: 116, Blue: 139}
	lightBg := &props.Color{Red: 248, Green: 250, Blue: 252}

	criticalColor := &props.Color{Red: 147, Green: 51, Blue: 234}
	highColor := &props.Color{Red: 239, Green: 68, Blue: 68}
	mediumColor := &props.Color{Red: 245, Green: 158, Blue: 11}
	lowColor := &props.Color{Red: 59, Green: 130, Blue: 246}

	// Sort issues by criticality
	sort.Slice(issues, func(i, j int) bool {
		return getSeverityWeight(issues[i]) > getSeverityWeight(issues[j])
	})

	// Summary metrics calculation
	model := projects.GenerateModel(fileCount, showSource, issues)
	model.Summarise()

	// --- 1. COVER PAGE ---
	m.AddRow(40, col.New(12)) // Spacer

	m.AddRow(30, col.New(12).Add(
		text.New("CheckMate Security Audit", props.Text{
			Size:  28,
			Style: fontstyle.Bold,
			Align: align.Center,
			Color: navyColor,
		}),
	))

	m.AddRow(60, col.New(12).Add(
		image.NewFromBytes(logoBytes, "png", props.Rect{
			Center:  true,
			Percent: 100,
		}),
	))

	m.AddRow(20, col.New(12).Add(
		text.New("Hard-coded Secrets Diagnostics & Posture", props.Text{
			Size:  14,
			Align: align.Center,
			Color: slateColor,
		}),
	))

	m.AddRow(40, col.New(12)) // Spacer

	m.AddRow(10, col.New(12).Add(
		text.New(fmt.Sprintf("Generated: %s", time.Now().Format("January 02, 2006 at 15:04")), props.Text{
			Size:  12,
			Align: align.Center,
			Color: slateColor,
		}),
	))
	m.AddRow(10, col.New(12).Add(
		text.New(fmt.Sprintf("Scanned Files: %d", fileCount), props.Text{
			Size:  12,
			Align: align.Center,
			Color: slateColor,
		}),
	))

	// Push next content to a new page
	m.AddPages(page.New())

	// --- 2. EXECUTIVE SUMMARY & CHART ---

	// Header Line
	m.AddRow(14, col.New(12).Add(
		text.New("1. Executive Summary", props.Text{
			Size:  16,
			Style: fontstyle.Bold,
			Color: navyColor,
		}),
	))
	m.AddRow(4, col.New(12).Add(line.New(props.Line{Color: slateColor, Thickness: 0.5})))
	m.AddRow(6, col.New(12)) // Spacer

	m.AddRow(12, col.New(12).Add(
		text.New(fmt.Sprintf("Overall Grade: %s", model.Grade), props.Text{
			Size:  16,
			Style: fontstyle.Bold,
			Color: criticalColor,
		}),
	))

	m.AddRow(20, col.New(12).Add(
		text.New("The grading system penalizes codebase risks based on severity, context (production vs test secret usage), secret reuse frequency, and the presence of highly sensitive files. A grade of 'A' indicates a clean state, while lower grades highlight escalating credential management risks.", props.Text{
			Size:  9,
			Style: fontstyle.Italic,
			Color: slateColor,
		}),
	))

	m.AddRow(10, col.New(12)) // Spacer

	// Add Chart
	chartBytes, errChart := GenerateSeverityChart(model.CriticalCount, model.HighCount, model.MediumCount, model.LowCount+model.InformationalCount)
	if errChart == nil && chartBytes != nil {
		m.AddRow(80, col.New(12).Add(
			image.NewFromBytes(chartBytes, "png", props.Rect{
				Center:  true,
				Percent: 100,
			}),
		))
	} else {
		m.AddRow(12, col.New(12).Add(
			text.New(fmt.Sprintf("Failed to generate chart: %v", errChart), props.Text{
				Size:  10,
				Color: highColor,
			}),
		))
	}

	m.AddRow(20, col.New(12)) // Spacer

	// --- 3. METRICS SECTION ---
	m.AddRow(14, col.New(12).Add(
		text.New("1.1 Metrics about your codebase", props.Text{
			Size:  14,
			Style: fontstyle.Bold,
			Color: navyColor,
		}),
	))
	m.AddRow(8, col.New(12).Add(
		text.New("The following is a summary of metrics calculated during the security audit of your codebase:", props.Text{
			Size:  10,
			Color: slateColor,
		}),
	))
	m.AddRow(4, col.New(12).Add(line.New(props.Line{Color: slateColor, Thickness: 0.5})))
	m.AddRow(4, col.New(12))

	addMetricRow := func(name string, value int) {
		m.AddRow(10,
			col.New(8).Add(text.New(name, props.Text{Size: 10, Style: fontstyle.Bold, Color: navyColor})),
			col.New(4).Add(text.New(fmt.Sprintf("%d", value), props.Text{Size: 10, Color: slateColor})),
		)
		m.AddRow(2, col.New(12).Add(line.New(props.Line{Color: lightBg, Thickness: 0.2})))
	}

	addMetricRow("Total number of issues", len(issues))
	addMetricRow("Total number of Critical Issues", model.CriticalCount)
	addMetricRow("Total number of High Issues", model.HighCount)
	addMetricRow("Total number of Medium Issues", model.MediumCount)
	addMetricRow("Total number of Low Issues", model.LowCount)
	addMetricRow("Total number of Informational Issues", model.InformationalCount)
	addMetricRow("No of files processed", model.FileCount)
	addMetricRow("Production Secrets Count", model.ProductionSecretsCount)
	addMetricRow("Number of secrets reused", model.NumberOfSecretsReuse)
	addMetricRow("Production Confidential Files Count", model.ProductionConfidentialFilesCount)

	if model.FileCount > 0 {
		avg := float64(len(issues)) / float64(model.FileCount)
		m.AddRow(10,
			col.New(8).Add(text.New("Average number of issues per file", props.Text{Size: 10, Style: fontstyle.Bold, Color: navyColor})),
			col.New(4).Add(text.New(fmt.Sprintf("%.2f", avg), props.Text{Size: 10, Color: slateColor})),
		)
		m.AddRow(2, col.New(12).Add(line.New(props.Line{Color: lightBg, Thickness: 0.2})))
	}

	m.AddRow(20, col.New(12))

	// Force page break before detailed findings
	m.AddPages(page.New())

	// --- 4. FINDINGS DETAILS ---
	if len(issues) == 0 {
		m.AddRow(16, col.New(12).Add(
			text.New("No hard-coded secrets or sensitive credentials detected. Excellent job!", props.Text{
				Size:  12,
				Style: fontstyle.Italic,
				Color: slateColor,
			}),
		))
	} else {
		m.AddRow(18, col.New(12).Add(
			text.New(fmt.Sprintf("2. Detailed Findings (%d Issues)", len(issues)), props.Text{
				Size:  14,
				Style: fontstyle.Bold,
				Color: navyColor,
			}),
		))
		
		// Table Header
		m.AddRow(12,
			col.New(1).Add(text.New("#", props.Text{Style: fontstyle.Bold, Color: navyColor, Size: 10})),
			col.New(2).Add(text.New("Severity", props.Text{Style: fontstyle.Bold, Color: navyColor, Size: 10})),
			col.New(2).Add(text.New("Reason", props.Text{Style: fontstyle.Bold, Color: navyColor, Size: 10})),
			col.New(1), // Spacer
			col.New(3).Add(text.New("Location", props.Text{Style: fontstyle.Bold, Color: navyColor, Size: 10})),
			col.New(3).Add(text.New("Evidence", props.Text{Style: fontstyle.Bold, Color: navyColor, Size: 10})),
		)
		m.AddRow(4, col.New(12).Add(line.New(props.Line{Color: slateColor, Thickness: 0.5})))
		m.AddRow(4, col.New(12))

		for i, issue := range issues {
			sevText := fmt.Sprintf("%v", issue.Justification.Headline.Confidence)
			sevColor := lowColor
			switch strings.ToUpper(sevText) {
			case "CRITICAL":
				sevColor = criticalColor
			case "HIGH":
				sevColor = highColor
			case "MEDIUM":
				sevColor = mediumColor
			}

			reasonText := "Secret Detected"
			if issue.Justification.Headline.Description != "" {
				reasonText = issue.Justification.Headline.Description
			}

			locationPath := "Unknown location"
			if issue.Location != nil && *issue.Location != "" {
				locationPath = formatLocation(*issue.Location)
			}
			if issue.Range.Start.Line > 0 {
				locationPath = fmt.Sprintf("%s:%d", locationPath, issue.Range.Start.Line)
			}

			snippetText := ""
			if showSource && issue.Source != nil && len(*issue.Source) > 0 {
				snippetText = redactSecret(*issue.Source)
			} else {
				snippetText = "N/A"
			}

			// AddAutoRow handles multi-line content gracefully
			m.AddAutoRow(
				col.New(1).Add(text.New(fmt.Sprintf("%d", i+1), props.Text{Size: 9, Color: slateColor})),
				col.New(2).Add(text.New(strings.ToUpper(sevText), props.Text{Style: fontstyle.Bold, Color: sevColor, Size: 9})),
				col.New(2).Add(text.New(reasonText, props.Text{Size: 9, Color: navyColor})),
				col.New(1), // Spacer
				col.New(3).Add(text.New(locationPath, props.Text{Size: 9, Style: fontstyle.Italic, Color: slateColor, BreakLineStrategy: breakline.DashStrategy})),
				col.New(3).Add(text.New(snippetText, props.Text{Size: 9, Color: navyColor})),
			)
			m.AddRow(4, col.New(12).Add(line.New(props.Line{Color: lightBg, Thickness: 0.2})))
		}
	}

	// Output Destination
	if outputDir == "" {
		outputDir = "."
	}

	outputPath := filepath.Join(outputDir, fmt.Sprintf("checkmate-report-%d.pdf", time.Now().Unix()))
	document, err := m.Generate()
	if err != nil {
		return "", fmt.Errorf("failed to generate PDF document: %w", err)
	}

	err = os.WriteFile(outputPath, document.GetBytes(), 0644)
	if err != nil {
		outputPath = fmt.Sprintf("checkmate-report-%d.pdf", time.Now().Unix())
		if errWrite := os.WriteFile(outputPath, document.GetBytes(), 0644); errWrite != nil {
			return "", fmt.Errorf("failed to write PDF report to disk: %w", errWrite)
		}
	}

	absPath, _ := filepath.Abs(outputPath)
	return absPath, nil
}

func getSeverityWeight(issue *diagnostics.SecurityDiagnostic) int {
	if issue == nil {
		return 0
	}
	sevText := fmt.Sprintf("%v", issue.Justification.Headline.Confidence)
	switch strings.ToUpper(sevText) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW", "INFO":
		return 1
	}
	return 0
}

func formatLocation(loc string) string {
	maxLen := 50
	if len(loc) <= maxLen {
		return loc
	}
	parts := strings.Split(filepath.ToSlash(loc), "/")
	if len(parts) <= 4 {
		half := (maxLen - 3) / 2
		return loc[:half] + "..." + loc[len(loc)-half:]
	}
	
	first := parts[0] + "/" + parts[1]
	last := parts[len(parts)-2] + "/" + parts[len(parts)-1]
	res := first + "/.../" + last
	if len(res) > maxLen {
		half := (maxLen - 3) / 2
		return res[:half] + "..." + res[len(res)-half:]
	}
	return res
}

func redactSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return "***REDACTED***"
	}
	
	// Keep a few characters at the start and end to provide context 
	// (e.g. `password="***"`) without revealing the actual string.
	// We'll mask out 60% of the middle of the string.
	maskLen := int(float64(len(s)) * 0.6)
	if maskLen < 4 {
		maskLen = 4
	}
	
	sideLen := (len(s) - maskLen) / 2
	if sideLen < 0 {
		sideLen = 0
	}
	
	redacted := s[:sideLen] + strings.Repeat("*", maskLen)
	if sideLen+maskLen < len(s) {
		redacted += s[sideLen+maskLen:]
	}
	return redacted
}
