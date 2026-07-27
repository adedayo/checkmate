package pdf

import (
	"bytes"

	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// GenerateSeverityChart generates a bar chart reflecting the severities distribution
func GenerateSeverityChart(critical, high, medium, low int) ([]byte, error) {
	var bars []chart.Value
	if critical > 0 {
		bars = append(bars, chart.Value{
			Value: float64(critical),
			Label: "Critical",
			Style: chart.Style{
				FillColor:   drawing.Color{R: 147, G: 51, B: 234, A: 255}, // Purple
				StrokeColor: drawing.ColorTransparent,
			},
		})
	}
	if high > 0 {
		bars = append(bars, chart.Value{
			Value: float64(high),
			Label: "High",
			Style: chart.Style{
				FillColor:   drawing.Color{R: 239, G: 68, B: 68, A: 255}, // Red
				StrokeColor: drawing.ColorTransparent,
			},
		})
	}
	if medium > 0 {
		bars = append(bars, chart.Value{
			Value: float64(medium),
			Label: "Medium",
			Style: chart.Style{
				FillColor:   drawing.Color{R: 245, G: 158, B: 11, A: 255}, // Orange
				StrokeColor: drawing.ColorTransparent,
			},
		})
	}
	if low > 0 {
		bars = append(bars, chart.Value{
			Value: float64(low),
			Label: "Low/Info",
			Style: chart.Style{
				FillColor:   drawing.Color{R: 59, G: 130, B: 246, A: 255}, // Blue
				StrokeColor: drawing.ColorTransparent,
			},
		})
	}

	if len(bars) == 0 {
		// No issues
		bars = append(bars, chart.Value{
			Value: 1,
			Label: "Clean",
			Style: chart.Style{
				FillColor:   drawing.Color{R: 34, G: 197, B: 94, A: 255}, // Green
				StrokeColor: drawing.ColorTransparent,
			},
		})
	}

	barChart := chart.BarChart{
		Width:  512,
		Height: 300,
		Bars:   bars,
		Background: chart.Style{
			Padding: chart.Box{Top: 20, Left: 20, Right: 20, Bottom: 20},
		},
	}

	var buffer bytes.Buffer
	err := barChart.Render(chart.PNG, &buffer)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
