package diagnostics

import (
	"testing"

	"github.com/adedayo/checkmate/pkg/core/code"
)

func TestSubsumeOverlapping_ConfidenceDominance(t *testing.T) {
	filePath := "config/settings.py"
	src1 := `pwd = "b7g7gw9bcbuiwdihbicyvuydvjcvce22cd"`
	src2 := `"b7g7gw9bcbuiwdihbicyvuydvjcvce22cd"`

	// Scanner A: High Confidence
	diagA := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{
				Description: "Hardcoded Password Assignment",
				Confidence:  High,
			},
		},
		Source: &src1,
		Range: code.Range{
			Start: code.Position{Line: 10, Character: 0},
			End:   code.Position{Line: 10, Character: 41},
		},
		RawRange: CharRange{StartIndex: 100, EndIndex: 141},
	}

	// Scanner B: Low Confidence
	diagB := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{
				Description: "High Entropy String",
				Confidence:  Low,
			},
		},
		Source: &src2,
		Range: code.Range{
			Start: code.Position{Line: 10, Character: 6},
			End:   code.Position{Line: 10, Character: 40},
		},
		RawRange: CharRange{StartIndex: 106, EndIndex: 140},
	}

	input := []*SecurityDiagnostic{diagB, diagA}
	result := SubsumeOverlapping(input)

	if len(result) != 1 {
		t.Fatalf("Expected 1 subsumed diagnostic, got %d", len(result))
	}

	if result[0].Justification.Headline.Confidence != High {
		t.Errorf("Expected High confidence finding to win, got %v", result[0].Justification.Headline.Confidence)
	}

	if *result[0].Source != src1 {
		t.Errorf("Expected complete source snippet to be preserved, got %s", *result[0].Source)
	}
}

func TestSubsumeOverlapping_CompletenessDominance(t *testing.T) {
	filePath := "src/main.go"
	srcFull := `apiKey := "AKIAIOSFODNN7EXAMPLE"`
	srcPart := `"AKIAIOSFODNN7EXAMPLE"`

	// Both Medium Confidence
	diagA := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{
				Description: "AWS Key Assignment",
				Confidence:  Medium,
			},
		},
		Source: &srcFull,
		Range: code.Range{
			Start: code.Position{Line: 5, Character: 0},
			End:   code.Position{Line: 5, Character: 31},
		},
		RawRange: CharRange{StartIndex: 50, EndIndex: 81},
	}

	diagB := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{
				Description: "AWS Access Key",
				Confidence:  Medium,
			},
		},
		Source: &srcPart,
		Range: code.Range{
			Start: code.Position{Line: 5, Character: 10},
			End:   code.Position{Line: 5, Character: 30},
		},
		RawRange: CharRange{StartIndex: 60, EndIndex: 80},
	}

	input := []*SecurityDiagnostic{diagB, diagA}
	result := SubsumeOverlapping(input)

	if len(result) != 1 {
		t.Fatalf("Expected 1 subsumed diagnostic, got %d", len(result))
	}

	if *result[0].Source != srcFull {
		t.Errorf("Expected larger span source to be preserved, got %s", *result[0].Source)
	}
}

func TestSubsumeOverlapping_NonOverlappingPreserved(t *testing.T) {
	filePath := "src/main.go"
	src1 := `token := "secret1"`
	src2 := `token := "secret2"`

	diag1 := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{Description: "Issue 1", Confidence: High},
		},
		Source: &src1,
		Range: code.Range{
			Start: code.Position{Line: 5, Character: 0},
			End:   code.Position{Line: 5, Character: 20},
		},
		RawRange: CharRange{StartIndex: 50, EndIndex: 70},
	}

	diag2 := &SecurityDiagnostic{
		Location: &filePath,
		Justification: Justification{
			Headline: Evidence{Description: "Issue 2", Confidence: High},
		},
		Source: &src2,
		Range: code.Range{
			Start: code.Position{Line: 50, Character: 0},
			End:   code.Position{Line: 50, Character: 20},
		},
		RawRange: CharRange{StartIndex: 500, EndIndex: 520},
	}

	input := []*SecurityDiagnostic{diag1, diag2}
	result := SubsumeOverlapping(input)

	if len(result) != 2 {
		t.Fatalf("Expected both non-overlapping findings to be preserved, got %d", len(result))
	}
}
