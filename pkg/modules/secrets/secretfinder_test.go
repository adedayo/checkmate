package secrets

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/common/code"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
)

func TestFindSecret(t *testing.T) {
	type args struct {
		source                           io.Reader
		matcher                          MatchProvider
		shouldProvideSourceInDiagnostics bool
	}
	tests := []struct {
		name      string
		value     string
		evidences [3]diagnostics.Evidence
	}{
		{
			name:  "Assignment 1",
			value: `pwd = "232d222x2324c2ecc2c2e"`,
			evidences: [3]diagnostics.Evidence{
				diagnostics.Evidence{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.Medium},
				diagnostics.Evidence{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				diagnostics.Evidence{
					Description: descNotSecret,
					Confidence:  diagnostics.Low},
			},
		},
		{
			name:  "Assignment 2",
			value: `crypt = "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V"`,
			evidences: [3]diagnostics.Evidence{
				diagnostics.Evidence{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				diagnostics.Evidence{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				diagnostics.Evidence{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:  "Assignment 3",
			value: `PassPhrase4 = "This should trigger a high"`,
			evidences: [3]diagnostics.Evidence{
				diagnostics.Evidence{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				diagnostics.Evidence{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				diagnostics.Evidence{
					Description: descHardCodedSecret,
					Confidence:  diagnostics.High},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for got := range FindSecret(strings.NewReader(tt.value), NewJavaFinder(), false) {
				want := makeDiagnostic(tt.value, tt.evidences)
				if got.ProviderID == assignmentProviderID && !reflect.DeepEqual(got, want) {
					t.Errorf("FindSecret() = %#v, want %#v", got, want)
				}
			}
		})
	}
}

func makeDiagnostic(source string, evidences [3]diagnostics.Evidence) diagnostics.SecurityDiagnostic {
	return diagnostics.SecurityDiagnostic{
		Justification: diagnostics.Justification{
			Headline: evidences[0],
			Reasons:  evidences[1:],
		},
		Range: code.Range{
			Start: code.Position{Line: 0, Character: 0},
			End:   code.Position{Line: 0, Character: len(source)}},
		Source:     nil,
		ProviderID: assignmentProviderID}
}
