package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIFOutputValidation(t *testing.T) {
	// 1. Generate SARIF output
	findings := []*diagnostics.SecurityDiagnostic{
		{
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: "aws.access_key",
					Confidence:  diagnostics.High,
				},
			},
			Range: code.Range{
				Start: code.Position{Line: 10, Character: 5},
				End:   code.Position{Line: 10, Character: 25},
			},
		},
	}
	
	loc := "src/main.go"
	findings[0].Location = &loc
	
	var buf bytes.Buffer
	err := GenerateSARIF(&buf, findings)
	require.NoError(t, err)

	// 2. Validate against schema
	schemaPath := filepath.Join("testdata", "sarif-schema-2.1.0.json")
	compiler := jsonschema.NewCompiler()
	sch, err := compiler.Compile(schemaPath)
	require.NoError(t, err)
	
	var v interface{}
	err = json.Unmarshal(buf.Bytes(), &v)
	require.NoError(t, err)
	
	err = sch.Validate(v)
	if err != nil {
		t.Fatalf("SARIF output failed schema validation: %v", err)
	}
	assert.NoError(t, err)
}

func TestSARIFSanitisedAndSuppressedValidation(t *testing.T) {
	findings := []*store.StoredFinding{
		{
			FindingID:      "f_tp",
			RuleID:         "AWS Access Key",
			Severity:       sdk.SeverityHigh,
			File:           "cmd/deploy/main.go",
			Line:           12,
			Column:         8,
			EndLine:        12,
			EndColumn:      28,
			SecretChecksum: "sha_real",
			Suppressed:     false,
			TriageStatus:   sdk.TriageStatusTruePositive,
			TriageSource:   "agent:copilot",
			AIAnnotation: &sdk.AIAnnotation{
				Summary:         "Live AWS access key",
				RemediationHint: "Revoke key and move to env var",
				ReasonCategory:  "real_credential",
			},
		},
		{
			FindingID:      "f_fp",
			RuleID:         "Generic High Entropy",
			Severity:       sdk.SeverityHigh,
			File:           "testdata/fixtures/tokens.json",
			Line:           4,
			Column:         15,
			SecretChecksum: "sha_dummy",
			Suppressed:     true,
			ExceptionID:    "exc_123",
			TriageStatus:   sdk.TriageStatusFalsePositive,
			TriageSource:   "agent:copilot",
			AIAnnotation: &sdk.AIAnnotation{
				Summary:        "Dummy fixture string used only in tests",
				ReasonCategory: "test_fixture",
			},
		},
	}

	schemaPath := filepath.Join("testdata", "sarif-schema-2.1.0.json")
	compiler := jsonschema.NewCompiler()
	sch, err := compiler.Compile(schemaPath)
	require.NoError(t, err)

	// 1. Sanitised mode omits suppressed findings
	var sanitisedBuf bytes.Buffer
	require.NoError(t, GenerateSARIFWithOptions(&sanitisedBuf, findings, SARIFOptions{IncludeSuppressed: false}))

	var sanitisedDoc SarifLog
	require.NoError(t, json.Unmarshal(sanitisedBuf.Bytes(), &sanitisedDoc))
	require.Len(t, sanitisedDoc.Runs[0].Results, 1)
	assert.Equal(t, "cmd/deploy/main.go", sanitisedDoc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 12, sanitisedDoc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.EndLine)
	assert.Equal(t, 28, sanitisedDoc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.EndColumn)
	assert.NotNil(t, sanitisedDoc.Runs[0].Results[0].Properties["checkmateTriage"])

	var v1 interface{}
	require.NoError(t, json.Unmarshal(sanitisedBuf.Bytes(), &v1))
	require.NoError(t, sch.Validate(v1))

	// 2. Full audit mode includes suppressed findings with SARIF suppressions[]
	var fullBuf bytes.Buffer
	require.NoError(t, GenerateSARIFWithOptions(&fullBuf, findings, SARIFOptions{IncludeSuppressed: true}))

	var fullDoc SarifLog
	require.NoError(t, json.Unmarshal(fullBuf.Bytes(), &fullDoc))
	require.Len(t, fullDoc.Runs[0].Results, 2)
	require.Len(t, fullDoc.Runs[0].Results[1].Suppressions, 1)
	assert.Equal(t, "external", fullDoc.Runs[0].Results[1].Suppressions[0].Kind)
	assert.Equal(t, "accepted", fullDoc.Runs[0].Results[1].Suppressions[0].Status)
	assert.Contains(t, fullDoc.Runs[0].Results[1].Suppressions[0].Justification, "test_fixture")

	var v2 interface{}
	require.NoError(t, json.Unmarshal(fullBuf.Bytes(), &v2))
	require.NoError(t, sch.Validate(v2))
}
