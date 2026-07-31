package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/santhosh-tekuri/jsonschema/v5"
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
