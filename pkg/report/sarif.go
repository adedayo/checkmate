package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

// SarifLog represents the root of a SARIF 2.1.0 document
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	ShortDescription SarifMessage     `json:"shortDescription"`
	DefaultConfiguration *SarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

type SarifRuleConfig struct {
	Level string `json:"level"`
}

type SarifResult struct {
	RuleID              string               `json:"ruleId"`
	Level               string               `json:"level"`
	Message             SarifMessage         `json:"message"`
	Locations           []SarifLocation      `json:"locations"`
	PartialFingerprints map[string]string    `json:"partialFingerprints,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// GenerateSARIF takes a slice of diagnostics and writes a SARIF 2.1.0 JSON to the writer
func GenerateSARIF(writer io.Writer, diags []*diagnostics.SecurityDiagnostic) error {
	run := SarifRun{
		Tool: SarifTool{
			Driver: SarifDriver{
				Name:           "CheckMate",
				InformationURI: "https://github.com/adedayo/checkmate",
				Rules:          []SarifRule{},
			},
		},
		Results: []SarifResult{},
	}

	seenRules := make(map[string]bool)

	for _, diag := range diags {
		if diag == nil {
			continue
		}

		ruleID := diag.Justification.Headline.Description
		if ruleID == "" {
			ruleID = "generic.high_entropy"
		}

		// Map CheckMate severity/confidence to SARIF level
		// Error, warning, note
		level := "warning"
		if diag.Justification.Headline.Confidence >= diagnostics.High {
			level = "error"
		} else if diag.Justification.Headline.Confidence <= diagnostics.Info {
			level = "note"
		}

		if !seenRules[ruleID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, SarifRule{
				ID: ruleID,
				ShortDescription: SarifMessage{
					Text: fmt.Sprintf("CheckMate finding for %s", ruleID),
				},
				DefaultConfiguration: &SarifRuleConfig{Level: level},
			})
			seenRules[ruleID] = true
		}

		locationURI := ""
		if diag.Location != nil {
			locationURI = *diag.Location
		}

		startLine := int(diag.Range.Start.Line + 1)
		startColumn := int(diag.Range.Start.Character + 1)

		// Use the fingerprint for partialFingerprints
		fingerprint := ""
		if diag.SHA256 != nil {
			fingerprint = *diag.SHA256
		}

		result := SarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: SarifMessage{
				Text: fmt.Sprintf("Detected secret of type: %s", ruleID),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: locationURI,
						},
						Region: SarifRegion{
							StartLine:   startLine,
							StartColumn: startColumn,
						},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"checkmate/v1": fingerprint,
			},
		}

		run.Results = append(run.Results, result)
	}

	sarifLog := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SarifRun{run},
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifLog)
}
