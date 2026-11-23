package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
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
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"`
	Message             SarifMessage           `json:"message"`
	Locations           []SarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Suppressions        []SarifSuppression     `json:"suppressions,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

// SarifSuppression represents a SARIF 2.1.0 result suppression entry.
type SarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// SARIFOptions configures sanitised/triaged SARIF export.
type SARIFOptions struct {
	// IncludeSuppressed emits suppressed/false-positive findings with SARIF
	// suppressions[] entries instead of omitting them.
	IncludeSuppressed bool
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

// GenerateSARIFWithOptions writes a SARIF 2.1.0 document from stored findings,
// supporting sanitised filtering (omitting suppressed/false-positive findings)
// or full-audit export with standard SARIF suppressions[] and triage metadata.
func GenerateSARIFWithOptions(writer io.Writer, findings []*store.StoredFinding, opts SARIFOptions) error {
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

	for _, f := range findings {
		if f == nil {
			continue
		}
		isSuppressed := f.Suppressed || f.TriageStatus == sdk.TriageStatusFalsePositive
		if isSuppressed && !opts.IncludeSuppressed {
			continue
		}

		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = string(sdk.SecretTypeHighEntropy)
		}

		level := sarifLevelFromSeverity(string(f.Severity))
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

		startLine := f.Line
		if startLine < 1 {
			startLine = 1
		}
		startColumn := f.Column
		if startColumn < 1 {
			startColumn = 1
		}

		msgText := fmt.Sprintf("Detected secret of type: %s", ruleID)
		if f.AIAnnotation != nil && f.AIAnnotation.Summary != "" {
			msgText = fmt.Sprintf("%s: %s", msgText, f.AIAnnotation.Summary)
		}

		region := SarifRegion{
			StartLine:   startLine,
			StartColumn: startColumn,
		}
		if f.EndLine >= startLine && f.EndLine > 0 {
			region.EndLine = f.EndLine
			if f.EndColumn >= 1 && (f.EndLine > startLine || f.EndColumn >= startColumn) {
				region.EndColumn = f.EndColumn
			}
		}

		result := SarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: SarifMessage{
				Text: msgText,
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: f.File,
						},
						Region: region,
					},
				},
			},
			PartialFingerprints: map[string]string{
				"checkmate/v1": f.SecretChecksum,
			},
		}

		if isSuppressed {
			justification := "Suppressed as false positive"
			if f.AIAnnotation != nil && f.AIAnnotation.Summary != "" {
				if f.AIAnnotation.ReasonCategory != "" {
					justification = fmt.Sprintf("[%s] %s", f.AIAnnotation.ReasonCategory, f.AIAnnotation.Summary)
				} else {
					justification = f.AIAnnotation.Summary
				}
			} else if f.ExceptionID != "" {
				justification = fmt.Sprintf("Suppressed by exception %s", f.ExceptionID)
			}
			result.Suppressions = []SarifSuppression{
				{
					Kind:          "external",
					Status:        "accepted",
					Justification: justification,
				},
			}
		}

		if f.TriageStatus != "" && f.TriageStatus != sdk.TriageStatusUntriaged {
			triageProps := map[string]interface{}{
				"triageStatus": string(f.TriageStatus),
			}
			if f.TriageSource != "" {
				triageProps["triageSource"] = f.TriageSource
			}
			if f.ExceptionID != "" {
				triageProps["exceptionId"] = f.ExceptionID
			}
			if f.AIAnnotation != nil {
				if f.AIAnnotation.Summary != "" {
					triageProps["summary"] = f.AIAnnotation.Summary
				}
				if f.AIAnnotation.RemediationHint != "" {
					triageProps["remediationHint"] = f.AIAnnotation.RemediationHint
				}
				if f.AIAnnotation.ReasonCategory != "" {
					triageProps["reasonCategory"] = f.AIAnnotation.ReasonCategory
				}
			}
			result.Properties = map[string]interface{}{
				"checkmateTriage": triageProps,
			}
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

func sarifLevelFromSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH", "CONFIRMED":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "warning"
	}
}
