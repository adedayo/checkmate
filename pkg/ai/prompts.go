package ai

import (
	"fmt"

	"github.com/adedayo/checkmate/pkg/sdk"
)

const systemPrompt = `You are an expert Application Security Analyst.
Your task is to analyze a suspected leaked secret in a codebase and determine if it is a false positive (e.g., a dummy token, test data, or generic high entropy string) or a true positive (an actual, sensitive credential).

You must respond ONLY with a valid JSON object matching the following structure:
{
  "fpLikelihood": 0.0, // float between 0.0 (definitely real) and 1.0 (definitely false positive)
  "summary": "1-2 sentence plain-English assessment of what this finding is.",
  "remediationHint": "Brief suggestion on what to do next (nullable)",
  "contextClues": ["list of strings", "explaining your reasoning"]
}
`

func buildUserPrompt(finding *sdk.Finding, promptMode sdk.PromptMode) string {
	context := finding.SourceContext
	if context == "" {
		context = "<no source context available>"
	}

	secretType := string(finding.SecretType)
	
	// If mode is REDACTED, we must assure the LLM that the secret is redacted.
	// We rely on the source_context having ████.
	modeWarning := ""
	if promptMode == sdk.PromptMode("REDACTED") || promptMode == sdk.PromptMode("") {
		modeWarning = "The actual secret value has been REDACTED and replaced with ████ for security reasons. Rely on the surrounding code context (variable names, functions, usage)."
	} else {
		// In RAW_VALUE mode, theoretically we would provide the raw secret, but currently
		// it is not stored in the database. 
		modeWarning = "The actual secret value has been REDACTED and replaced with ████ (raw value storage is disabled in the database)."
	}

	return fmt.Sprintf(`Analyze the following secret finding:

Secret Type: %s
Rule ID: %s
File Path: %s
Line: %d

%s

Code Context:
%s
`, secretType, finding.RuleID, finding.File, finding.Line, modeWarning, context)
}
