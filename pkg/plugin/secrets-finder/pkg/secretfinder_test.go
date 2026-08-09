package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

func TestFindSecret(t *testing.T) {
	// type args struct {
	// 	source                           io.Reader
	// 	matcher                          MatchProvider
	// 	extension                        string
	// 	shouldProvideSourceInDiagnostics bool
	// }
	tests := []struct {
		name            string
		value           string
		extension       string
		provider        string
		evidences       [3]diagnostics.Evidence
		shouldNotDetect bool //test FPs
	}{
		{
			name:            "PHP arrow",
			value:           `'secret' => env('MANDRILL_SECRET'),\n`,
			extension:       ".php",
			shouldNotDetect: true,
		},
		{
			name:            "Empty arrow",
			value:           `'dkim-signature'         => `,
			extension:       ".php",
			shouldNotDetect: true,
		},
		{
			name:      "Assignment 1",
			value:     `pwd = "232d222x2324c2ecc2c2e"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.Medium},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descSuspiciousSecret,
					Confidence:  diagnostics.Info},
			},
		},
		{
			name:      "Assignment 2",
			value:     `crypt = "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:      "Assignment 2.1",
			value:     `secret  = "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:      "Assignment 2.2",
			value:     `crypt space = "gho_pTruZn7ntsbrTERIYU4sGx3Qq4689V2Jzoq1"`,
			extension: ".java",
			provider:  descGithubToken,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descGithubToken,
					Confidence:  diagnostics.Critical},
				{
					Description: descSecretUnbrokenString,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:            "Assignment 2.3",
			value:           `crypt_with_space = "HbjZ!+{c]Y5! kNzB+-p^A6bCt(zNtf=V"`,
			extension:       ".java",
			shouldNotDetect: true,
		},
		{
			name:      "Assignment 3",
			value:     `PassPhrase4 = "This should trigger a high"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHardCodedSecret,
					Confidence:  diagnostics.High},
			},
		},
		{
			name:      "JSON Assignment 1",
			value:     `"Pwd": "This_is_A_{§pwd1"`,
			extension: ".json",
			provider:  jsonAssignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:      "Github",
			value:     `"gho_pTruZn7ntsbrTERIYU4sGx3Qq4689V2Jzoq1"`,
			extension: ".xml",
			provider:  descGithubToken,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descGithubToken,
					Confidence:  diagnostics.Critical},
				{
					Description: descSecretUnbrokenString,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name: "Assigned variable name with newline",
			value: `
IAuthUserRequest,
  res: Response,
  next
) => {
  req.user = { nickname: "test"
`,
			extension:       ".ts",
			shouldNotDetect: true,
			provider:        yamlAssignmentProviderID,
		},

		{
			name:            "key with unusual value assignement",
			value:           `key: TaggingAction.FALSE_POSITIVE_DOMAIN.key };`,
			extension:       ".ts",
			shouldNotDetect: true,
		},

		{
			name:            "Numbers should not be picked up",
			value:           `key: "97654247905442"`,
			extension:       ".js",
			shouldNotDetect: true,
		},
	}

	wl := diagnostics.MakeEmptyExcludes()
	options := SecretSearchOptions{
		Exclusions: wl,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := fmt.Sprintf("Filename%s", tt.extension) // dummy path
			gotResult := false
			for got := range FindSecret(util.RepositoryIndexedFile{RepositoryIndex: 0, File: path}, strings.NewReader(tt.value), GetFinderForFileType(tt.extension, options), true) {
				if tt.shouldNotDetect {
					t.Errorf("Result Not expected, but Got %#v", got)
				}
				gotResult = true
				want := makeDiagnostic(tt.value, tt.evidences, tt.provider)
				if (got.Justification.Headline.Description != want.Justification.Headline.Description ||
					got.Justification.Headline.Confidence != want.Justification.Headline.Confidence) &&
					!checkEqual(want.Justification.Reasons, got.Justification.Reasons) {
					g, _ := json.MarshalIndent(got, "", " ")
					w, _ := json.MarshalIndent(want, "", " ")

					t.Errorf("FindSecret() = %s, \n\n ========want===========\n %s", string(g), string(w))
				}
			}

			if !gotResult && !tt.shouldNotDetect {
				t.Errorf("Expected Result from %#v", tt)
			}

		})
	}
}

func checkEqual(a, b []diagnostics.Evidence) bool {
	for i, x := range a {
		if x.Description != b[i].Description || x.Confidence != b[i].Confidence {
			return false
		}
	}
	return true
}

func makeDiagnostic(source string, evidences [3]diagnostics.Evidence, providerID string) diagnostics.SecurityDiagnostic {
	return diagnostics.SecurityDiagnostic{
		Justification: diagnostics.Justification{
			Headline: evidences[0],
			Reasons:  evidences[1:],
		},
		Range: code.Range{
			Start: code.Position{Line: 0, Character: 0},
			End:   code.Position{Line: 0, Character: int64(len(source) - 1)}},
		Source:     nil,
		ProviderID: &providerID}
}
