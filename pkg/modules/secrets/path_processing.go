package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/common/util"
)

var (
	confidentialFilesProviderID = "Confidential_Files"
)

//SearchSecretsOnPaths searches for secrets on indicated paths
func SearchSecretsOnPaths(paths []string, showSource bool) chan diagnostics.SecurityDiagnostic {
	out := make(chan diagnostics.SecurityDiagnostic)
	collector := func(diagnostic diagnostics.SecurityDiagnostic) {
		out <- diagnostic
	}
	consumers := []util.PathConsumer{&confidentialFilesFinder{}, &pathBasedSecretFinder{showSource: showSource}}
	providers := []diagnostics.SecurityDiagnosticsProvider{}
	for _, c := range consumers {
		providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
	}
	common.RegisterDiagnosticsConsumer(collector, providers...)

	mux := util.NewPathMultiplexer(consumers...)
	go func() {
		defer close(out)
		for _, path := range util.FindFiles(paths) {
			mux.ConsumePath(path)
		}
	}()

	return out
}

type confidentialFilesFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
}

func (cff confidentialFilesFinder) Consume(path string) {
	if confidential, why := common.IsConfidentialFile(path); confidential {
		why = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why)
		issue := diagnostics.SecurityDiagnostic{
			Location:   &path,
			ProviderID: confidentialFilesProviderID,
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: why,
					Confidence:  diagnostics.Medium,
				},
				Reasons: []diagnostics.Evidence{
					diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.Medium,
					},
				},
			},
		}
		cff.Broadcast(issue)
	}
}

type pathBasedSecretFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	showSource bool
}

func (pathBSF pathBasedSecretFinder) Consume(path string) {
	ext := filepath.Ext(path)
	if _, present := common.TextFileExtensions[ext]; present {
		if f, err := os.Open(path); err == nil {
			for issue := range FindSecret(f, GetFinderForFileType(ext), pathBSF.showSource) {
				issue.Location = &path
				pathBSF.Broadcast(issue)
				if x, err := json.Marshal(issue); err == nil {
					fmt.Printf("\n%s\n", x)
				}
			}
			f.Close()
		}
	}
	if confidential, why := common.IsConfidentialFile(path); confidential {
		why = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why)
		issue := diagnostics.SecurityDiagnostic{
			Location:   &path,
			ProviderID: confidentialFilesProviderID,
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: why,
					Confidence:  diagnostics.Medium,
				},
				Reasons: []diagnostics.Evidence{
					diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.Medium,
					},
				},
			},
		}
		pathBSF.Broadcast(issue)
	}
}
