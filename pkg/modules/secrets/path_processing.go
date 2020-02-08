package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	// "github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/common/git"
	"github.com/adedayo/checkmate/pkg/common/util"
	// "github.com/adedayo/checkmate/pkg/common/util"
)

var (
	confidentialFilesProviderID = "ConfidentialFiles"
	gitURL                      = regexp.MustCompile(`\s*(?i:https?://|git@).*`)
)

//SearchSecretsOnPaths searches for secrets on indicated paths
func SearchSecretsOnPaths(paths []string, showSource bool, wl diagnostics.DefaultWhitelistProvider) (chan diagnostics.SecurityDiagnostic, chan []string) {
	out := make(chan diagnostics.SecurityDiagnostic)
	pathsOut := make(chan []string)
	repos, local := determineAndCloneRepositories(paths)
	paths = local
	for _, path := range repos {
		paths = append(paths, path)
	}
	//reverse local paths to git URL
	repoMapper := make(map[string]string)
	for repo, loc := range repos {
		repoMapper[loc] = repo
	}
	collector := func(diagnostic diagnostics.SecurityDiagnostic) {
		location := *diagnostic.Location
		for loc, repo := range repoMapper {
			location = strings.Replace(location, loc, repo, 1)
		}
		diagnostic.Location = &location
		if repo, present := repoMapper[*diagnostic.Location]; present {
			diagnostic.Location = &repo
		}
		out <- diagnostic
	}
	consumers := []util.PathConsumer{
		&confidentialFilesFinder{
			DefaultWhitelistProvider: wl,
		},
		&pathBasedSecretFinder{showSource: showSource, DefaultWhitelistProvider: wl},
	}
	providers := []diagnostics.SecurityDiagnosticsProvider{}
	for _, c := range consumers {
		providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
	}
	common.RegisterDiagnosticsConsumer(collector, providers...)

	mux := util.NewPathMultiplexer(consumers...)

	go func() {
		allFiles := []string{}
		defer func() {
			for _, r := range repos {
				os.RemoveAll(r)
			}
			close(out)
			pathsOut <- allFiles
			close(pathsOut)
		}()
		allFiles = util.FindFiles(paths)
		for _, path := range allFiles {
			mux.ConsumePath(path)
		}
	}()

	return out, pathsOut
}

//determineAndCloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
//and the second argument are non-git local paths
func determineAndCloneRepositories(paths []string) (map[string]string, []string) {
	repoMap := make(map[string]string)
	local := []string{}
	for _, p := range paths {
		if !gitURL.MatchString(p) {
			local = append(local, p)
		} else {
			if _, present := repoMap[p]; !present {
				if repo, err := gitutils.Clone(p); err == nil {
					repoMap[p] = repo
				}
			}
		}
	}
	return repoMap, local
}

type confidentialFilesFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.DefaultWhitelistProvider
}

func (cff confidentialFilesFinder) Consume(path string) {
	if cff.ShouldWhitelistPath(path) {
		return
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
		cff.Broadcast(issue)
	}
}

type pathBasedSecretFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.DefaultWhitelistProvider
	showSource bool
}

func (pathBSF pathBasedSecretFinder) Consume(path string) {
	if pathBSF.ShouldWhitelistPath(path) {
		return
	}
	ext := filepath.Ext(path)
	if _, present := common.TextFileExtensions[ext]; present {
		if f, err := os.Open(path); err == nil {
			for issue := range FindSecret(f, GetFinderForFileType(ext), pathBSF.showSource) {
				issue.Location = &path
				pathBSF.Broadcast(issue)
			}
			f.Close()
		}
	}
}
