package secrets

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	gitutils "github.com/adedayo/checkmate/pkg/core/git"
	util "github.com/adedayo/checkmate/pkg/core/util"
)

var (
	confidentialFilesProviderID     = "ConfidentialFiles"
	pathBasedSecretFinderProviderID = "PathBasedSecretsFinder"
	gitURL                          = regexp.MustCompile(`\s*(?i:https?://|git@).*`)
	TenMB                           = int64(1024 * 1000 * 10) // 10Mb
)

// determineAndCloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
// and the second argument are non-git local paths
func determineAndCloneRepositories(paths []string) (map[string]repoCloneAndDetail, []string) {
	fmt.Println("TESTING COMPILATION determineAndCloneRepositories")
	repoMap := make(map[string]repoCloneAndDetail)
	local := []string{}
	for _, p := range paths {
		if !gitURL.MatchString(p) {
			local = append(local, p)
		} else {
			if _, present := repoMap[p]; !present {
				if repo, err := gitutils.Clone(context.Background(), p, &gitutils.GitCloneOptions{}); err == nil {
					repoMap[p] = repoCloneAndDetail{
						CloneDetail: repo,
					}
				} else {
					log.Printf("Failed to clone repository %s: %s\n", p, err.Error())
				}
			}
		}
	}
	return repoMap, local
}

type confidentialFilesFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	options SecretSearchOptions
}

func (cff confidentialFilesFinder) ConsumePath(rif util.RepositoryIndexedFile) {
	path := rif.File
	isTestFile := testFile.MatchString(path)
	if confidential, why := common.IsConfidentialFile(path); confidential {

		if cff.options.Verbose {
			log.Printf("Processing file: %s\n", path)
		}

		if cff.options.ExcludeTestFiles {
			if isTestFile {
				if cff.options.Verbose {
					log.Printf("Skipping suspected test file %s\n", path)
				}
				if cff.options.ReportIgnored {
					why := fmt.Sprintf("Skipped: Suspected test file %s", path)
					issue := diagnostics.SecurityDiagnostic{
						Location:   &path,
						ProviderID: &confidentialFilesProviderID,
						Justification: diagnostics.Justification{
							Headline: diagnostics.Evidence{
								Description: why,
								Confidence:  diagnostics.High,
							},
						},
						Excluded:        true,
						SHA256:          computeFileHash(cff.options.CalculateChecksum, path),
						RepositoryIndex: rif.RepositoryIndex,
					}
					issue.AddTag("test")
					cff.Broadcast(&issue)
				}
				return
			}
		}

		if cff.ShouldExcludePath(path) {
			if cff.options.Verbose {
				log.Printf("Skipping excluded path %s\n", path)
			}

			if cff.options.ReportIgnored {
				why := fmt.Sprintf("Skipped: An exclusion matches path %s", path)
				issue := diagnostics.SecurityDiagnostic{
					Location:   &path,
					ProviderID: &confidentialFilesProviderID,
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: why,
							Confidence:  diagnostics.High,
						},
					},
					Excluded:        true,
					SHA256:          computeFileHash(cff.options.CalculateChecksum, path),
					RepositoryIndex: rif.RepositoryIndex,
				}
				if isTestFile {
					issue.AddTag("test")
				}
				cff.Broadcast(&issue)
			}
			return
		}

		evidence := checkConfidential(confidentialFile{
			path: path,
			why:  fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why),
		})
		// why = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why)
		hash := computeFileHash(cff.options.CalculateChecksum, path)
		issue := diagnostics.SecurityDiagnostic{
			Location:   &path,
			ProviderID: &confidentialFilesProviderID,
			SHA256:     hash,
			Justification: diagnostics.Justification{
				Headline: evidence,
				Reasons: []diagnostics.Evidence{
					evidence,
				},
			},
			RepositoryIndex: rif.RepositoryIndex,
		}
		if isTestFile {
			issue.AddTag("test")
		}
		if confidential {
			issue.AddTag("confidential")
		}

		if hash != nil && !cff.ShouldExcludeHash(*hash) {
			cff.Broadcast(&issue)
		}
	}
}

type pathBasedSourceSecretFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	showSource bool
	options    SecretSearchOptions
}

func (pathBSF pathBasedSourceSecretFinder) ConsumePath(rif util.RepositoryIndexedFile) {

	path := rif.File
	isTestFile := testFile.MatchString(path)

	if pathBSF.options.Verbose {
		log.Printf("Processing file: %s\n", path)
	}

	if pathBSF.options.ExcludeTestFiles {
		if isTestFile {
			if pathBSF.options.Verbose {
				log.Printf("Skipping suspected test File %s\n", path)
			}
			if pathBSF.options.ReportIgnored {
				why := fmt.Sprintf("Skipped: Suspected test file %s", path)
				issue := diagnostics.SecurityDiagnostic{
					Location:   &path,
					ProviderID: &confidentialFilesProviderID,
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: why,
							Confidence:  diagnostics.High,
						},
					},
					Excluded:        true,
					SHA256:          computeFileHash(pathBSF.options.CalculateChecksum, path),
					RepositoryIndex: rif.RepositoryIndex,
				}
				issue.AddTag("test")
				pathBSF.Broadcast(&issue)
			}
			return
		}
	}

	if pathBSF.ShouldExcludePath(path) {

		if pathBSF.options.Verbose {
			log.Printf("Skipping excluded path %s\n", path)
		}

		if pathBSF.options.ReportIgnored {
			why := fmt.Sprintf("Skipped: An exclusion matches path %s", path)
			issue := diagnostics.SecurityDiagnostic{
				Location:   &path,
				ProviderID: &pathBasedSecretFinderProviderID,
				Justification: diagnostics.Justification{
					Headline: diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.High,
					},
				},
				Excluded:        true,
				RepositoryIndex: rif.RepositoryIndex,
			}
			if isTestFile {
				issue.AddTag("test")
			}
			pathBSF.Broadcast(&issue)
		}
		return
	}
	ext := filepath.Ext(path)
	cutOffSize := TenMB

	if _, present := common.TextFileExtensions[ext]; present || ext == "" { //now scan files without extensions
		if f, err := os.Open(path); err == nil {
			defer func() {
				_ = f.Close()
			}()
			//don't scan files larger than cutOffSize, unless they are in recognisedFiles
			//don't scan files without extension, unless they are smaller than cutOffSize and contain plaintext content
			if _, present := recognisedFiles[ext]; !present {
				//Skip searching file not in standard recognised parsable files and greater than 10Mb in size
				if stat, err := f.Stat(); err == nil && stat.Size() > cutOffSize {
					if pathBSF.options.ReportIgnored {
						why := fmt.Sprintf("Skipped: File %s exceeds %d bytes in size", path, cutOffSize)
						issue := diagnostics.SecurityDiagnostic{
							Location:   &path,
							ProviderID: &confidentialFilesProviderID,
							Justification: diagnostics.Justification{
								Headline: diagnostics.Evidence{
									Description: why,
									Confidence:  diagnostics.High,
								},
							},
							Excluded:        true,
							SHA256:          computeFileHash(pathBSF.options.CalculateChecksum, path),
							RepositoryIndex: rif.RepositoryIndex,
						}
						if isTestFile {
							issue.AddTag("test")
						}
						pathBSF.Broadcast(&issue)
					}
					return
				}

				if ext == "" {
					buff := make([]byte, 512)
					_, err := f.Read(buff)
					if err == nil && !strings.Contains(http.DetectContentType(buff), "text/plain") {
						//we found a non-textual file with no extension, skip scanning
						return
					}
				}
			}
			for issue := range FindSecret(rif, f, GetFinderForFileType(ext, rif, pathBSF.options), pathBSF.options.ShowSource) {
				issue.Location = &path
				if isTestFile {
					issue.AddTag("test")
				}

				val := issue.GetValue()
				if !pathBSF.ShouldExclude(path, val) && (issue.SHA256 == nil || !pathBSF.ShouldExcludeHashOnPath(path, *issue.SHA256)) {
					pathBSF.Broadcast(issue)
				}
			}

		}
	} else {
		if pathBSF.options.ReportIgnored {
			why := fmt.Sprintf("Skipped: File extension %s is ignored", ext)
			issue := diagnostics.SecurityDiagnostic{
				Location:   &path,
				ProviderID: &pathBasedSecretFinderProviderID,
				Justification: diagnostics.Justification{
					Headline: diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.High,
					},
				},
				RepositoryIndex: rif.RepositoryIndex,
			}
			if isTestFile {
				issue.AddTag("test")
			}
			pathBSF.Broadcast(&issue)
		}
	}
}
