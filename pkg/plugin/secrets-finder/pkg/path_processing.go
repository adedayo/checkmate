package secrets

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	util "github.com/adedayo/checkmate/pkg/core/util"
)

var (
	confidentialFilesProviderID     = "ConfidentialFiles"
	pathBasedSecretFinderProviderID = "PathBasedSecretsFinder"
	gitURL                          = regexp.MustCompile(`\s*(?i:https?://|git@).*`)
	TenMB                           = int64(1024 * 1000 * 10) // 10Mb
)

// determineAndCloneRepositories was replaced by acquirePaths in roots.go: it
// cloned serially, and it keyed the result by URL in a map whose iteration
// order then decided each repository's index — independently of the second map
// iteration that built the walk roots, so the two could disagree.

type confidentialFilesFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	options SecretSearchOptions
}

func (cff confidentialFilesFinder) ConsumePath(rif util.RepositoryIndexedFile) {
	cff.consumePathGated(rif, newPathGate(rif, cff.ExclusionProvider))
}

func (cff confidentialFilesFinder) consumePathGated(rif util.RepositoryIndexedFile, gate *pathGate) {
	path := rif.File
	isTestFile := gate.IsTestFile
	if confidential, why := gate.Confidential, gate.ConfidentialWhy; confidential {

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

		if gate.ExcludedPath {
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
	// scanContext holds the finder set reused across every file this consumer
	// handles. It replaces the previous per-file GetFinderForFileType call.
	// The path multiplexer drives each consumer sequentially, so a single
	// context per consumer is safe; a parallel walker must give each worker
	// its own consumer (and hence its own context).
	scanContext *ScanContext
}

// newPathBasedSourceSecretFinder builds the consumer together with its
// reusable ScanContext.
func newPathBasedSourceSecretFinder(options SecretSearchOptions) *pathBasedSourceSecretFinder {
	return &pathBasedSourceSecretFinder{
		showSource:        options.ShowSource,
		ExclusionProvider: options.Exclusions,
		options:           options,
		scanContext:       NewScanContext(options),
	}
}

func (pathBSF pathBasedSourceSecretFinder) ConsumePath(rif util.RepositoryIndexedFile) {
	pathBSF.consumePathGated(rif, newPathGate(rif, pathBSF.ExclusionProvider))
}

func (pathBSF pathBasedSourceSecretFinder) consumePathGated(rif util.RepositoryIndexedFile, gate *pathGate) {

	path := rif.File
	isTestFile := gate.IsTestFile

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

	if gate.ExcludedPath {

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
	ext := gate.Ext
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

					//The sniff consumed the first 512 bytes of the handle, and
					//the handle is what the scanner reads next. Left as it was,
					//every extensionless text file was scanned from byte 512
					//onwards: its first 512 bytes were never searched for
					//secrets, and every finding after them was reported at an
					//offset 512 too low, which puts the wrong line number on
					//the finding and — since position feeds the finding ID —
					//gives it the wrong identity too.
					//
					//Rewinding costs one lseek against an already-open handle
					//and restores the whole file to the scanner, which also
					//keeps it on the *os.File whole-file read path. Reusing the
					//sniffed bytes via io.MultiReader would save re-reading 512
					//bytes that are certainly still in the page cache, at the
					//cost of hiding the file size from readAll and pushing
					//every extensionless file onto the chunked path — a bad
					//trade.
					if _, err := f.Seek(0, io.SeekStart); err != nil {
						return
					}
				}
			}
			var source io.Reader = f
			for _, issue := range pathBSF.scanContext.FindSecretsInFile(rif, source, ext, pathBSF.options.ShowSource) {
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
