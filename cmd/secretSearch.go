package cmd

/*
Copyright © 2019 Adedayo Adetoye (aka Dayo)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	showSource, asJSON, runningCommentary bool
	exclusion                             string
	sensitiveFiles, sensitiveFilesOnly    bool
	calculateChecksum                     bool
)

// secretSearchCmd represents the secretSearch command
var secretSearchCmd = &cobra.Command{
	Use:   "secretSearch",
	Short: "Search for secrets in a textual data source",
	Long:  `Search for secrets in a textual data source`,
	Run:   search,
}

func init() {
	rootCmd.AddCommand(secretSearchCmd)
	secretSearchCmd.Flags().BoolVarP(&showSource, "source", "s", true, "Provide source code evidence in the diagnostic results")
	secretSearchCmd.Flags().BoolVar(&calculateChecksum, "calculate-checksums", true, "Calculate checksums of secrets")
	secretSearchCmd.Flags().StringVarP(&exclusion, "exclusion", "e", "", "Use provided exclusion yaml configuration")
	secretSearchCmd.Flags().BoolVar(&asJSON, "json", false, "Generate JSON output")
	secretSearchCmd.Flags().BoolVar(&sensitiveFiles, "sensitive-files", false, "List all registered sensitive files and their description")
	secretSearchCmd.Flags().BoolVar(&sensitiveFilesOnly, "sensitive-files-only", false, "Only search for sensitive files (e.g. certificates, key stores etc.)")
	secretSearchCmd.Flags().BoolVar(&runningCommentary, "running-commentary", false, "Generate a running commentary of results. Useful for analysis of large input data")
}

func search(cmd *cobra.Command, args []string) {
	if !(asJSON || sensitiveFiles) {
		fmt.Printf("Starting %s %s (https://github.com/adedayo/checkmate)\n", common.AppName, appVersion)
	}

	if sensitiveFiles {
		println("Sensitive files")
		if x, err := json.MarshalIndent(common.GetSensitiveFilesDescriptors(), "", " "); err == nil {
			fmt.Printf("%s\n", x)
		} else {
			log.Printf("Marshall Error: %s", err.Error())
			fmt.Print("[]")
		}
		return
	}

	var wld diagnostics.ExcludeDefinition
	if exclusion != "" {
		data, err := ioutil.ReadFile(exclusion)
		if err != nil {
			log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
		} else {
			if err := yaml.Unmarshal(data, &wld); err != nil {
				log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
			} else {
				//Successfully loaded exclusion. Add exclusion file to the exclusion
				if wlPath, err := filepath.Abs(exclusion); err == nil {
					wld.PathExclusionRegExs = append(wld.PathExclusionRegExs, wlPath)
				}
			}
		}
	}
	var wl diagnostics.ExclusionProvider
	if w, err := diagnostics.CompileExcludes(&wld); err != nil {
		log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
	} else {
		wl = w
	}
	issues := []diagnostics.SecurityDiagnostic{}
	options := secrets.SecretSearchOptions{
		ShowSource:            showSource,
		CalculateChecksum:     calculateChecksum,
		ConfidentialFilesOnly: sensitiveFilesOnly,
		Exclusions:            wl,
	}
	issueChannel, paths := secrets.SearchSecretsOnPaths(args, options)

	for issue := range issueChannel {
		issues = append(issues, issue)
		if runningCommentary {
			if x, err := json.MarshalIndent(issue, "", " "); err == nil {
				fmt.Printf("\n%s\n", x)
			}
		}
	}
	files := <-paths
	// fmt.Printf("\n,Files: %#v\n", files)

	if asJSON {
		if x, err := json.MarshalIndent(issues, "", " "); err == nil {
			fmt.Printf("%s\n", x)
		} else {
			log.Printf("Marshall Error: %s", err.Error())
			fmt.Print("[]")
		}
	} else {
		path, err := asciidoc.GenerateReport(options, files, issues...)
		if err != nil {
			fmt.Printf("\nError: %s%s\n", err.Error(), path)
			return
		}
		println("Report generated at ", path)
	}
}
